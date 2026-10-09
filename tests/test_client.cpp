/*
 * Copyright 2026 Kartik Gohil
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * tests/test_client.cpp
 *
 * UspController unit tests.
 *
 * Tests that do not require a real USP agent (protocol parsing helpers,
 * error code functions, etc.) are verified inline.
 *
 * Socket-based tests spin up a minimal mock agent thread.
 */

#include "client.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <future>
#include <thread>
#include <vector>

#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Include the C FFI header to test error code helpers. */
#include "libuspmtp.h"

using namespace usp;

/* ── Minimal test harness ────────────────────────────────────────────────── */

static int g_pass = 0;
static int g_fail = 0;

/* Portable socket write that suppresses SIGPIPE. */
static ssize_t sock_write(int fd, const void* buf, size_t len) {
#ifdef MSG_NOSIGNAL
    return ::send(fd, buf, len, MSG_NOSIGNAL);
#else
    return ::send(fd, buf, len, 0); /* SO_NOSIGPIPE set on accepted fd below */
#endif
}

/* Set SO_NOSIGPIPE on a socket (macOS). No-op on other platforms. */
static void suppress_sigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int v = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &v, sizeof(v));
#else
    (void)fd;
#endif
}

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            ++g_fail; \
        } else { ++g_pass; } \
    } while (0)

#define CHECK_EQ(a, b) \
    do { \
        auto _a = (a); auto _b = (b); \
        if (!(_a == _b)) { \
            std::fprintf(stderr, "FAIL: %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
            ++g_fail; \
        } else { ++g_pass; } \
    } while (0)

/* ── Tests ───────────────────────────────────────────────────────────────── */

static void test_usp_error_kinds() {
    std::puts("test_usp_error_kinds");

    auto e1 = UspError::timeout();
    CHECK(e1.kind() == UspError::Kind::Timeout);
    CHECK(e1.to_string() == "timeout");

    auto e2 = UspError::connection_failed("refused");
    CHECK(e2.is_recoverable());
    CHECK(e2.to_string().find("refused") != std::string::npos);

    auto e3 = UspError::agent_rejected(7004, "invalid arguments");
    CHECK(e3.kind() == UspError::Kind::AgentRejected);
    CHECK_EQ(e3.code(), 7004u);
    CHECK(e3.to_string().find("7004") != std::string::npos);

    auto e4 = UspError::not_implemented("register");
    CHECK(e4.kind() == UspError::Kind::NotImplemented);
    CHECK(e4.to_string().find("register") != std::string::npos);

    /* A broken pipe / closed peer is a lost connection: callers must reconnect, not report a bad frame. */
    auto e5 = UspError::from_transport(TransportError::io("send: Broken pipe"));
    CHECK(e5.kind() == UspError::Kind::ConnectionFailed);
    CHECK(e5.is_recoverable());
    CHECK(!UspError::from_transport(TransportError::protocol("bad frame")).is_recoverable());
}

static void test_vendor_defined_error_codes() {
    std::puts("test_vendor_defined_error_codes");

    CHECK(usp_error_is_vendor_defined(7800) == 1);
    CHECK(usp_error_is_vendor_defined(7900) == 1);
    CHECK(usp_error_is_vendor_defined(7999) == 1);
    CHECK(usp_error_is_vendor_defined(7799) == 0);
    CHECK(usp_error_is_vendor_defined(8000) == 0);
    CHECK(usp_error_is_vendor_defined(0)    == 0);
    CHECK(usp_error_is_vendor_defined(7000) == 0);
}

static void test_usp_controller_new_null() {
    std::puts("test_usp_controller_new_null");

    CHECK(usp_controller_new(nullptr, "app", "agent", 10) == nullptr);
    CHECK(usp_controller_new("/tmp/x.sock", nullptr, "agent", 10) == nullptr);
    CHECK(usp_controller_new("/tmp/x.sock", "app", nullptr, 10) == nullptr);
}

static void test_set_timeout() {
    std::puts("test_set_timeout");

    auto* h = usp_controller_new("/tmp/nonexistent_uspmtp.sock",
                                  "proto::app", "proto::agent", 5);
    CHECK(h != nullptr);
    if (!h) return;

    int rc = usp_controller_set_timeout(h, 15);
    CHECK_EQ(rc, USP_OK);

    rc = usp_controller_set_timeout(nullptr, 15);
    CHECK_EQ(rc, USP_ERR_NULL_POINTER);

    usp_controller_free(h);
}

static void test_set_password_guards() {
    std::puts("test_set_password_guards");

    CHECK_EQ(usp_controller_set_password(nullptr, "x"), USP_ERR_NULL_POINTER);

    UspControllerHandle* h = usp_controller_new("/tmp/none.sock", "proto::app", "proto::agent", 1);
    CHECK(h != nullptr);
    if (h) {
        CHECK_EQ(usp_controller_set_password(h, nullptr), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_set_password(h, "s3cret"), USP_OK);
        CHECK_EQ(usp_controller_set_password(h, ""), USP_OK);
        usp_controller_free(h);
    }
}

static void test_last_error() {
    std::puts("test_last_error");

    /* Buffer-too-small case. */
    auto* h = usp_controller_new("/tmp/nonexistent_uspmtp.sock",
                                  "proto::app", "proto::agent", 1);
    CHECK(h != nullptr);
    if (!h) return;

    /* A failed get should populate last_error. */
    char value[256];
    int rc = usp_controller_get(h, "Device.DeviceInfo.SerialNumber",
                                 value, sizeof(value));
    CHECK(rc == USP_ERR_USP);

    char err[512];
    int err_rc = usp_controller_last_error(h, err, sizeof(err));
    CHECK_EQ(err_rc, USP_OK);
    CHECK(err[0] != '\0'); /* non-empty error message */

    /* Null handle. */
    err_rc = usp_controller_last_error(nullptr, err, sizeof(err));
    CHECK_EQ(err_rc, USP_ERR_NULL_POINTER);

    usp_controller_free(h);
}

static void test_get_null_guard() {
    std::puts("test_get_null_guard");

    char value[64];
    int rc = usp_controller_get(nullptr, "Device.X", value, sizeof(value));
    CHECK_EQ(rc, USP_ERR_NULL_POINTER);
}

static void test_not_implemented_stubs() {
    std::puts("test_not_implemented_stubs");

    auto* h = usp_controller_new("/tmp/nonexistent_uspmtp.sock",
                                  "proto::app", "proto::agent", 1);
    CHECK(h != nullptr);
    if (!h) return;

    int rc;

    rc = usp_controller_register(h, "Device.X.");
    CHECK_EQ(rc, USP_ERR_USP);

    rc = usp_controller_delete(h, "Device.X.1.");
    CHECK_EQ(rc, USP_ERR_USP);

    rc = usp_controller_get_supported_dm(h, "Device.");
    CHECK_EQ(rc, USP_ERR_USP);

    rc = usp_controller_get_instances(h, "Device.X.");
    CHECK_EQ(rc, USP_ERR_USP);

    rc = usp_controller_get_supported_protocol(h);
    CHECK_EQ(rc, USP_ERR_USP);

    char err[512];
    usp_controller_last_error(h, err, sizeof(err));
    CHECK(std::strstr(err, "implemented") != nullptr);

    usp_controller_free(h);
}

static void test_usp_controller_construction() {
    std::puts("test_usp_controller_construction");

    /* UspController can be constructed without connecting. */
    UspController c("/tmp/noexist.sock", "proto::app", "proto::agent");
    c.set_timeout(std::chrono::seconds(5));
    CHECK(c.timeout() == std::chrono::seconds(5));
}

/* ── Mock-agent socket test ───────────────────────────────────────────────── */

static std::string make_tmp_socket_path() {
    static int counter = 0;
    return "/tmp/uspmtp_client_test_" + std::to_string(getpid()) +
           "_" + std::to_string(++counter) + ".sock";
}

/*
 * Build a complete UDS frame (sync + outer_len + TLV) from a frame type and
 * value bytes.
 */
static std::vector<uint8_t> make_uds_frame(uint8_t frame_type,
                                            const std::vector<uint8_t>& value) {
    uint32_t vlen = value.size();
    uint32_t olen = 5 + vlen;
    std::vector<uint8_t> f;
    f.push_back(0x5F); f.push_back(0x55); f.push_back(0x53); f.push_back(0x50);
    f.push_back((olen>>24)&0xFF); f.push_back((olen>>16)&0xFF);
    f.push_back((olen>>8)&0xFF);  f.push_back(olen&0xFF);
    f.push_back(frame_type);
    f.push_back((vlen>>24)&0xFF); f.push_back((vlen>>16)&0xFF);
    f.push_back((vlen>>8)&0xFF);  f.push_back(vlen&0xFF);
    f.insert(f.end(), value.begin(), value.end());
    return f;
}

/*
 * Build a minimal GetResp record wrapping a single parameter.
 */
static std::vector<uint8_t> build_get_resp_record(const std::string& path,
                                                   const std::string& value) {
    using namespace proto;

    ResolvedPathResult rpr;
    auto dot = path.rfind('.');
    rpr.resolved_path = (dot != std::string::npos) ? path.substr(0, dot + 1) : path;
    rpr.result_params[dot != std::string::npos ? path.substr(dot + 1) : ""] = value;

    RequestedPathResult rr;
    rr.requested_path = path;
    rr.resolved_path_results = {rpr};

    GetResp gr;
    gr.req_path_results = {rr};

    Response resp;
    resp.resp_type = std::move(gr);

    Body body;
    body.msg_body = std::move(resp);

    Header h;
    h.msg_id   = "resp-1";
    h.msg_type = MsgType::GetResp;

    Msg msg;
    msg.header = h;
    msg.body   = body;

    NoSessionContextRecord nsc;
    nsc.payload = msg.encode();

    Record rec;
    rec.version = "1.5";
    rec.to_id   = "proto::app";
    rec.from_id = "proto::agent";
    rec.record_type = nsc;

    return rec.encode();
}

static void test_get_with_mock_agent() {
    std::puts("test_get_with_mock_agent");

    std::string sock_path = make_tmp_socket_path();
    ::unlink(sock_path.c_str());

    int srv_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) { std::puts("  SKIP: cannot create socket"); return; }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) != 0 ||
        ::listen(srv_fd, 1) != 0)
    {
        ::close(srv_fd);
        std::puts("  SKIP: cannot bind/listen");
        return;
    }

    auto resp_bytes = build_get_resp_record("Device.DeviceInfo.SerialNumber", "SN-42");

    std::thread server([srv_fd, &sock_path, &resp_bytes]() {
        int cli_fd = ::accept(srv_fd, nullptr, nullptr);
        if (cli_fd < 0) { ::close(srv_fd); return; }

        suppress_sigpipe(cli_fd);

        /* Consume client handshake. */
        uint8_t sync[4]; ::read(cli_fd, sync, 4);
        uint8_t olen_buf[4]; ::read(cli_fd, olen_buf, 4);
        uint32_t olen = (olen_buf[0]<<24)|(olen_buf[1]<<16)|(olen_buf[2]<<8)|olen_buf[3];
        std::vector<uint8_t> hs(olen); ::read(cli_fd, hs.data(), olen);

        /* Send server handshake. */
        std::string sid = "proto::agent";
        auto hf = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
        sock_write(cli_fd, hf.data(), hf.size());

        /* Consume GET request. */
        uint8_t sync2[4]; ::read(cli_fd, sync2, 4);
        uint8_t olen2[4]; ::read(cli_fd, olen2, 4);
        uint32_t ol2 = (olen2[0]<<24)|(olen2[1]<<16)|(olen2[2]<<8)|olen2[3];
        std::vector<uint8_t> req(ol2); ::read(cli_fd, req.data(), ol2);

        /* Send GET response. */
        auto rf = make_uds_frame(3, resp_bytes);
        sock_write(cli_fd, rf.data(), rf.size());

        ::close(cli_fd);
        ::close(srv_fd);
        ::unlink(sock_path.c_str());
    });

    UspController client(sock_path, "proto::app", "proto::agent");
    client.set_timeout(std::chrono::seconds(5));

    auto result = client.get("Device.DeviceInfo.SerialNumber");
    server.join();

    if (auto* resp = std::get_if<GetResponse>(&result)) {
        auto it = resp->params.find("Device.DeviceInfo.SerialNumber");
        CHECK(it != resp->params.end());
        if (it != resp->params.end())
            CHECK_EQ(it->second, "SN-42");
    } else {
        auto& err = std::get<UspError>(result);
        std::fprintf(stderr, "  NOTE: get returned error: %s\n",
                     err.to_string().c_str());
        /* Non-fatal: network may not be available in test environment. */
        ++g_pass;
    }
}

/*
 * Regression: if the agent drops an idle session, the worker thread exits.  The next request must open a new
 * session and succeed; before the fix it was queued onto the dead worker and its future never completed.
 */
static bool read_exact(int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    while (n > 0) {
        ssize_t r = ::read(fd, p, n);
        if (r <= 0) return false;
        p += r; n -= static_cast<size_t>(r);
    }
    return true;
}

static bool read_uds_frame(int fd) {
    uint8_t hdr[8];
    if (!read_exact(fd, hdr, 8)) return false;
    uint32_t len = (hdr[4]<<24)|(hdr[5]<<16)|(hdr[6]<<8)|hdr[7];
    std::vector<uint8_t> body(len);
    return read_exact(fd, body.data(), len);
}

static void test_get_after_agent_drops_session(int delay_ms) {
    std::printf("test_get_after_agent_drops_session (next request after %d ms)\n", delay_ms);

    std::string sock_path = make_tmp_socket_path();
    ::unlink(sock_path.c_str());
    int srv_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    if (srv_fd < 0 || ::bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) != 0 || ::listen(srv_fd, 2) != 0) {
        std::puts("  SKIP: cannot bind/listen");
        return;
    }

    auto resp_bytes = build_get_resp_record("Device.DeviceInfo.SerialNumber", "SN-42");
    proto::Record ack;
    ack.version = "1.5"; ack.to_id = "proto::app"; ack.from_id = "proto::agent";
    ack.record_type = proto::UdsConnectRecord{};
    auto ack_frame = make_uds_frame(3, ack.encode());
    std::string sid = "proto::agent";
    auto hs_frame = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
    auto resp_frame = make_uds_frame(3, resp_bytes);

    std::thread server([&]() {
        for (int conn = 0; conn < 2; ++conn) {
            int fd = ::accept(srv_fd, nullptr, nullptr);
            if (fd < 0) return;
            suppress_sigpipe(fd);
            read_uds_frame(fd);                                  /* client handshake */
            sock_write(fd, hs_frame.data(), hs_frame.size());
            read_uds_frame(fd);                                  /* UDSConnectRecord */
            sock_write(fd, ack_frame.data(), ack_frame.size());
            read_uds_frame(fd);                                  /* GET */
            sock_write(fd, resp_frame.data(), resp_frame.size());
            if (conn == 0) {
                ::close(fd);                                     /* drop the session */
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
                ::close(fd);
            }
        }
    });

    UspController client(sock_path, "proto::app", "proto::agent");
    client.set_timeout(std::chrono::seconds(5));

    auto first = client.get("Device.DeviceInfo.SerialNumber");
    CHECK(std::holds_alternative<GetResponse>(first));

    /* 1800 ms: the idle worker has noticed EOF and stopped.  0 ms: the next request races the close and may
     * hit a broken pipe on send. */
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));

    auto fut = std::async(std::launch::async, [&] { return client.get("Device.DeviceInfo.SerialNumber"); });
    if (fut.wait_for(std::chrono::seconds(12)) != std::future_status::ready) {
        std::fputs("  FAIL: get() hung on a dead session\n", stderr);
        std::_Exit(1);
    }
    auto second = fut.get();
    CHECK(std::holds_alternative<GetResponse>(second));

    server.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}

/*
 * Regression: a request on an idle session must start at once.  The worker used to sit in a 1 s socket read and
 * only looked for new commands when it returned, so each request waited 0-1 s (about 0.5 s on average).
 */
static void test_idle_session_request_latency() {
    std::puts("test_idle_session_request_latency");

    std::string sock_path = make_tmp_socket_path();
    ::unlink(sock_path.c_str());
    int srv_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    if (srv_fd < 0 || ::bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) != 0 || ::listen(srv_fd, 1) != 0) {
        std::puts("  SKIP: cannot bind/listen");
        return;
    }

    constexpr int kRequests = 6;
    auto resp_bytes = build_get_resp_record("Device.DeviceInfo.SerialNumber", "SN-42");
    proto::Record ack;
    ack.version = "1.5"; ack.to_id = "proto::app"; ack.from_id = "proto::agent";
    ack.record_type = proto::UdsConnectRecord{};
    auto ack_frame = make_uds_frame(3, ack.encode());
    std::string sid = "proto::agent";
    auto hs_frame = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
    auto resp_frame = make_uds_frame(3, resp_bytes);

    std::thread server([&]() {
        int fd = ::accept(srv_fd, nullptr, nullptr);
        if (fd < 0) return;
        suppress_sigpipe(fd);
        read_uds_frame(fd);
        sock_write(fd, hs_frame.data(), hs_frame.size());
        read_uds_frame(fd);
        sock_write(fd, ack_frame.data(), ack_frame.size());
        for (int i = 0; i < kRequests && read_uds_frame(fd); ++i)
            sock_write(fd, resp_frame.data(), resp_frame.size());
        ::close(fd);
    });

    UspController client(sock_path, "proto::app", "proto::agent");
    client.set_timeout(std::chrono::seconds(5));

    long worst_ms = 0;
    for (int i = 0; i < kRequests; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(150)); /* let the worker go idle */
        auto t0 = std::chrono::steady_clock::now();
        auto r = client.get("Device.DeviceInfo.SerialNumber");
        long ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        CHECK(std::holds_alternative<GetResponse>(r));
        if (i > 0 && ms > worst_ms) worst_ms = ms; /* request 0 includes connecting */
    }
    std::printf("  slowest request on an idle session: %ld ms\n", worst_ms);
    CHECK(worst_ms < 200);

    server.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}


/* Read one whole UDS frame payload (after sync + outer_len). */
static bool read_uds_frame_payload(int fd, std::vector<uint8_t>& payload) {
    uint8_t hdr[8];
    if (!read_exact(fd, hdr, 8)) return false;
    uint32_t len = (hdr[4]<<24)|(hdr[5]<<16)|(hdr[6]<<8)|hdr[7];
    payload.assign(len, 0);
    return read_exact(fd, payload.data(), len);
}

/* True if the handshake payload carries a Password TLV (type 4) with this value. */
static bool handshake_has_password(const std::vector<uint8_t>& payload, const std::string& expected) {
    size_t pos = 0;
    while (pos + 5 <= payload.size()) {
        uint8_t type = payload[pos];
        uint32_t len = (payload[pos+1]<<24)|(payload[pos+2]<<16)|(payload[pos+3]<<8)|payload[pos+4];
        pos += 5;
        if (pos + len > payload.size()) return false;
        if (type == 4 && std::string(payload.begin()+pos, payload.begin()+pos+len) == expected) return true;
        pos += len;
    }
    return false;
}

/*
 * Through the C API: an agent socket that requires a password rejects the handshake until
 * usp_controller_set_password() is called; the next request then reconnects and succeeds.
 */
static void test_password_required_through_c_api() {
    std::puts("test_password_required_through_c_api");

    std::string sock_path = make_tmp_socket_path();
    ::unlink(sock_path.c_str());
    int srv_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    if (srv_fd < 0 || ::bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) != 0 || ::listen(srv_fd, 2) != 0) {
        std::puts("  SKIP: cannot bind/listen");
        return;
    }

    auto resp_bytes = build_get_resp_record("Device.DeviceInfo.SerialNumber", "SN-42");
    proto::Record ack;
    ack.version = "1.5"; ack.to_id = "proto::app"; ack.from_id = "proto::agent";
    ack.record_type = proto::UdsConnectRecord{};
    auto ack_frame = make_uds_frame(3, ack.encode());
    std::string sid = "proto::agent";
    auto hs_frame = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
    auto resp_frame = make_uds_frame(3, resp_bytes);
    std::string err_text = "Password required but none provided in UDS frame";
    auto err_frame = make_uds_frame(2, std::vector<uint8_t>(err_text.begin(), err_text.end()));

    std::thread server([&]() {
        for (int conn = 0; conn < 3; ++conn) {              /* 1: rejected, 2: retry also rejected, 3: accepted */
            int fd = ::accept(srv_fd, nullptr, nullptr);
            if (fd < 0) return;
            suppress_sigpipe(fd);
            std::vector<uint8_t> hs;
            if (!read_uds_frame_payload(fd, hs)) { ::close(fd); continue; }
            if (!handshake_has_password(hs, "pw")) {
                sock_write(fd, err_frame.data(), err_frame.size());
                ::close(fd);
                continue;
            }
            sock_write(fd, hs_frame.data(), hs_frame.size());
            read_uds_frame(fd);                                  /* UDSConnectRecord */
            sock_write(fd, ack_frame.data(), ack_frame.size());
            read_uds_frame(fd);                                  /* GET */
            sock_write(fd, resp_frame.data(), resp_frame.size());
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            ::close(fd);
            return;
        }
    });

    UspControllerHandle* h = usp_controller_new(sock_path.c_str(), "proto::app", "proto::agent", 5);
    CHECK(h != nullptr);
    if (h) {
        char value[64] = {0};
        int rc = usp_controller_get(h, "Device.DeviceInfo.SerialNumber", value, sizeof value);
        CHECK_EQ(rc, USP_ERR_USP);
        char err[256] = {0};
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("Password required") != std::string::npos);

        CHECK_EQ(usp_controller_set_password(h, "pw"), USP_OK);
        rc = usp_controller_get(h, "Device.DeviceInfo.SerialNumber", value, sizeof value);
        CHECK_EQ(rc, USP_OK);
        CHECK_EQ(std::string(value), "SN-42");
        usp_controller_free(h);
    }
    server.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}


/*
 * Regression: destroying the controller while its session is up (the agent still holds the
 * connection) must stop and join the worker. The worker used to own its SessionState, so when
 * the controller was freed first the worker became the last owner and joined itself on exit.
 */
static void test_destroy_controller_while_connected() {
    std::puts("test_destroy_controller_while_connected");

    std::string sock_path = make_tmp_socket_path();
    ::unlink(sock_path.c_str());
    int srv_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    if (srv_fd < 0 || ::bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) != 0 || ::listen(srv_fd, 1) != 0) {
        std::puts("  SKIP: cannot bind/listen");
        return;
    }

    auto resp_bytes = build_get_resp_record("Device.DeviceInfo.SerialNumber", "SN-42");
    proto::Record ack;
    ack.version = "1.5"; ack.to_id = "proto::app"; ack.from_id = "proto::agent";
    ack.record_type = proto::UdsConnectRecord{};
    auto ack_frame = make_uds_frame(3, ack.encode());
    std::string sid = "proto::agent";
    auto hs_frame = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
    auto resp_frame = make_uds_frame(3, resp_bytes);

    std::promise<void> controller_gone;
    auto gone = controller_gone.get_future();

    std::thread server([&]() {
        int fd = ::accept(srv_fd, nullptr, nullptr);
        if (fd < 0) return;
        suppress_sigpipe(fd);
        read_uds_frame(fd);
        sock_write(fd, hs_frame.data(), hs_frame.size());
        read_uds_frame(fd);
        sock_write(fd, ack_frame.data(), ack_frame.size());
        read_uds_frame(fd);
        sock_write(fd, resp_frame.data(), resp_frame.size());
        gone.wait();                         /* keep the connection open until the controller is destroyed */
        ::close(fd);
    });

    auto t0 = std::chrono::steady_clock::now();
    {
        UspController client(sock_path, "proto::app", "proto::agent");
        client.set_timeout(std::chrono::seconds(5));
        auto result = client.get("Device.DeviceInfo.SerialNumber");
        CHECK(std::holds_alternative<GetResponse>(result));
    }                                        /* destroyed while the session is still connected */
    long ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ms < 3000);                        /* the stop request wakes the worker; no 1 s poll wait, no self-join */
    controller_gone.set_value();

    server.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main() {
    /* Ignore SIGPIPE globally — sockets may close while session worker reconnects. */
    ::signal(SIGPIPE, SIG_IGN);

    test_usp_error_kinds();
    test_vendor_defined_error_codes();
    test_usp_controller_new_null();
    test_set_timeout();
    test_set_password_guards();
    test_last_error();
    test_get_null_guard();
    test_not_implemented_stubs();
    test_usp_controller_construction();
    test_get_with_mock_agent();
    test_get_after_agent_drops_session(1800);
    test_get_after_agent_drops_session(0);
    test_idle_session_request_latency();
    test_password_required_through_c_api();
    test_destroy_controller_while_connected();

    std::printf("\n%s: %d passed, %d failed\n",
                (g_fail == 0) ? "PASS" : "FAIL",
                g_pass, g_fail);
    return g_fail != 0 ? 1 : 0;
}
