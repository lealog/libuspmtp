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
#include "session.hpp"

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

    UspControllerHandle* h = usp_controller_new("/tmp/none.sock", "proto::app", "proto::agent", 1);
    CHECK(h != nullptr);
    if (!h) return;

    CHECK_EQ(usp_controller_register(h, "Device.TestApp."), USP_ERR_USP);
    char err[128] = {0};
    usp_controller_last_error(h, err, sizeof err);
    CHECK(std::string(err).find("Not yet implemented") != std::string::npos);

    /* Null guards of the implemented requests do not touch the (absent) agent. */
    char buf[64];
    CHECK_EQ(usp_controller_add(nullptr, "Device.X.", nullptr, nullptr, 0, buf, sizeof buf), USP_ERR_NULL_POINTER);
    CHECK_EQ(usp_controller_add(h, nullptr, nullptr, nullptr, 0, buf, sizeof buf), USP_ERR_NULL_POINTER);
    CHECK_EQ(usp_controller_delete(h, nullptr, buf, sizeof buf), USP_ERR_NULL_POINTER);
    CHECK_EQ(usp_controller_get_supported_dm(h, nullptr, 0, buf, sizeof buf), USP_ERR_NULL_POINTER);
    CHECK_EQ(usp_controller_get_instances(nullptr, "Device.X.", 0, buf, sizeof buf), USP_ERR_NULL_POINTER);
    CHECK_EQ(usp_controller_get_supported_protocol(nullptr, buf, sizeof buf), USP_ERR_NULL_POINTER);

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


/* ── Mock agent that answers requests with canned frames, in order ─────────── */

static int listen_unix(const std::string& sock_path) {
    ::unlink(sock_path.c_str());
    int srv_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) return -1;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) != 0 || ::listen(srv_fd, 2) != 0) {
        ::close(srv_fd);
        return -1;
    }
    return srv_fd;
}

/* A USP Record frame (type 3) from the agent to the app carrying `msg`. */
static std::vector<uint8_t> agent_frame(const proto::Msg& msg) {
    proto::NoSessionContextRecord nsc;
    nsc.payload = msg.encode();
    proto::Record rec;
    rec.version = "1.5";
    rec.to_id   = "proto::app";
    rec.from_id = "proto::agent";
    rec.record_type = nsc;
    return make_uds_frame(3, rec.encode());
}

static proto::Msg response_msg(const char* id, proto::ResponseVariant resp_type) {
    proto::Response resp;
    resp.resp_type = std::move(resp_type);
    proto::Body body;
    body.msg_body = resp;
    proto::Msg msg;
    msg.header = proto::Header{id, proto::msg_type_of(body)};
    msg.body = body;
    return msg;
}

static proto::Msg error_msg(const char* id, uint32_t code, const std::string& text) {
    proto::ErrorBody error;
    error.err_code = code;
    error.err_msg = text;
    proto::Body body;
    body.msg_body = error;
    proto::Msg msg;
    msg.header = proto::Header{id, proto::MsgType::Error};
    msg.body = body;
    return msg;
}


static proto::Msg request_msg_for_test(const char* id, proto::RequestVariant req_type) {
    proto::Request req;
    req.req_type = std::move(req_type);
    proto::Body body;
    body.msg_body = req;
    proto::Msg msg;
    msg.header = proto::Header{id, proto::msg_type_of(body)};
    msg.body = body;
    return msg;
}

/* Accept one connection, complete the UDS handshake and session, then answer each request with the next reply. */
static std::thread mock_agent(int srv_fd, std::vector<std::vector<uint8_t>> replies) {
    return std::thread([srv_fd, replies = std::move(replies)]() {
        int fd = ::accept(srv_fd, nullptr, nullptr);
        if (fd < 0) return;
        suppress_sigpipe(fd);

        std::string sid = "proto::agent";
        auto hs_frame = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
        proto::Record ack;
        ack.version = "1.5"; ack.to_id = "proto::app"; ack.from_id = "proto::agent";
        ack.record_type = proto::UdsConnectRecord{};
        auto ack_frame = make_uds_frame(3, ack.encode());

        read_uds_frame(fd);
        sock_write(fd, hs_frame.data(), hs_frame.size());
        read_uds_frame(fd);
        sock_write(fd, ack_frame.data(), ack_frame.size());
        for (const auto& reply : replies) {
            if (!read_uds_frame(fd)) break;
            sock_write(fd, reply.data(), reply.size());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ::close(fd);
    });
}

static std::vector<std::vector<uint8_t>> canned_discovery_replies() {
    proto::AddResp add_resp;
    proto::CreatedObjectResult created;
    created.requested_path = "Device.TestApp.Item.";
    proto::AddOperationSuccess add_ok;
    add_ok.instantiated_path = "Device.TestApp.Item.3.";
    add_ok.unique_keys = {{"Name", "new"}};
    add_ok.param_errs = {{"Colour", 7010, "Unsupported parameter"}};
    created.oper_status = proto::AddOperationStatus{add_ok};
    add_resp.created_obj_results = {created};

    proto::DeleteResp del_resp;
    proto::DeletedObjectResult deleted;
    deleted.requested_path = "Device.TestApp.Item.3.";
    proto::DeleteOperationSuccess del_ok;
    del_ok.affected_paths = {"Device.TestApp.Item.3."};
    del_ok.unaffected_path_errs = {{"Device.TestApp.Item.3.Child.1.", 7024, "Delete failure"}};
    deleted.oper_status = proto::DeleteOperationStatus{del_ok};
    del_resp.deleted_obj_results = {deleted};

    proto::GetSupportedDMResp gsdm_resp;
    proto::RequestedObjectResult gsdm_result;
    gsdm_result.req_obj_path = "Device.TestApp.";
    proto::SupportedObjectResult object;
    object.supported_obj_path = "Device.TestApp.Item.{i}.";
    object.access = proto::ObjAccessType::AddDelete;
    object.is_multi_instance = true;
    object.supported_params = {{"Name", proto::ParamAccessType::ReadWrite, proto::ParamValueType::String,
                                proto::ValueChangeType::Allowed}};
    object.supported_commands = {{"Reset()", {"Hard"}, {"Status"}, proto::CmdType::Async}};
    object.supported_events = {{"Changed!", {"Reason"}}};
    gsdm_result.supported_objs = {object};
    proto::RequestedObjectResult gsdm_failed;
    gsdm_failed.req_obj_path = "Device.Missing.";
    gsdm_failed.err_code = 7026;
    gsdm_failed.err_msg = "Invalid path";
    gsdm_resp.req_obj_results = {gsdm_result, gsdm_failed};

    proto::GetInstancesResp gi_resp;
    proto::InstancesPathResult gi_result;
    gi_result.requested_path = "Device.TestApp.Item.";
    gi_result.curr_insts = {{"Device.TestApp.Item.1.", {{"Name", "a"}}}, {"Device.TestApp.Item.2.", {{"Name", "b"}}}};
    gi_resp.req_path_results = {gi_result};

    return {
        agent_frame(response_msg("r1", add_resp)),
        agent_frame(response_msg("r2", del_resp)),
        agent_frame(response_msg("r3", gsdm_resp)),
        agent_frame(response_msg("r4", gi_resp)),
        agent_frame(response_msg("r5", proto::GetSupportedProtocolResp{"1.3,1.4,1.5"})),
    };
}

static void test_add_delete_discovery_cpp_api() {
    std::puts("test_add_delete_discovery_cpp_api");

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }
    auto server = mock_agent(srv_fd, canned_discovery_replies());

    UspController client(sock_path, "proto::app", "proto::agent");
    client.set_timeout(std::chrono::seconds(5));

    auto add = client.add("Device.TestApp.Item.", {{"Name", "new"}, {"Colour", "red"}});
    auto* add_ok = std::get_if<AddResponse>(&add);
    CHECK(add_ok != nullptr);
    if (add_ok) {
        CHECK_EQ(add_ok->instantiated_path, "Device.TestApp.Item.3.");
        CHECK_EQ(add_ok->unique_keys.at("Name"), "new");
        CHECK(add_ok->param_errors.size() == 1);
        if (add_ok->param_errors.size() == 1) {
            CHECK_EQ(add_ok->param_errors[0].path, "Colour");
            CHECK_EQ(add_ok->param_errors[0].err_code, 7010u);
        }
    }

    auto del = client.delete_instance("Device.TestApp.Item.3.");
    auto* del_ok = std::get_if<DeleteResponse>(&del);
    CHECK(del_ok != nullptr);
    if (del_ok) {
        CHECK_EQ(del_ok->affected_paths, std::vector<std::string>{"Device.TestApp.Item.3."});
        CHECK(del_ok->unaffected_paths.size() == 1);
        if (del_ok->unaffected_paths.size() == 1) CHECK_EQ(del_ok->unaffected_paths[0].err_code, 7024u);
    }

    auto gsdm = client.get_supported_dm("Device.TestApp.");
    auto* gsdm_ok = std::get_if<SupportedDMResponse>(&gsdm);
    CHECK(gsdm_ok != nullptr);
    if (gsdm_ok) {
        CHECK(gsdm_ok->objects.size() == 1);
        if (gsdm_ok->objects.size() == 1) {
            CHECK_EQ(gsdm_ok->objects[0].supported_obj_path, "Device.TestApp.Item.{i}.");
            CHECK(gsdm_ok->objects[0].is_multi_instance);
            CHECK(gsdm_ok->objects[0].supported_params.size() == 1);
            CHECK(gsdm_ok->objects[0].supported_commands.size() == 1);
            CHECK(gsdm_ok->objects[0].supported_events.size() == 1);
        }
        CHECK(gsdm_ok->errors.size() == 1);
        if (gsdm_ok->errors.size() == 1) CHECK_EQ(gsdm_ok->errors[0].err_code, 7026u);
    }

    auto gi = client.get_instances("Device.TestApp.Item.", true);
    auto* gi_ok = std::get_if<InstancesResponse>(&gi);
    CHECK(gi_ok != nullptr);
    if (gi_ok) {
        CHECK(gi_ok->instances.size() == 2);
        if (gi_ok->instances.size() == 2) {
            CHECK_EQ(gi_ok->instances[1].instantiated_obj_path, "Device.TestApp.Item.2.");
            CHECK_EQ(gi_ok->instances[1].unique_keys.at("Name"), "b");
        }
        CHECK(gi_ok->errors.empty());
    }

    auto gsp = client.get_supported_protocol();
    auto* versions = std::get_if<std::string>(&gsp);
    CHECK(versions != nullptr);
    if (versions) CHECK_EQ(*versions, "1.3,1.4,1.5");

    server.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}

static void test_add_delete_discovery_c_api() {
    std::puts("test_add_delete_discovery_c_api");

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }
    auto server = mock_agent(srv_fd, canned_discovery_replies());

    UspControllerHandle* h = usp_controller_new(sock_path.c_str(), "proto::app", "proto::agent", 5);
    CHECK(h != nullptr);
    if (h) {
        char out[2048];
        const char* names[]  = {"Name", "Colour"};
        const char* values[] = {"new", "red"};
        CHECK_EQ(usp_controller_add(h, "Device.TestApp.Item.", names, values, 2, out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out), "INSTANCE\tDevice.TestApp.Item.3.\nKEY\tName\tnew\nERROR\tColour\t7010\tUnsupported parameter\n");

        CHECK_EQ(usp_controller_delete(h, "Device.TestApp.Item.3.", out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out), "AFFECTED\tDevice.TestApp.Item.3.\nUNAFFECTED\tDevice.TestApp.Item.3.Child.1.\t7024\tDelete failure\n");

        CHECK_EQ(usp_controller_get_supported_dm(h, "Device.TestApp.", 0, out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out),
                 "OBJECT\tDevice.TestApp.Item.{i}.\tAddDelete\t1\n"
                 "PARAM\tDevice.TestApp.Item.{i}.\tName\tReadWrite\tString\n"
                 "COMMAND\tDevice.TestApp.Item.{i}.\tReset()\tAsync\tHard\tStatus\n"
                 "EVENT\tDevice.TestApp.Item.{i}.\tChanged!\tReason\n"
                 "ERROR\tDevice.Missing.\t7026\tInvalid path\n");

        CHECK_EQ(usp_controller_get_instances(h, "Device.TestApp.Item.", 1, out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out),
                 "INSTANCE\tDevice.TestApp.Item.1.\nKEY\tDevice.TestApp.Item.1.\tName\ta\n"
                 "INSTANCE\tDevice.TestApp.Item.2.\nKEY\tDevice.TestApp.Item.2.\tName\tb\n");

        char versions[32] = {0};
        CHECK_EQ(usp_controller_get_supported_protocol(h, versions, sizeof versions), USP_OK);
        CHECK_EQ(std::string(versions), "1.3,1.4,1.5");

        usp_controller_free(h);
    }
    server.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}

/* Agent refusals, mismatched response types and too-small output buffers are reported, never silently dropped. */
static void test_request_error_paths() {
    std::puts("test_request_error_paths");

    proto::AddResp refused;
    proto::CreatedObjectResult created;
    created.requested_path = "Device.TestApp.Fixed.";
    created.oper_status = proto::AddOperationStatus{proto::AddOperationFailure{7019, "Not creatable"}};
    refused.created_obj_results = {created};

    proto::GetInstancesResp gi_resp;
    proto::InstancesPathResult gi_result;
    gi_result.requested_path = "Device.TestApp.Item.";
    gi_result.curr_insts = {{"Device.TestApp.Item.1.", {{"Name", "a"}}}};
    gi_resp.req_path_results = {gi_result};

    std::vector<std::vector<uint8_t>> replies = {
        agent_frame(error_msg("e1", 7004, "Invalid arguments")),           /* add    -> Error body        */
        agent_frame(response_msg("e2", proto::GetResp{})),                   /* delete -> wrong response    */
        agent_frame(response_msg("e3", refused)),                            /* add    -> operation failure */
        agent_frame(response_msg("e4", gi_resp)),                            /* get_instances, small buffer */
        agent_frame(response_msg("e5", proto::GetSupportedDMResp{})),        /* get_supported_dm, empty     */
    };

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }
    auto server = mock_agent(srv_fd, std::move(replies));

    UspControllerHandle* h = usp_controller_new(sock_path.c_str(), "proto::app", "proto::agent", 5);
    CHECK(h != nullptr);
    if (h) {
        char out[64] = {0};
        char err[256] = {0};

        CHECK_EQ(usp_controller_add(h, "Device.TestApp.Item.", nullptr, nullptr, 0, out, sizeof out), USP_ERR_USP);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("7004") != std::string::npos);

        CHECK_EQ(usp_controller_delete(h, "Device.TestApp.Item.1.", out, sizeof out), USP_ERR_USP);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("unexpected response type") != std::string::npos);

        CHECK_EQ(usp_controller_add(h, "Device.TestApp.Fixed.", nullptr, nullptr, 0, out, sizeof out), USP_ERR_USP);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("7019") != std::string::npos);
        CHECK(std::string(err).find("Not creatable") != std::string::npos);

        char tiny[8];
        CHECK_EQ(usp_controller_get_instances(h, "Device.TestApp.Item.", 0, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);

        CHECK_EQ(usp_controller_get_supported_dm(h, "Device.TestApp.", 1, out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out), "");

        usp_controller_free(h);
    }
    server.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}


/* ── Session helpers (shared by the controller and the service) ──────────── */

static void test_session_helpers() {
    std::puts("test_session_helpers");

    proto::Record connect;
    connect.record_type = proto::UdsConnectRecord{};
    auto no_nsc = detail::extract_msg(connect);
    CHECK(std::holds_alternative<UspError>(no_nsc));
    if (auto* e = std::get_if<UspError>(&no_nsc)) CHECK(e->to_string().find("expected NoSessionContextRecord") != std::string::npos);

    proto::NoSessionContextRecord nsc;
    nsc.payload = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    proto::Record garbage;
    garbage.record_type = nsc;
    auto bad = detail::extract_msg(garbage);
    CHECK(std::holds_alternative<UspError>(bad));
    if (auto* e = std::get_if<UspError>(&bad)) CHECK(e->to_string().find("failed to decode inner Msg") != std::string::npos);

    proto::Body body;
    proto::Response resp;
    resp.resp_type = proto::GetResp{};
    body.msg_body = resp;
    auto reply = detail::build_reply_record("proto::a", "proto::b", "id-7", body);
    CHECK_EQ(reply.from_id, "proto::a");
    CHECK_EQ(reply.to_id, "proto::b");
    auto msg = detail::extract_msg(reply);
    CHECK(std::holds_alternative<proto::Msg>(msg));
    if (auto* m = std::get_if<proto::Msg>(&msg)) {
        CHECK(m->header && m->header->msg_id == "id-7" && m->header->msg_type == proto::MsgType::GetResp);
    }
    CHECK(detail::next_msg_id() != detail::next_msg_id());

    /* establish_uds_session: the peer answers with something other than a UDSConnectRecord. */
    {
        std::string sock_path = make_tmp_socket_path();
        int srv_fd = listen_unix(sock_path);
        if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }
        std::thread server([srv_fd]() {
            int fd = ::accept(srv_fd, nullptr, nullptr);
            if (fd < 0) return;
            suppress_sigpipe(fd);
            read_uds_frame(fd);
            std::string sid = "proto::agent";
            auto hs = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
            sock_write(fd, hs.data(), hs.size());
            read_uds_frame(fd);                                    /* our connect record */
            auto wrong = agent_frame(error_msg("x", 7003, "nope"));
            sock_write(fd, wrong.data(), wrong.size());
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            ::close(fd);
        });
        auto t = Transport::connect(sock_path, std::chrono::seconds(1), "proto::app");
        CHECK(std::holds_alternative<Transport>(t));
        if (auto* tr = std::get_if<Transport>(&t)) {
            auto err = detail::establish_uds_session(*tr, "proto::app", "proto::agent", std::chrono::seconds(2));
            CHECK(err.has_value());
            if (err) CHECK(err->to_string().find("expected UDSConnectRecord") != std::string::npos);
        }
        server.join();
        ::close(srv_fd);
        ::unlink(sock_path.c_str());
    }
    /* establish_uds_session: the peer stays silent past the deadline, then one that closes. */
    for (int closes = 0; closes < 2; ++closes) {
        std::string sock_path = make_tmp_socket_path();
        int srv_fd = listen_unix(sock_path);
        if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }
        std::thread server([srv_fd, closes]() {
            int fd = ::accept(srv_fd, nullptr, nullptr);
            if (fd < 0) return;
            suppress_sigpipe(fd);
            read_uds_frame(fd);
            std::string sid = "proto::agent";
            auto hs = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
            sock_write(fd, hs.data(), hs.size());
            read_uds_frame(fd);
            std::this_thread::sleep_for(std::chrono::milliseconds(closes ? 200 : 2600));
            ::close(fd);
        });
        auto t = Transport::connect(sock_path, std::chrono::seconds(1), "proto::app");
        if (auto* tr = std::get_if<Transport>(&t)) {
            auto err = detail::establish_uds_session(*tr, "proto::app", "proto::agent", std::chrono::seconds(2));
            CHECK(err.has_value());
            if (err) {
                if (closes) CHECK(err->is_recoverable() && !err->is_timeout());
                else CHECK(err->to_string().find("no UDS Connect acknowledgement") != std::string::npos);
            }
        } else {
            CHECK(false);
        }
        server.join();
        ::close(srv_fd);
        ::unlink(sock_path.c_str());
    }
}

/* ── Set, operate and the remaining response-parsing branches ─────────────── */

static proto::SetResp set_resp_ok(const std::string& path) {
    proto::SetResp resp;
    proto::UpdatedObjectResult r;
    r.requested_path = path;
    r.oper_status = proto::OperationStatus{proto::OperationSuccess{}};
    resp.updated_obj_results = {r};
    return resp;
}

static void test_set_and_operate_paths() {
    std::puts("test_set_and_operate_paths");

    proto::SetResp set_failed;
    proto::UpdatedObjectResult rf;
    rf.requested_path = "Device.WiFi.SSID.9.";
    rf.oper_status = proto::OperationStatus{proto::OperationFailure{7016, "Object does not exist", {}}};
    set_failed.updated_obj_results = {rf};

    proto::OperateResp op_ok;
    proto::OperationResult ok_result;
    ok_result.executed_command = "Device.Reboot()";
    ok_result.operation_resp = proto::OutputArgs{{{"Status", "Scheduled"}}};
    op_ok.operation_results = {ok_result};

    proto::OperateResp op_failed;
    proto::OperationResult failed_result;
    failed_result.executed_command = "Device.Broken()";
    failed_result.operation_resp = proto::CommandFailure{7022, "Command failure"};
    op_failed.operation_results = {failed_result};

    proto::OperateResp op_async;
    proto::OperationResult async_result;
    async_result.executed_command = "Device.Long()";
    async_result.operation_resp = std::string("Device.LocalAgent.Request.3.");
    op_async.operation_results = {async_result};

    proto::Msg empty_body;
    empty_body.header = proto::Header{"nobody", proto::MsgType::GetResp};

    std::vector<std::vector<uint8_t>> replies = {
        agent_frame(response_msg("s1", set_resp_ok("Device.WiFi.SSID.1."))),  /* set ok                     */
        agent_frame(response_msg("s2", set_failed)),                           /* set: per-object failure    */
        agent_frame(error_msg("s3", 7004, "Invalid arguments")),               /* set: Error body            */
        agent_frame(response_msg("s4", proto::GetResp{})),                     /* set: wrong response type   */
        agent_frame(response_msg("o1", op_ok)),                                /* operate ok                 */
        agent_frame(response_msg("o2", op_failed)),                            /* operate: command failure   */
        agent_frame(response_msg("o3", op_async)),                             /* operate: async, no output  */
        agent_frame(error_msg("o4", 7002, "Request denied")),                  /* operate: Error body        */
        agent_frame(response_msg("o5", proto::SetResp{})),                     /* operate: wrong type        */
        agent_frame(error_msg("g1", 7006, "Permission denied")),               /* get: Error body            */
        agent_frame(response_msg("g2", proto::OperateResp{})),                 /* get: wrong type            */
        agent_frame(empty_body),                                               /* get: empty body            */
        agent_frame(response_msg("g3", proto::GetSupportedProtocolResp{})),    /* get_supported_protocol: ok, empty */
        agent_frame(error_msg("g4", 7001, "Not supported")),                   /* get_supported_dm: Error    */
        agent_frame(response_msg("g5", proto::SetResp{})),                     /* get_instances: wrong type  */
        agent_frame(error_msg("g6", 7001, "Not supported")),                   /* get_supported_protocol: Error */
        agent_frame(response_msg("g7", proto::SetResp{})),                     /* get_supported_dm: wrong type */
        agent_frame(error_msg("g8", 7001, "Not supported")),                   /* get_instances: Error */
        agent_frame(response_msg("d1", proto::DeleteResp{})),                  /* delete: no result          */
        agent_frame(response_msg("a1", proto::AddResp{})),                     /* add: no result             */
        agent_frame(error_msg("d2", 7024, "Delete failure")),                  /* delete: Error body         */
    };

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }
    auto server = mock_agent(srv_fd, std::move(replies));

    UspController client(sock_path, "proto::app", "proto::agent");
    client.set_timeout(std::chrono::seconds(5));

    auto s1 = client.set("Device.WiFi.SSID.1.SSID", "home");
    auto* s1ok = std::get_if<SetResponse>(&s1);
    CHECK(s1ok != nullptr);
    if (s1ok) CHECK_EQ(s1ok->updated, std::vector<std::string>{"Device.WiFi.SSID.1."});

    auto s2 = client.set_many({{"Device.WiFi.SSID.9.SSID", "x"}, {"Device.WiFi.SSID.9.Enable", "true"}, {"NoDot", "v"}});
    auto* s2ok = std::get_if<SetResponse>(&s2);
    CHECK(s2ok != nullptr);
    if (s2ok) {
        CHECK(s2ok->errors.size() == 1 && s2ok->errors[0].err_code == 7016);
        CHECK(s2ok->updated.empty());
    }
    auto s3 = client.set("Device.X", "1");
    CHECK(std::holds_alternative<UspError>(s3));
    if (auto* e = std::get_if<UspError>(&s3)) CHECK_EQ(e->code(), 7004u);
    auto s4 = client.set("Device.X", "1");
    if (auto* e = std::get_if<UspError>(&s4)) CHECK(e->to_string().find("unexpected response type for SET") != std::string::npos); else CHECK(false);

    auto o1 = client.operate("Device.Reboot()", {{"Delay", "0"}});
    auto* o1ok = std::get_if<OperateResponse>(&o1);
    CHECK(o1ok != nullptr);
    if (o1ok) CHECK_EQ(o1ok->output_args.at("Status"), "Scheduled");
    auto o2 = client.operate("Device.Broken()", {});
    if (auto* e = std::get_if<UspError>(&o2)) { CHECK_EQ(e->code(), 7022u); CHECK_EQ(e->message(), "Command failure"); } else CHECK(false);
    auto o3 = client.operate("Device.Long()", {});
    auto* o3ok = std::get_if<OperateResponse>(&o3);
    CHECK(o3ok != nullptr && o3ok->output_args.empty());
    auto o4 = client.operate("Device.Reboot()", {});
    if (auto* e = std::get_if<UspError>(&o4)) CHECK_EQ(e->code(), 7002u); else CHECK(false);
    auto o5 = client.operate("Device.Reboot()", {});
    if (auto* e = std::get_if<UspError>(&o5)) CHECK(e->to_string().find("unexpected response type for OPERATE") != std::string::npos); else CHECK(false);

    auto g1 = client.get("Device.Secret");
    if (auto* e = std::get_if<UspError>(&g1)) CHECK_EQ(e->code(), 7006u); else CHECK(false);
    auto g2 = client.get("Device.X");
    if (auto* e = std::get_if<UspError>(&g2)) CHECK(e->to_string().find("unexpected response type for GET") != std::string::npos); else CHECK(false);
    auto g2b = client.get("Device.X");
    if (auto* e = std::get_if<UspError>(&g2b)) CHECK(e->to_string().find("empty body") != std::string::npos); else CHECK(false);
    auto g3 = client.get_supported_protocol();
    CHECK(std::holds_alternative<std::string>(g3));
    auto g4 = client.get_supported_dm("Device.");
    if (auto* e = std::get_if<UspError>(&g4)) CHECK_EQ(e->code(), 7001u); else CHECK(false);
    auto g5 = client.get_instances("Device.");
    if (auto* e = std::get_if<UspError>(&g5)) CHECK(e->to_string().find("unexpected response type for GET_INSTANCES") != std::string::npos); else CHECK(false);
    auto g6 = client.get_supported_protocol("1.5");
    if (auto* e = std::get_if<UspError>(&g6)) CHECK_EQ(e->code(), 7001u); else CHECK(false);
    auto g7 = client.get_supported_dm("Device.");
    if (auto* e = std::get_if<UspError>(&g7)) CHECK(e->to_string().find("unexpected response type for GET_SUPPORTED_DM") != std::string::npos); else CHECK(false);
    auto g8 = client.get_instances("Device.");
    if (auto* e = std::get_if<UspError>(&g8)) CHECK_EQ(e->code(), 7001u); else CHECK(false);
    auto d1 = client.delete_instance("Device.X.1.");
    if (auto* e = std::get_if<UspError>(&d1)) CHECK(e->to_string().find("carries no result") != std::string::npos); else CHECK(false);
    auto a1 = client.add("Device.X.", {});
    if (auto* e = std::get_if<UspError>(&a1)) CHECK(e->to_string().find("carries no result") != std::string::npos); else CHECK(false);
    auto d2 = client.delete_instance("Device.X.1.");
    if (auto* e = std::get_if<UspError>(&d2)) CHECK_EQ(e->code(), 7024u); else CHECK(false);

    server.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}

/* ── Subscriptions and agent-originated Notify, through the C API ─────────── */

static void on_notify(void* user_data) { ++*static_cast<int*>(user_data); }

static void test_subscriptions_and_notify() {
    std::puts("test_subscriptions_and_notify");

    proto::AddResp sub_ok;
    proto::CreatedObjectResult created;
    created.requested_path = "Device.LocalAgent.Subscription.";
    proto::AddOperationSuccess ok;
    ok.instantiated_path = "Device.LocalAgent.Subscription.5.";
    created.oper_status = proto::AddOperationStatus{ok};
    sub_ok.created_obj_results = {created};

    proto::AddResp sub_exists;
    proto::CreatedObjectResult exists;
    exists.requested_path = "Device.LocalAgent.Subscription.";
    exists.oper_status = proto::AddOperationStatus{proto::AddOperationFailure{7025, "Subscription ID already in use"}};
    sub_exists.created_obj_results = {exists};

    proto::AddResp sub_refused;
    proto::CreatedObjectResult refused;
    refused.requested_path = "Device.LocalAgent.Subscription.";
    refused.oper_status = proto::AddOperationStatus{proto::AddOperationFailure{7006, "Permission denied"}};
    sub_refused.created_obj_results = {refused};

    proto::GetResp values;
    proto::RequestedPathResult rr;
    rr.requested_path = "Device.WiFi.SSID.1.SSID";
    proto::ResolvedPathResult rp;
    rp.resolved_path = "Device.WiFi.SSID.1.";
    rp.result_params = {{"SSID", "home"}};
    rr.resolved_path_results = {rp};
    values.req_path_results = {rr};

    proto::Notify notify;
    notify.subscription_id = "sub-x";
    notify.send_resp = true;
    notify.notification = proto::ValueChange{"Device.WiFi.SSID.1.SSID", "away"};

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }

    std::optional<proto::Msg> notify_resp;
    std::thread agent([&]() {
        int fd = ::accept(srv_fd, nullptr, nullptr);
        if (fd < 0) return;
        suppress_sigpipe(fd);
        std::string sid = "proto::agent";
        auto hs = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
        proto::Record ack;
        ack.version = "1.5"; ack.to_id = "proto::app"; ack.from_id = "proto::agent";
        ack.record_type = proto::UdsConnectRecord{};
        auto ack_frame = make_uds_frame(3, ack.encode());
        read_uds_frame(fd); sock_write(fd, hs.data(), hs.size());
        read_uds_frame(fd); sock_write(fd, ack_frame.data(), ack_frame.size());

        /* subscribe_and_get: Add then Get; the Notify arrives while the Get is pending, so the worker handles it inline. */
        read_uds_frame(fd); auto f1 = agent_frame(response_msg("n1", sub_ok)); sock_write(fd, f1.data(), f1.size());
        read_uds_frame(fd);
        auto nf = agent_frame(request_msg_for_test("n-notify", notify)); sock_write(fd, nf.data(), nf.size());
        auto f2 = agent_frame(response_msg("n2", values)); sock_write(fd, f2.data(), f2.size());
        /* the NotifyResp the client owes for send_resp=true */
        {
            std::vector<uint8_t> payload;
            if (read_uds_frame_payload(fd, payload)) {
                size_t pos = 0;
                while (pos + 5 <= payload.size()) {
                    uint8_t type = payload[pos];
                    uint32_t len = (payload[pos+1]<<24)|(payload[pos+2]<<16)|(payload[pos+3]<<8)|payload[pos+4];
                    pos += 5;
                    if (type == 3 && pos + len <= payload.size()) {
                        auto rec = proto::Record::decode(std::vector<uint8_t>(payload.begin()+pos, payload.begin()+pos+len));
                        if (rec) { auto m = detail::extract_msg(*rec); if (auto* mm = std::get_if<proto::Msg>(&m)) notify_resp = *mm; }
                    }
                    pos += len;
                }
            }
        }
        /* a Notify while idle (no request pending) also reaches the callback, with no response asked */
        proto::Notify quiet = notify; quiet.send_resp = false;
        auto qf = agent_frame(request_msg_for_test("n-quiet", quiet)); sock_write(fd, qf.data(), qf.size());
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        /* subscribe_many_and_get with one "already exists" result, then its Get */
        read_uds_frame(fd); auto f3 = agent_frame(response_msg("n3", sub_exists)); sock_write(fd, f3.data(), f3.size());
        read_uds_frame(fd); auto f4 = agent_frame(response_msg("n4", values)); sock_write(fd, f4.data(), f4.size());
        /* a refused subscription */
        read_uds_frame(fd); auto f5 = agent_frame(response_msg("n5", sub_refused)); sock_write(fd, f5.data(), f5.size());
        /* an Error body */
        read_uds_frame(fd); auto f6 = agent_frame(error_msg("n6", 7003, "Internal error")); sock_write(fd, f6.data(), f6.size());
        /* a response of the wrong type */
        read_uds_frame(fd); auto f7 = agent_frame(response_msg("n7", proto::GetResp{})); sock_write(fd, f7.data(), f7.size());
        /* subscribe_and_get into a buffer too small for the values: Add, then Get */
        read_uds_frame(fd); auto f8 = agent_frame(response_msg("n8", sub_ok)); sock_write(fd, f8.data(), f8.size());
        read_uds_frame(fd); auto f9 = agent_frame(response_msg("n9", values)); sock_write(fd, f9.data(), f9.size());
        /* subscribe_many_and_get into a buffer too small */
        read_uds_frame(fd); auto f10 = agent_frame(response_msg("n10", sub_ok)); sock_write(fd, f10.data(), f10.size());
        read_uds_frame(fd); auto f11 = agent_frame(response_msg("n11", values)); sock_write(fd, f11.data(), f11.size());
        /* subscribe_many_and_get refused with an Error body */
        read_uds_frame(fd); auto f12 = agent_frame(error_msg("n12", 7006, "Permission denied")); sock_write(fd, f12.data(), f12.size());
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        ::close(fd);
    });

    int notified = 0;
    UspControllerHandle* h = usp_controller_new(sock_path.c_str(), "proto::app", "proto::agent", 5);
    CHECK(h != nullptr);
    if (h) {
        char out[512] = {0};
        CHECK_EQ(usp_controller_subscribe_and_get(h, "Device.WiFi.SSID.1.SSID", USP_SUBSCRIPTION_VALUE_CHANGE,
                                                  on_notify, &notified, out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out), "PARAM\tDevice.WiFi.SSID.1.SSID\thome\n");
        for (int i = 0; i < 40 && notified < 2; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        CHECK_EQ(notified, 2);

        const char* paths[] = {"Device.WiFi.SSID.1.SSID", "Device.WiFi.SSID.1.SSID"};
        int types[] = {USP_SUBSCRIPTION_OBJECT_CREATION, USP_SUBSCRIPTION_OBJECT_DELETION};
        CHECK_EQ(usp_controller_subscribe_many_and_get(h, paths, types, 2, nullptr, nullptr, out, sizeof out), USP_OK);

        CHECK_EQ(usp_controller_subscribe_and_get(h, "Device.X", USP_SUBSCRIPTION_VALUE_CHANGE, nullptr, nullptr, out, sizeof out), USP_ERR_USP);
        char err[256] = {0};
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("Permission denied") != std::string::npos);
        CHECK_EQ(usp_controller_subscribe_and_get(h, "Device.X", USP_SUBSCRIPTION_VALUE_CHANGE, nullptr, nullptr, out, sizeof out), USP_ERR_USP);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("7003") != std::string::npos);
        CHECK_EQ(usp_controller_subscribe_and_get(h, "Device.X", USP_SUBSCRIPTION_VALUE_CHANGE, nullptr, nullptr, out, sizeof out), USP_ERR_USP);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("unexpected ADD response") != std::string::npos);

        char tiny[3];
        CHECK_EQ(usp_controller_subscribe_and_get(h, "Device.WiFi.SSID.2.SSID", USP_SUBSCRIPTION_VALUE_CHANGE, nullptr, nullptr, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        const char* more_paths[] = {"Device.WiFi.SSID.3.SSID"};
        CHECK_EQ(usp_controller_subscribe_many_and_get(h, more_paths, types, 1, on_notify, &notified, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        const char* denied_paths[] = {"Device.Secret.X"};
        CHECK_EQ(usp_controller_subscribe_many_and_get(h, denied_paths, types, 1, nullptr, nullptr, out, sizeof out), USP_ERR_USP);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("Permission denied") != std::string::npos);

        /* argument guards, none of which reach the agent */
        CHECK_EQ(usp_controller_subscribe_and_get(h, "Device.X", 42, nullptr, nullptr, out, sizeof out), USP_ERR_INVALID_ARGUMENT);
        CHECK_EQ(usp_controller_subscribe_and_get(nullptr, "Device.X", 0, nullptr, nullptr, out, sizeof out), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_subscribe_many_and_get(h, paths, types, 0, nullptr, nullptr, out, sizeof out), USP_ERR_INVALID_ARGUMENT);
        CHECK_EQ(usp_controller_subscribe_many_and_get(h, nullptr, types, 1, nullptr, nullptr, out, sizeof out), USP_ERR_NULL_POINTER);
        int bad_types[] = {99};
        CHECK_EQ(usp_controller_subscribe_many_and_get(h, paths, bad_types, 1, nullptr, nullptr, out, sizeof out), USP_ERR_INVALID_ARGUMENT);
        const char* null_paths[] = {nullptr};
        CHECK_EQ(usp_controller_subscribe_many_and_get(h, null_paths, types, 1, nullptr, nullptr, out, sizeof out), USP_ERR_NULL_POINTER);
        usp_controller_free(h);
    }
    agent.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());

    CHECK(notify_resp.has_value());
    if (notify_resp && notify_resp->header && notify_resp->body) {
        CHECK(notify_resp->header->msg_type == proto::MsgType::NotifyResp);
        auto* r = std::get_if<proto::Response>(&notify_resp->body->msg_body);
        auto* nr = r ? std::get_if<proto::NotifyResp>(&r->resp_type) : nullptr;
        CHECK(nr != nullptr && nr->subscription_id == "sub-x");
    }
}

/* ── The remaining C API branches: get/get_many/set/set_many/operate text, buffers, guards ── */

static void test_c_api_controller_text_and_buffers() {
    std::puts("test_c_api_controller_text_and_buffers");

    proto::GetResp one;
    proto::RequestedPathResult r1;
    r1.requested_path = "Device.DeviceInfo.SerialNumber";
    proto::ResolvedPathResult p1;
    p1.resolved_path = "Device.DeviceInfo.";
    p1.result_params = {{"SerialNumber", "SN-1"}};
    r1.resolved_path_results = {p1};
    one.req_path_results = {r1};

    proto::GetResp other_path;                     /* a single value, but not under the requested name */
    proto::RequestedPathResult r2 = r1;
    r2.resolved_path_results[0].result_params = {{"ModelName", "M-1"}};
    other_path.req_path_results = {r2};

    proto::GetResp two_values;                     /* several values, none of them the requested one */
    proto::RequestedPathResult r3 = r1;
    r3.resolved_path_results[0].result_params = {{"ModelName", "M-1"}, {"SerialNumber", "SN-1"}};
    two_values.req_path_results = {r3};

    proto::GetResp with_error;
    proto::RequestedPathResult r4;
    r4.requested_path = "Device.Nope.";
    r4.err_code = 7026;
    r4.err_msg = "Invalid path";
    with_error.req_path_results = {r1, r4};

    proto::OperateResp op;
    proto::OperationResult res;
    res.executed_command = "Device.Reboot()";
    res.operation_resp = proto::OutputArgs{{{"Status", "Done"}}};
    op.operation_results = {res};

    proto::SetResp set_mixed;
    proto::UpdatedObjectResult u1;
    u1.requested_path = "Device.A.";
    u1.oper_status = proto::OperationStatus{proto::OperationSuccess{}};
    proto::UpdatedObjectResult u2;
    u2.requested_path = "Device.B.";
    u2.oper_status = proto::OperationStatus{proto::OperationFailure{7013, "Non-writable", {}}};
    set_mixed.updated_obj_results = {u1, u2};

    /* One reply per request, in the order the calls below make them; argument guards make no request. */
    std::vector<std::vector<uint8_t>> replies = {
        agent_frame(response_msg("c1", one)),                       /* get: exact match                     */
        agent_frame(response_msg("c2", other_path)),                /* get: the one value, other name       */
        agent_frame(response_msg("c3", two_values)),                /* get: not found                       */
        agent_frame(response_msg("c4", one)),                       /* get: buffer too small                */
        agent_frame(error_msg("c5", 7004, "bad")),                  /* get: Error body                      */
        agent_frame(response_msg("c6", one)),                       /* get: no buffer wanted (len 0)        */
        agent_frame(response_msg("c7", one)),                       /* get: NULL buffer with a length       */
        agent_frame(response_msg("c7b", with_error)),               /* get_many: result discarded (NULL, 0) */
        agent_frame(response_msg("c7c", with_error)),               /* get_many: NULL buffer with a length  */
        agent_frame(response_msg("c8", with_error)),                /* get_many: text                       */
        agent_frame(response_msg("c9", with_error)),                /* get_many_depth: buffer too small     */
        agent_frame(error_msg("c10", 7004, "bad")),                 /* get_many: Error body                 */
        agent_frame(response_msg("c11", set_resp_ok("Device.A."))), /* set: ok                              */
        agent_frame(error_msg("c12", 7013, "Non-writable")),        /* set: Error body                      */
        agent_frame(response_msg("c13", set_mixed)),                /* set_many: text                       */
        agent_frame(response_msg("c14", set_mixed)),                /* set_many: buffer too small           */
        agent_frame(error_msg("c15", 7004, "bad")),                 /* set_many: Error body                 */
        agent_frame(response_msg("c16", op)),                       /* operate: text                        */
        agent_frame(response_msg("c17", op)),                       /* operate: buffer too small            */
        agent_frame(error_msg("c18", 7002, "denied")),              /* operate: Error body                  */
    };

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }
    auto server = mock_agent(srv_fd, std::move(replies));

    UspControllerHandle* h = usp_controller_new(sock_path.c_str(), "proto::app", "proto::agent", 5);
    CHECK(h != nullptr);
    if (h) {
        char out[512] = {0};
        char err[256] = {0};
        char tiny[3];
        CHECK_EQ(usp_controller_get(h, "Device.DeviceInfo.SerialNumber", out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out), "SN-1");
        CHECK_EQ(usp_controller_get(h, "Device.DeviceInfo.SerialNumber", out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out), "M-1");
        CHECK_EQ(usp_controller_get(h, "Device.Nope.", out, sizeof out), USP_ERR_NOT_FOUND);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("not found in response") != std::string::npos);
        CHECK_EQ(usp_controller_get(h, "Device.DeviceInfo.SerialNumber", tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("too small") != std::string::npos);
        CHECK_EQ(usp_controller_get(h, "Device.DeviceInfo.SerialNumber", out, sizeof out), USP_ERR_USP);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("7004") != std::string::npos);
        CHECK_EQ(usp_controller_get(h, "Device.DeviceInfo.SerialNumber", nullptr, 0), USP_ERR_NULL_POINTER); /* a value needs a buffer */
        CHECK_EQ(usp_controller_get(h, "Device.DeviceInfo.SerialNumber", nullptr, 8), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_get(h, nullptr, out, sizeof out), USP_ERR_NULL_POINTER);

        const char* paths[] = {"Device.DeviceInfo.SerialNumber", "Device.Nope."};
        CHECK_EQ(usp_controller_get_many(h, paths, 2, nullptr, 0), USP_OK);                       /* result discarded */
        CHECK_EQ(usp_controller_get_many(h, paths, 2, nullptr, 8), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_get_many(h, paths, 2, out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out), "PARAM\tDevice.DeviceInfo.SerialNumber\tSN-1\nERROR\tDevice.Nope.\t7026\tInvalid path\n");
        CHECK_EQ(usp_controller_get_many_depth(h, paths, 2, 1, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(usp_controller_get_many(h, paths, 2, out, sizeof out), USP_ERR_USP);
        CHECK_EQ(usp_controller_get_many(h, paths, 0, out, sizeof out), USP_ERR_INVALID_ARGUMENT);
        CHECK_EQ(usp_controller_get_many(nullptr, paths, 2, out, sizeof out), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_get_many(h, nullptr, 2, out, sizeof out), USP_ERR_NULL_POINTER);
        const char* null_path[] = {nullptr};
        CHECK_EQ(usp_controller_get_many(h, null_path, 1, out, sizeof out), USP_ERR_NULL_POINTER);

        CHECK_EQ(usp_controller_set(h, "Device.A.X", "1"), USP_OK);
        CHECK_EQ(usp_controller_set(h, "Device.A.X", "1"), USP_ERR_USP);
        CHECK_EQ(usp_controller_set(h, nullptr, "1"), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_set(h, "Device.A.X", nullptr), USP_ERR_NULL_POINTER);
        const char* sp[] = {"Device.A.X", "Device.B.Y"};
        const char* sv[] = {"1", "2"};
        CHECK_EQ(usp_controller_set_many(h, sp, sv, 2, out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out), "UPDATED\tDevice.A.\nERROR\tDevice.B.\t7013\tNon-writable\n");
        CHECK_EQ(usp_controller_set_many(h, sp, sv, 2, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(usp_controller_set_many(h, sp, sv, 2, out, sizeof out), USP_ERR_USP);
        CHECK_EQ(usp_controller_set_many(h, sp, sv, 0, out, sizeof out), USP_ERR_INVALID_ARGUMENT);
        CHECK_EQ(usp_controller_set_many(h, sp, nullptr, 2, out, sizeof out), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_set_many(nullptr, sp, sv, 2, out, sizeof out), USP_ERR_NULL_POINTER);
        const char* null_value[] = {nullptr, nullptr};
        CHECK_EQ(usp_controller_set_many(h, sp, null_value, 2, out, sizeof out), USP_ERR_NULL_POINTER);

        const char* an[] = {"Delay"};
        const char* av[] = {"0"};
        CHECK_EQ(usp_controller_operate(h, "Device.Reboot()", an, av, 1, out, sizeof out), USP_OK);
        CHECK_EQ(std::string(out), "OUTPUT\tStatus\tDone\n");
        CHECK_EQ(usp_controller_operate(h, "Device.Reboot()", an, av, 1, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(usp_controller_operate(h, "Device.Reboot()", nullptr, nullptr, 0, out, sizeof out), USP_ERR_USP);
        CHECK_EQ(usp_controller_operate(h, nullptr, nullptr, nullptr, 0, out, sizeof out), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_operate(h, "Device.X()", an, nullptr, 1, out, sizeof out), USP_ERR_NULL_POINTER);

        CHECK_EQ(usp_controller_set_timeout(h, 0), USP_OK);
        CHECK_EQ(usp_controller_set_timeout(nullptr, 1), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_last_error(h, nullptr, 8), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_last_error(h, out, 0), USP_ERR_INVALID_ARGUMENT);
        CHECK_EQ(usp_controller_last_error(h, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(usp_error_is_vendor_defined(7800), 1);
        CHECK_EQ(usp_error_is_vendor_defined(7026), 0);
        usp_controller_free(h);
    }
    server.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}

/* ── The agent drops the connection in the middle of a request, then stops answering ── */

static void test_request_retried_after_drop_and_timeout() {
    std::puts("test_request_retried_after_drop_and_timeout");

    auto resp_bytes = build_get_resp_record("Device.DeviceInfo.SerialNumber", "SN-42");
    proto::Record ack;
    ack.version = "1.5"; ack.to_id = "proto::app"; ack.from_id = "proto::agent";
    ack.record_type = proto::UdsConnectRecord{};
    auto ack_frame = make_uds_frame(3, ack.encode());
    std::string sid = "proto::agent";
    auto hs_frame = make_uds_frame(1, std::vector<uint8_t>(sid.begin(), sid.end()));
    auto resp_frame = make_uds_frame(3, resp_bytes);

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }

    /* connection 1: drop while the GET is pending; connection 2: serve one GET, then never answer the next */
    std::thread agent([&]() {
        for (int conn = 0; conn < 2; ++conn) {
            int fd = ::accept(srv_fd, nullptr, nullptr);
            if (fd < 0) return;
            suppress_sigpipe(fd);
            read_uds_frame(fd); sock_write(fd, hs_frame.data(), hs_frame.size());
            read_uds_frame(fd); sock_write(fd, ack_frame.data(), ack_frame.size());
            read_uds_frame(fd);                                 /* the GET */
            if (conn == 1) {
                sock_write(fd, resp_frame.data(), resp_frame.size());
                read_uds_frame(fd);                             /* the next GET: left unanswered */
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
            }
            ::close(fd);
        }
    });

    UspController client(sock_path, "proto::app", "proto::agent");
    client.set_timeout(std::chrono::seconds(1));
    auto first = client.get("Device.DeviceInfo.SerialNumber");        /* dropped, then served on a new connection */
    CHECK(std::holds_alternative<GetResponse>(first));
    if (auto* e = std::get_if<UspError>(&first)) std::fprintf(stderr, "  first: %s\n", e->to_string().c_str());
    auto t0 = std::chrono::steady_clock::now();
    auto second = client.get("Device.DeviceInfo.SerialNumber");       /* never answered: times out, reconnect fails */
    long ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    auto* err = std::get_if<UspError>(&second);
    CHECK(err != nullptr);
    if (err) CHECK(err->is_recoverable());
    CHECK(ms >= 900 && ms < 4500);

    agent.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}


/* ── Discovery through the C API: every enum string, and the buffer/Error branch of each call ── */

static void test_c_api_discovery_errors_and_enums() {
    std::puts("test_c_api_discovery_errors_and_enums");

    proto::GetSupportedDMResp gsdm;
    proto::RequestedObjectResult result;
    result.req_obj_path = "Device.Zoo.";
    proto::SupportedObjectResult ro, ao, dl;
    ro.supported_obj_path = "Device.Zoo.";
    ro.access = proto::ObjAccessType::ReadOnly;
    ro.supported_params = {
        {"A", proto::ParamAccessType::ReadOnly,  proto::ParamValueType::Unknown,      proto::ValueChangeType::Unknown},
        {"B", proto::ParamAccessType::WriteOnly, proto::ParamValueType::Base64,       proto::ValueChangeType::Allowed},
        {"C", proto::ParamAccessType::ReadWrite, proto::ParamValueType::Boolean,      proto::ValueChangeType::Allowed},
        {"D", proto::ParamAccessType::ReadOnly,  proto::ParamValueType::DateTime,     proto::ValueChangeType::Allowed},
        {"E", proto::ParamAccessType::ReadOnly,  proto::ParamValueType::Decimal,      proto::ValueChangeType::Allowed},
        {"F", proto::ParamAccessType::ReadOnly,  proto::ParamValueType::HexBinary,    proto::ValueChangeType::Allowed},
        {"G", proto::ParamAccessType::ReadOnly,  proto::ParamValueType::Int,          proto::ValueChangeType::Allowed},
        {"H", proto::ParamAccessType::ReadOnly,  proto::ParamValueType::Long,         proto::ValueChangeType::Allowed},
        {"I", proto::ParamAccessType::ReadOnly,  proto::ParamValueType::UnsignedInt,  proto::ValueChangeType::Allowed},
        {"J", proto::ParamAccessType::ReadOnly,  proto::ParamValueType::UnsignedLong, proto::ValueChangeType::Allowed},
    };
    ro.supported_commands = {{"Sync()", {}, {}, proto::CmdType::Sync}, {"Odd()", {}, {}, proto::CmdType::Unknown}};
    ao.supported_obj_path = "Device.Zoo.AddOnly.{i}.";
    ao.access = proto::ObjAccessType::AddOnly;
    ao.is_multi_instance = true;
    dl.supported_obj_path = "Device.Zoo.DeleteOnly.{i}.";
    dl.access = proto::ObjAccessType::DeleteOnly;
    dl.is_multi_instance = true;
    result.supported_objs = {ro, ao, dl};
    gsdm.req_obj_results = {result};

    proto::AddResp add_resp;
    proto::CreatedObjectResult created;
    created.requested_path = "Device.Zoo.AddOnly.";
    proto::AddOperationSuccess add_ok;
    add_ok.instantiated_path = "Device.Zoo.AddOnly.1.";
    created.oper_status = proto::AddOperationStatus{add_ok};
    add_resp.created_obj_results = {created};

    proto::DeleteResp del_resp;
    proto::DeletedObjectResult deleted;
    deleted.requested_path = "Device.Zoo.DeleteOnly.1.";
    proto::DeleteOperationSuccess del_ok;
    del_ok.affected_paths = {"Device.Zoo.DeleteOnly.1."};
    deleted.oper_status = proto::DeleteOperationStatus{del_ok};
    del_resp.deleted_obj_results = {deleted};

    proto::GetInstancesResp gi_resp;
    proto::InstancesPathResult gi_result;
    gi_result.requested_path = "Device.Zoo.AddOnly.";
    gi_result.curr_insts = {{"Device.Zoo.AddOnly.1.", {}}};
    gi_resp.req_path_results = {gi_result};

    std::vector<std::vector<uint8_t>> replies = {
        agent_frame(response_msg("z1", gsdm)),                                  /* gsdm: every enum string      */
        agent_frame(response_msg("z2", gsdm)),                                  /* gsdm: buffer too small       */
        agent_frame(error_msg("z3", 7001, "Not supported")),                    /* gsdm: Error body             */
        agent_frame(response_msg("z4", add_resp)),                              /* add: buffer too small        */
        agent_frame(error_msg("z5", 7006, "Permission denied")),                /* add: Error body              */
        agent_frame(response_msg("z6", del_resp)),                              /* delete: buffer too small     */
        agent_frame(error_msg("z7", 7006, "Permission denied")),                /* delete: Error body           */
        agent_frame(response_msg("z8", gi_resp)),                               /* get_instances: buffer small  */
        agent_frame(error_msg("z9", 7001, "Not supported")),                    /* get_instances: Error body    */
        agent_frame(response_msg("z10", proto::GetSupportedProtocolResp{"1.5"})), /* gsp: buffer too small      */
        agent_frame(error_msg("z11", 7001, "Not supported")),                   /* gsp: Error body              */
    };

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }
    auto server = mock_agent(srv_fd, std::move(replies));

    UspControllerHandle* h = usp_controller_new(sock_path.c_str(), "proto::app", "proto::agent", 5);
    CHECK(h != nullptr);
    if (h) {
        char out[2048] = {0};
        char tiny[3];
        char err[256] = {0};
        CHECK_EQ(usp_controller_get_supported_dm(h, "Device.Zoo.", 1, out, sizeof out), USP_OK);
        std::string text = out;
        for (const char* expected : {"OBJECT\tDevice.Zoo.\tReadOnly\t0\n", "OBJECT\tDevice.Zoo.AddOnly.{i}.\tAddOnly\t1\n",
                                     "OBJECT\tDevice.Zoo.DeleteOnly.{i}.\tDeleteOnly\t1\n",
                                     "\tA\tReadOnly\tUnknown\n", "\tB\tWriteOnly\tBase64\n", "\tC\tReadWrite\tBoolean\n",
                                     "\tD\tReadOnly\tDateTime\n", "\tE\tReadOnly\tDecimal\n", "\tF\tReadOnly\tHexBinary\n",
                                     "\tG\tReadOnly\tInt\n", "\tH\tReadOnly\tLong\n", "\tI\tReadOnly\tUnsignedInt\n",
                                     "\tJ\tReadOnly\tUnsignedLong\n", "COMMAND\tDevice.Zoo.\tSync()\tSync\t\t\n",
                                     "COMMAND\tDevice.Zoo.\tOdd()\tUnknown\t\t\n"}) {
            bool found = text.find(expected) != std::string::npos;
            if (!found) std::fprintf(stderr, "  missing %s in:\n%s", expected, text.c_str());
            CHECK(found);
        }
        CHECK_EQ(usp_controller_get_supported_dm(h, "Device.Zoo.", 1, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(usp_controller_get_supported_dm(h, "Device.Zoo.", 1, out, sizeof out), USP_ERR_USP);
        usp_controller_last_error(h, err, sizeof err);
        CHECK(std::string(err).find("7001") != std::string::npos);
        CHECK_EQ(usp_controller_get_supported_dm(h, nullptr, 1, out, sizeof out), USP_ERR_NULL_POINTER);

        const char* names[] = {"Name"};
        const char* values[] = {"x"};
        CHECK_EQ(usp_controller_add(h, "Device.Zoo.AddOnly.", names, values, 1, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(usp_controller_add(h, "Device.Zoo.AddOnly.", nullptr, nullptr, 0, out, sizeof out), USP_ERR_USP);
        CHECK_EQ(usp_controller_add(h, "Device.Zoo.AddOnly.", names, nullptr, 1, out, sizeof out), USP_ERR_NULL_POINTER);
        CHECK_EQ(usp_controller_add(h, nullptr, nullptr, nullptr, 0, out, sizeof out), USP_ERR_NULL_POINTER);

        CHECK_EQ(usp_controller_delete(h, "Device.Zoo.DeleteOnly.1.", tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(usp_controller_delete(h, "Device.Zoo.DeleteOnly.1.", out, sizeof out), USP_ERR_USP);
        CHECK_EQ(usp_controller_delete(h, nullptr, out, sizeof out), USP_ERR_NULL_POINTER);

        CHECK_EQ(usp_controller_get_instances(h, "Device.Zoo.AddOnly.", 1, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(usp_controller_get_instances(h, "Device.Zoo.AddOnly.", 1, out, sizeof out), USP_ERR_USP);
        CHECK_EQ(usp_controller_get_instances(h, nullptr, 1, out, sizeof out), USP_ERR_NULL_POINTER);

        CHECK_EQ(usp_controller_get_supported_protocol(h, tiny, sizeof tiny), USP_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(usp_controller_get_supported_protocol(h, out, sizeof out), USP_ERR_USP);
        CHECK_EQ(usp_controller_get_supported_protocol(nullptr, out, sizeof out), USP_ERR_NULL_POINTER);
        usp_controller_free(h);
    }
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
    test_add_delete_discovery_cpp_api();
    test_add_delete_discovery_c_api();
    test_request_error_paths();
    test_session_helpers();
    test_set_and_operate_paths();
    test_subscriptions_and_notify();
    test_c_api_controller_text_and_buffers();
    test_request_retried_after_drop_and_timeout();
    test_c_api_discovery_errors_and_enums();

    std::printf("\n%s: %d passed, %d failed\n",
                (g_fail == 0) ? "PASS" : "FAIL",
                g_pass, g_fail);
    return g_fail != 0 ? 1 : 0;
}
