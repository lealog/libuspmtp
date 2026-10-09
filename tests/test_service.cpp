/*
 * Copyright 2026 Kartik Gohil
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Tests for UspService against a mock USP Broker: the broker side of the
 * UDS handshake and session, Register, then every request the broker routes
 * to a service, a subscription with its Notify, and Deregister on stop.
 */

#include "service.hpp"
#include "usp_proto.hpp"

#include "libuspmtp.h"

#include <cstdio>
#include <cstring>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace usp;

static int g_pass = 0;
static int g_fail = 0;

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

/* ── Socket and UDS frame helpers (the broker side) ──────────────────────── */

static std::string make_tmp_socket_path() {
    static int counter = 0;
    return "/tmp/uspmtp_service_test_" + std::to_string(getpid()) + "_" + std::to_string(++counter) + ".sock";
}

static int listen_unix(const std::string& sock_path) {
    ::unlink(sock_path.c_str());
    int srv_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) return -1;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) != 0 || ::listen(srv_fd, 1) != 0) {
        ::close(srv_fd);
        return -1;
    }
    return srv_fd;
}

static void suppress_sigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)fd;
#endif
}

static bool read_exact(int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    while (n > 0) {
        ssize_t r = ::read(fd, p, n);
        if (r <= 0) return false;
        p += r; n -= static_cast<size_t>(r);
    }
    return true;
}

static std::vector<uint8_t> make_uds_frame(uint8_t frame_type, const std::vector<uint8_t>& value) {
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

static void write_frame(int fd, const std::vector<uint8_t>& frame) {
    ::send(fd, frame.data(), frame.size(), 0);
}

/* Read one frame and return its TLVs as (type, value). */
static bool read_tlvs(int fd, std::vector<std::pair<uint8_t, std::vector<uint8_t>>>& out) {
    uint8_t hdr[8];
    if (!read_exact(fd, hdr, 8)) return false;
    uint32_t len = (hdr[4]<<24)|(hdr[5]<<16)|(hdr[6]<<8)|hdr[7];
    std::vector<uint8_t> payload(len);
    if (!read_exact(fd, payload.data(), len)) return false;
    size_t pos = 0;
    out.clear();
    while (pos + 5 <= payload.size()) {
        uint8_t type = payload[pos];
        uint32_t vlen = (payload[pos+1]<<24)|(payload[pos+2]<<16)|(payload[pos+3]<<8)|payload[pos+4];
        pos += 5;
        if (pos + vlen > payload.size()) return false;
        out.emplace_back(type, std::vector<uint8_t>(payload.begin()+pos, payload.begin()+pos+vlen));
        pos += vlen;
    }
    return true;
}

static std::optional<proto::Record> read_record(int fd) {
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> tlvs;
    if (!read_tlvs(fd, tlvs)) return std::nullopt;
    for (auto& [type, value] : tlvs)
        if (type == 3) return proto::Record::decode(value);
    return std::nullopt;
}

static std::optional<proto::Msg> read_msg(int fd) {
    auto rec = read_record(fd);
    if (!rec) return std::nullopt;
    auto* nsc = std::get_if<proto::NoSessionContextRecord>(&rec->record_type);
    if (!nsc) return std::nullopt;
    return proto::Msg::decode(nsc->payload);
}

static void send_record(int fd, const proto::Record& rec) {
    write_frame(fd, make_uds_frame(3, rec.encode()));
}

static void send_msg(int fd, const proto::Msg& msg) {
    proto::NoSessionContextRecord nsc;
    nsc.payload = msg.encode();
    proto::Record rec;
    rec.version = "1.5";
    rec.to_id = "proto::svc";
    rec.from_id = "proto::broker";
    rec.record_type = nsc;
    send_record(fd, rec);
}

static proto::Msg request_msg(const char* id, proto::RequestVariant req_type) {
    proto::Request req;
    req.req_type = std::move(req_type);
    proto::Body body;
    body.msg_body = req;
    proto::Msg msg;
    msg.header = proto::Header{id, proto::msg_type_of(body)};
    msg.body = body;
    return msg;
}

static proto::Msg response_msg(const std::string& id, proto::ResponseVariant resp_type) {
    proto::Response resp;
    resp.resp_type = std::move(resp_type);
    proto::Body body;
    body.msg_body = resp;
    proto::Msg msg;
    msg.header = proto::Header{id, proto::msg_type_of(body)};
    msg.body = body;
    return msg;
}

static proto::Msg error_msg(const std::string& id, uint32_t code, const std::string& text) {
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

/* Broker side of the UDS handshake and session establishment; returns the connected fd or -1. */
static int broker_accept(int srv_fd, std::string* seen_password = nullptr) {
    int fd = ::accept(srv_fd, nullptr, nullptr);
    if (fd < 0) return -1;
    suppress_sigpipe(fd);
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> tlvs;
    if (!read_tlvs(fd, tlvs)) { ::close(fd); return -1; }
    for (auto& [type, value] : tlvs)
        if (type == 4 && seen_password) seen_password->assign(value.begin(), value.end());
    std::string bid = "proto::broker";
    write_frame(fd, make_uds_frame(1, std::vector<uint8_t>(bid.begin(), bid.end())));
    /* The service sends its UDSConnectRecord; like OB-USPA's controller socket, the broker sends none back. */
    auto connect = read_record(fd);
    if (!connect || !std::holds_alternative<proto::UdsConnectRecord>(connect->record_type)) { ::close(fd); return -1; }
    return fd;
}

template<typename T>
static const T* response_of(const std::optional<proto::Msg>& msg) {
    if (!msg || !msg->body) return nullptr;
    auto* resp = std::get_if<proto::Response>(&msg->body->msg_body);
    return resp ? std::get_if<T>(&resp->resp_type) : nullptr;
}

static const proto::ErrorBody* error_of(const std::optional<proto::Msg>& msg) {
    if (!msg || !msg->body) return nullptr;
    return std::get_if<proto::ErrorBody>(&msg->body->msg_body);
}

/* ── The application under test: a two-object model held in memory ───────── */

struct TestApp {
    std::mutex mutex;
    std::map<std::string, std::map<std::string, std::string>> items = {
        {"Device.TestApp.Item.1.", {{"Name", "a"}, {"Count", "1"}}},
        {"Device.TestApp.Item.2.", {{"Name", "b"}, {"Count", "2"}}},
    };
    int next_instance = 3;
    std::vector<std::string> operated;

    void describe(UspService& service) {
        ServiceObject app;
        app.path = "Device.TestApp.";
        app.params = {{"Version", proto::ParamAccessType::ReadOnly, proto::ParamValueType::String},
                      {"Enable", proto::ParamAccessType::ReadWrite, proto::ParamValueType::Boolean}};
        app.commands = {{"Reset()", {"Hard"}, {"Status"}, false}};
        app.events = {{"Changed!", {"Reason"}}};
        service.add_object(app);

        ServiceObject item;
        item.path = "Device.TestApp.Item.{i}.";
        item.multi_instance = true;
        item.access = proto::ObjAccessType::AddDelete;
        item.params = {{"Name", proto::ParamAccessType::ReadWrite, proto::ParamValueType::String},
                       {"Count", proto::ParamAccessType::ReadOnly, proto::ParamValueType::UnsignedInt}};
        item.unique_keys = {"Name"};
        service.add_object(item);

        ServiceHandlers h;
        h.get = [this](const std::string& path) -> std::optional<std::map<std::string, std::string>> {
            std::lock_guard lk(mutex);
            if (path == "Device.TestApp.") return std::map<std::string, std::string>{{"Version", "1.0"}, {"Enable", "true"}};
            auto it = items.find(path);
            if (it == items.end()) return std::nullopt;
            return it->second;
        };
        h.instances = [this](const std::string& table) {
            std::lock_guard lk(mutex);
            std::vector<proto::CurrInstance> out;
            if (table != "Device.TestApp.Item.") return out;
            for (auto& [path, values] : items) out.push_back({path, {{"Name", values.at("Name")}}});
            return out;
        };
        h.set = [this](const std::string& path, const std::map<std::string, std::string>& params) -> std::optional<ParamErrors> {
            std::lock_guard lk(mutex);
            auto it = items.find(path);
            if (it == items.end()) return std::nullopt;
            ParamErrors errors;
            for (auto& [name, value] : params) {
                if (name == "Name") it->second["Name"] = value;
                else errors.push_back({name, 7013, "Non-writable parameter"});
            }
            return errors;
        };
        h.add = [this](const std::string& table, const std::map<std::string, std::string>& params) -> UspResult<AddResponse> {
            std::lock_guard lk(mutex);
            if (table != "Device.TestApp.Item.") return UspError::agent_rejected(7026, "Invalid path");
            std::string path = table + std::to_string(next_instance++) + ".";
            std::map<std::string, std::string> values = {{"Name", ""}, {"Count", "0"}};
            auto name = params.find("Name");
            if (name != params.end()) values["Name"] = name->second;
            items[path] = values;
            AddResponse out;
            out.instantiated_path = path;
            out.unique_keys = {{"Name", values["Name"]}};
            return out;
        };
        h.del = [this](const std::string& path) -> std::optional<UspError> {
            std::lock_guard lk(mutex);
            if (items.erase(path) == 0) return UspError::agent_rejected(7016, "Object does not exist");
            return std::nullopt;
        };
        h.operate = [this](const std::string& path, const std::string& command,
                           const std::map<std::string, std::string>& input) -> UspResult<std::map<std::string, std::string>> {
            std::lock_guard lk(mutex);
            operated.push_back(path + command);
            if (command != "Reset()") return UspError::agent_rejected(7022, "Command failure");
            std::map<std::string, std::string> out = {{"Status", input.count("Hard") ? "HardDone" : "Done"}};
            return out;
        };
        service.set_handlers(std::move(h));
    }
};

/* ── Tests ───────────────────────────────────────────────────────────────── */

static void test_start_without_broker() {
    std::puts("test_start_without_broker");

    UspService service("/nonexistent/broker.sock", "proto::svc");
    service.set_timeout(std::chrono::seconds(2));
    auto result = service.start({"Device.TestApp."});
    auto* err = std::get_if<UspError>(&result);
    CHECK(err != nullptr);
    if (err) CHECK(err->kind() == UspError::Kind::ConnectionFailed);
    CHECK(!service.running());

    auto empty = service.start({});
    CHECK(std::holds_alternative<UspError>(empty));
}

static void test_register_refused() {
    std::puts("test_register_refused");

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }

    std::string seen_password;
    std::thread broker([&]() {
        int fd = broker_accept(srv_fd, &seen_password);
        if (fd < 0) return;
        auto reg = read_msg(fd);
        if (reg && reg->header) send_msg(fd, error_msg(reg->header->msg_id, 7800, "Path already registered"));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ::close(fd);
    });

    UspService service(sock_path, "proto::svc");
    service.set_timeout(std::chrono::seconds(5));
    service.set_password("pw-1");
    auto result = service.start({"Device.TestApp."});
    broker.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());

    auto* err = std::get_if<UspError>(&result);
    CHECK(err != nullptr);
    if (err) {
        CHECK(err->kind() == UspError::Kind::AgentRejected);
        CHECK_EQ(err->code(), 7800u);
    }
    CHECK(!service.running());
    CHECK_EQ(seen_password, "pw-1");
}

static void test_full_exchange() {
    std::puts("test_full_exchange");

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }

    /* What the broker observed, checked on the main thread after join. */
    struct Seen {
        std::optional<proto::Msg> reg, gsdm, get_obj, get_params, instances, set, add, del, operate, sub_add, notify, dereg;
        std::string reg_id;
    } seen;
    std::promise<void> subscribed, notified;
    auto subscribed_f = subscribed.get_future();
    auto notified_f = notified.get_future();

    std::thread broker([&]() {
        int fd = broker_accept(srv_fd);
        if (fd < 0) { subscribed.set_value(); notified.set_value(); return; }

        seen.reg = read_msg(fd);
        if (seen.reg && seen.reg->header) {
            seen.reg_id = seen.reg->header->msg_id;
            proto::RegisterResp resp;
            proto::RegisteredPathResult ok;
            ok.requested_path = "Device.TestApp.";
            ok.oper_status = proto::RegisterOperationStatus{proto::RegisterOperationSuccess{"Device.TestApp."}};
            resp.registered_path_results = {ok};
            send_msg(fd, response_msg(seen.reg_id, resp));
        }

        proto::GetSupportedDM gsdm;
        gsdm.obj_paths = {"Device.TestApp."};
        gsdm.return_commands = gsdm.return_events = gsdm.return_params = gsdm.return_unique_key_sets = true;
        send_msg(fd, request_msg("b1", gsdm));
        seen.gsdm = read_msg(fd);

        proto::Get get_obj;
        get_obj.param_paths = {"Device.TestApp."};
        send_msg(fd, request_msg("b2", get_obj));
        seen.get_obj = read_msg(fd);

        proto::Get get_params;
        get_params.param_paths = {"Device.TestApp.Item.2.Name", "Device.Nope.", "Device.TestApp.Item."};
        send_msg(fd, request_msg("b3", get_params));
        seen.get_params = read_msg(fd);

        proto::GetInstances gi;
        gi.obj_paths = {"Device.TestApp."};
        send_msg(fd, request_msg("b4", gi));
        seen.instances = read_msg(fd);

        proto::Set set;
        proto::UpdateObject update;
        update.obj_path = "Device.TestApp.Item.1.";
        update.param_settings = {{"Name", "renamed", true}, {"Count", "9", false}};
        set.update_objs = {update};
        send_msg(fd, request_msg("b5", set));
        seen.set = read_msg(fd);

        proto::Add add;
        proto::CreateObject create;
        create.obj_path = "Device.TestApp.Item.";
        create.param_settings = {{"Name", "new", true}};
        add.create_objs = {create};
        send_msg(fd, request_msg("b6", add));
        seen.add = read_msg(fd);

        proto::Delete del;
        del.obj_paths = {"Device.TestApp.Item.2."};
        send_msg(fd, request_msg("b7", del));
        seen.del = read_msg(fd);

        proto::Operate op;
        op.command = "Device.TestApp.Reset()";
        op.send_resp = true;
        op.input_args = {{"Hard", "true"}};
        send_msg(fd, request_msg("b8", op));
        seen.operate = read_msg(fd);

        proto::Add sub_add;
        proto::CreateObject sub;
        sub.obj_path = "Device.LocalAgent.Subscription.";
        sub.param_settings = {{"ID", "sub-1", true}, {"NotifType", "ValueChange", true},
                              {"ReferenceList", "Device.TestApp.Item.1.Name", true}, {"Enable", "true", false}};
        sub_add.create_objs = {sub};
        send_msg(fd, request_msg("b9", sub_add));
        seen.sub_add = read_msg(fd);
        subscribed.set_value();

        seen.notify = read_msg(fd);
        notified.set_value();

        seen.dereg = read_msg(fd);
        if (seen.dereg && seen.dereg->header) {
            proto::DeregisterResp resp;
            proto::DeregisteredPathResult ok;
            ok.requested_path = "Device.TestApp.";
            ok.oper_status = proto::DeregisterOperationStatus{proto::DeregisterOperationSuccess{{"Device.TestApp."}}};
            resp.deregistered_path_results = {ok};
            send_msg(fd, response_msg(seen.dereg->header->msg_id, resp));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ::close(fd);
    });

    TestApp app;
    UspService service(sock_path, "proto::svc");
    service.set_timeout(std::chrono::seconds(5));
    app.describe(service);

    auto started = service.start({"Device.TestApp."});
    auto* results = std::get_if<std::vector<RegisterResult>>(&started);
    CHECK(results != nullptr);
    if (results) {
        CHECK(results->size() == 1);
        if (results->size() == 1) {
            CHECK(results->at(0).ok);
            CHECK_EQ(results->at(0).path, "Device.TestApp.");
        }
    }
    CHECK(service.running());
    CHECK_EQ(service.broker_endpoint_id(), "proto::broker");

    CHECK(subscribed_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    auto subs = service.subscriptions();
    CHECK(subs.size() == 1);
    if (subs.size() == 1) {
        CHECK_EQ(subs[0].id, "sub-1");
        CHECK_EQ(subs[0].notif_type, "ValueChange");
        CHECK_EQ(subs[0].reference_list, std::vector<std::string>{"Device.TestApp.Item.1.Name"});
    }

    service.value_changed("Device.TestApp.Item.9.Name", "ignored");   /* no subscription matches */
    service.value_changed("Device.TestApp.Item.1.Name", "renamed");
    CHECK(notified_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);

    service.stop();
    CHECK(!service.running());
    broker.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());

    /* Register */
    {
        auto* req = seen.reg && seen.reg->body ? std::get_if<proto::Request>(&seen.reg->body->msg_body) : nullptr;
        auto* reg = req ? std::get_if<proto::Register>(&req->req_type) : nullptr;
        CHECK(reg != nullptr);
        if (reg) CHECK_EQ(reg->reg_paths, std::vector<std::string>{"Device.TestApp."});
        CHECK(seen.reg && seen.reg->header && seen.reg->header->msg_type == proto::MsgType::Register);
    }
    /* GetSupportedDM */
    {
        auto* resp = response_of<proto::GetSupportedDMResp>(seen.gsdm);
        CHECK(resp != nullptr);
        CHECK(seen.gsdm && seen.gsdm->header && seen.gsdm->header->msg_id == "b1");
        if (resp && resp->req_obj_results.size() == 1) {
            const auto& objs = resp->req_obj_results[0].supported_objs;
            CHECK_EQ(objs.size(), 2u);
            if (objs.size() == 2) {
                CHECK_EQ(objs[0].supported_obj_path, "Device.TestApp.");
                CHECK(objs[0].supported_params.size() == 2);
                CHECK(objs[0].supported_commands.size() == 1 && objs[0].supported_commands[0].command_name == "Reset()");
                CHECK(objs[0].supported_events.size() == 1 && objs[0].supported_events[0].event_name == "Changed!");
                CHECK_EQ(objs[1].supported_obj_path, "Device.TestApp.Item.{i}.");
                CHECK(objs[1].is_multi_instance);
                CHECK(objs[1].access == proto::ObjAccessType::AddDelete);
                CHECK(objs[1].unique_key_sets.size() == 1 && objs[1].unique_key_sets[0].key_names == std::vector<std::string>{"Name"});
            }
        } else {
            CHECK(false);
        }
    }
    /* Get of the whole object tree */
    {
        auto* resp = response_of<proto::GetResp>(seen.get_obj);
        CHECK(resp != nullptr);
        if (resp && resp->req_path_results.size() == 1) {
            std::map<std::string, std::map<std::string, std::string>> by_path;
            for (auto& r : resp->req_path_results[0].resolved_path_results) by_path[r.resolved_path] = r.result_params;
            CHECK_EQ(by_path.size(), 3u);
            CHECK_EQ(by_path["Device.TestApp."]["Version"], "1.0");
            CHECK_EQ(by_path["Device.TestApp.Item.1."]["Name"], "a");
            CHECK_EQ(by_path["Device.TestApp.Item.2."]["Count"], "2");
        } else {
            CHECK(false);
        }
    }
    /* Get of a parameter, an unknown path and a table */
    {
        auto* resp = response_of<proto::GetResp>(seen.get_params);
        CHECK(resp != nullptr);
        if (resp && resp->req_path_results.size() == 3) {
            const auto& param = resp->req_path_results[0];
            CHECK_EQ(param.err_code, 0u);
            CHECK(param.resolved_path_results.size() == 1);
            if (param.resolved_path_results.size() == 1) {
                CHECK_EQ(param.resolved_path_results[0].resolved_path, "Device.TestApp.Item.2.");
                CHECK_EQ(param.resolved_path_results[0].result_params.at("Name"), "b");
            }
            CHECK_EQ(resp->req_path_results[1].err_code, 7026u);
            CHECK_EQ(resp->req_path_results[2].resolved_path_results.size(), 2u);
        } else {
            CHECK(false);
        }
    }
    /* GetInstances */
    {
        auto* resp = response_of<proto::GetInstancesResp>(seen.instances);
        CHECK(resp != nullptr);
        if (resp && resp->req_path_results.size() == 1) {
            const auto& insts = resp->req_path_results[0].curr_insts;
            CHECK_EQ(insts.size(), 2u);
            if (insts.size() == 2) {
                CHECK_EQ(insts[0].instantiated_obj_path, "Device.TestApp.Item.1.");
                CHECK_EQ(insts[1].unique_keys.at("Name"), "b");
            }
        } else {
            CHECK(false);
        }
    }
    /* Set: Name applied, Count refused but not required */
    {
        auto* resp = response_of<proto::SetResp>(seen.set);
        CHECK(resp != nullptr);
        if (resp && resp->updated_obj_results.size() == 1 && resp->updated_obj_results[0].oper_status) {
            auto* ok = std::get_if<proto::OperationSuccess>(&resp->updated_obj_results[0].oper_status->oper_status);
            CHECK(ok != nullptr);
            if (ok && ok->updated_inst_results.size() == 1) {
                CHECK_EQ(ok->updated_inst_results[0].affected_path, "Device.TestApp.Item.1.");
                CHECK_EQ(ok->updated_inst_results[0].updated_params.at("Name"), "renamed");
                CHECK(ok->updated_inst_results[0].param_errs.size() == 1 && ok->updated_inst_results[0].param_errs[0].param == "Count");
            } else {
                CHECK(false);
            }
        } else {
            CHECK(false);
        }
        std::lock_guard lk(app.mutex);
        CHECK_EQ(app.items["Device.TestApp.Item.1."]["Name"], "renamed");
    }
    /* Add */
    {
        auto* resp = response_of<proto::AddResp>(seen.add);
        CHECK(resp != nullptr);
        if (resp && resp->created_obj_results.size() == 1 && resp->created_obj_results[0].oper_status) {
            auto* ok = std::get_if<proto::AddOperationSuccess>(&resp->created_obj_results[0].oper_status->oper_status);
            CHECK(ok != nullptr);
            if (ok) {
                CHECK_EQ(ok->instantiated_path, "Device.TestApp.Item.3.");
                CHECK_EQ(ok->unique_keys.at("Name"), "new");
            }
        } else {
            CHECK(false);
        }
    }
    /* Delete */
    {
        auto* resp = response_of<proto::DeleteResp>(seen.del);
        CHECK(resp != nullptr);
        if (resp && resp->deleted_obj_results.size() == 1 && resp->deleted_obj_results[0].oper_status) {
            auto* ok = std::get_if<proto::DeleteOperationSuccess>(&resp->deleted_obj_results[0].oper_status->oper_status);
            CHECK(ok != nullptr);
            if (ok) CHECK_EQ(ok->affected_paths, std::vector<std::string>{"Device.TestApp.Item.2."});
        } else {
            CHECK(false);
        }
        std::lock_guard lk(app.mutex);
        CHECK(app.items.count("Device.TestApp.Item.2.") == 0);
    }
    /* Operate */
    {
        auto* resp = response_of<proto::OperateResp>(seen.operate);
        CHECK(resp != nullptr);
        if (resp && resp->operation_results.size() == 1) {
            CHECK_EQ(resp->operation_results[0].executed_command, "Device.TestApp.Reset()");
            auto* args = std::get_if<proto::OutputArgs>(&resp->operation_results[0].operation_resp);
            CHECK(args != nullptr);
            if (args) CHECK_EQ(args->output_args.at("Status"), "HardDone");
        } else {
            CHECK(false);
        }
        std::lock_guard lk(app.mutex);
        CHECK_EQ(app.operated, std::vector<std::string>{"Device.TestApp.Reset()"});
    }
    /* Subscription Add and the Notify it produced */
    {
        auto* resp = response_of<proto::AddResp>(seen.sub_add);
        CHECK(resp != nullptr);
        if (resp && resp->created_obj_results.size() == 1 && resp->created_obj_results[0].oper_status) {
            auto* ok = std::get_if<proto::AddOperationSuccess>(&resp->created_obj_results[0].oper_status->oper_status);
            CHECK(ok != nullptr);
            if (ok) CHECK_EQ(ok->instantiated_path, "Device.LocalAgent.Subscription.1.");
        }
        auto* req = seen.notify && seen.notify->body ? std::get_if<proto::Request>(&seen.notify->body->msg_body) : nullptr;
        auto* notify = req ? std::get_if<proto::Notify>(&req->req_type) : nullptr;
        CHECK(notify != nullptr);
        if (notify) {
            CHECK_EQ(notify->subscription_id, "sub-1");
            auto* vc = std::get_if<proto::ValueChange>(&notify->notification);
            CHECK(vc != nullptr);
            if (vc) {
                CHECK_EQ(vc->param_path, "Device.TestApp.Item.1.Name");
                CHECK_EQ(vc->param_value, "renamed");
            }
        }
    }
    /* Deregister on stop */
    {
        auto* req = seen.dereg && seen.dereg->body ? std::get_if<proto::Request>(&seen.dereg->body->msg_body) : nullptr;
        auto* dereg = req ? std::get_if<proto::Deregister>(&req->req_type) : nullptr;
        CHECK(dereg != nullptr);
        if (dereg) CHECK_EQ(dereg->paths, (std::vector<std::string>{"Device.TestApp.", "Device.TestApp.Item.{i}."}));
    }
}

/* Requests the service cannot honour get a USP error, never silence. */
static void test_error_replies() {
    std::puts("test_error_replies");

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }

    struct Seen { std::optional<proto::Msg> unsupported, bad_set, bad_operate, bad_delete, bad_add, sub_get, sub_del; } seen;
    std::promise<void> done;
    auto done_f = done.get_future();

    std::thread broker([&]() {
        int fd = broker_accept(srv_fd);
        if (fd < 0) { done.set_value(); return; }
        auto reg = read_msg(fd);
        if (reg && reg->header) {
            proto::RegisterResp resp;
            proto::RegisteredPathResult ok;
            ok.requested_path = "Device.TestApp.";
            ok.oper_status = proto::RegisterOperationStatus{proto::RegisterOperationSuccess{"Device.TestApp."}};
            resp.registered_path_results = {ok};
            send_msg(fd, response_msg(reg->header->msg_id, resp));
        }

        send_msg(fd, request_msg("e1", proto::GetSupportedProtocol{"1.5"}));
        seen.unsupported = read_msg(fd);

        proto::Set set;
        proto::UpdateObject update;
        update.obj_path = "Device.Other.1.";
        update.param_settings = {{"Name", "x", true}};
        set.update_objs = {update};
        send_msg(fd, request_msg("e2", set));
        seen.bad_set = read_msg(fd);

        proto::Operate op;
        op.command = "Device.Other.Reset()";
        send_msg(fd, request_msg("e3", op));
        seen.bad_operate = read_msg(fd);

        proto::Delete del;
        del.allow_partial = true;
        del.obj_paths = {"Device.TestApp.Item.7."};
        send_msg(fd, request_msg("e4", del));
        seen.bad_delete = read_msg(fd);

        proto::Add add;
        proto::CreateObject create;
        create.obj_path = "Device.TestApp.";          /* not a table */
        add.create_objs = {create};
        send_msg(fd, request_msg("e5", add));
        seen.bad_add = read_msg(fd);

        proto::Get sub_get;
        sub_get.param_paths = {"Device.LocalAgent.Subscription."};
        send_msg(fd, request_msg("e6", sub_get));
        seen.sub_get = read_msg(fd);

        proto::Delete sub_del;
        sub_del.obj_paths = {"Device.LocalAgent.Subscription.4."};
        send_msg(fd, request_msg("e7", sub_del));
        seen.sub_del = read_msg(fd);

        done.set_value();
        read_msg(fd);                                  /* Deregister on stop; the reply is not needed */
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ::close(fd);
    });

    TestApp app;
    UspService service(sock_path, "proto::svc");
    service.set_timeout(std::chrono::seconds(5));
    app.describe(service);
    auto started = service.start({"Device.TestApp."});
    CHECK(std::holds_alternative<std::vector<RegisterResult>>(started));
    CHECK(done_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    service.stop();
    broker.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());

    auto* e1 = error_of(seen.unsupported);
    CHECK(e1 != nullptr && e1->err_code == 7001);
    CHECK(seen.unsupported && seen.unsupported->header && seen.unsupported->header->msg_id == "e1");
    auto* e2 = error_of(seen.bad_set);
    CHECK(e2 != nullptr && e2->err_code == 7026);
    auto* e3 = error_of(seen.bad_operate);
    CHECK(e3 != nullptr && e3->err_code == 7026);
    auto* d4 = response_of<proto::DeleteResp>(seen.bad_delete);     /* allow_partial: a failure inside the response */
    CHECK(d4 != nullptr);
    if (d4 && d4->deleted_obj_results.size() == 1 && d4->deleted_obj_results[0].oper_status) {
        auto* f = std::get_if<proto::DeleteOperationFailure>(&d4->deleted_obj_results[0].oper_status->oper_status);
        CHECK(f != nullptr && f->err_code == 7016);
    } else {
        CHECK(false);
    }
    auto* e5 = error_of(seen.bad_add);
    CHECK(e5 != nullptr && e5->err_code == 7026);
    auto* g6 = response_of<proto::GetResp>(seen.sub_get);           /* empty subscription table reads back empty */
    CHECK(g6 != nullptr && g6->req_path_results.size() == 1 && g6->req_path_results[0].resolved_path_results.empty());
    auto* e7 = error_of(seen.sub_del);
    CHECK(e7 != nullptr && e7->err_code == 7026);
}

/* Destroying a running service must stop and join its worker at once, even with the broker still connected. */
static void test_destroy_while_connected() {
    std::puts("test_destroy_while_connected");

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }

    std::promise<void> gone;
    auto gone_f = gone.get_future();
    std::thread broker([&]() {
        int fd = broker_accept(srv_fd);
        if (fd < 0) return;
        auto reg = read_msg(fd);
        if (reg && reg->header) {
            proto::RegisterResp resp;
            proto::RegisteredPathResult ok;
            ok.requested_path = "Device.TestApp.";
            ok.oper_status = proto::RegisterOperationStatus{proto::RegisterOperationSuccess{"Device.TestApp."}};
            resp.registered_path_results = {ok};
            send_msg(fd, response_msg(reg->header->msg_id, resp));
        }
        read_msg(fd);                                  /* Deregister from the destructor */
        gone_f.wait();
        ::close(fd);
    });

    auto t0 = std::chrono::steady_clock::now();
    {
        TestApp app;
        UspService service(sock_path, "proto::svc");
        service.set_timeout(std::chrono::seconds(2));
        app.describe(service);
        CHECK(std::holds_alternative<std::vector<RegisterResult>>(service.start({"Device.TestApp."})));
    }                                                  /* destroyed while connected; the Deregister gets no reply */
    long ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ms < 4000);
    gone.set_value();
    broker.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}



/* The broker drops the first connection right after the handshake; start() must try once more and succeed. */
static void test_start_retries_after_dropped_connection() {
    std::puts("test_start_retries_after_dropped_connection");

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }

    int connections = 0;
    std::thread broker([&]() {
        for (int conn = 0; conn < 2; ++conn) {
            int fd = ::accept(srv_fd, nullptr, nullptr);
            if (fd < 0) return;
            ++connections;
            suppress_sigpipe(fd);
            std::vector<std::pair<uint8_t, std::vector<uint8_t>>> tlvs;
            read_tlvs(fd, tlvs);
            std::string bid = "proto::broker";
            write_frame(fd, make_uds_frame(1, std::vector<uint8_t>(bid.begin(), bid.end())));
            if (conn == 0) { ::close(fd); continue; }             /* dropped before the Register can be answered */
            read_record(fd);                                       /* UDSConnectRecord */
            auto reg = read_msg(fd);
            if (reg && reg->header) {
                proto::RegisterResp resp;
                proto::RegisteredPathResult ok;
                ok.requested_path = "Device.TestApp.";
                ok.oper_status = proto::RegisterOperationStatus{proto::RegisterOperationSuccess{"Device.TestApp."}};
                resp.registered_path_results = {ok};
                send_msg(fd, response_msg(reg->header->msg_id, resp));
            }
            read_msg(fd);                                          /* Deregister on stop */
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            ::close(fd);
        }
    });

    TestApp app;
    UspService service(sock_path, "proto::svc");
    service.set_timeout(std::chrono::seconds(3));
    app.describe(service);
    auto started = service.start({"Device.TestApp."});
    auto* results = std::get_if<std::vector<RegisterResult>>(&started);
    CHECK(results != nullptr);
    if (!results) {
        std::fprintf(stderr, "  start: %s\n", std::get<UspError>(started).to_string().c_str());
    }
    CHECK(service.running());
    service.stop();
    broker.join();
    CHECK_EQ(connections, 2);
    ::close(srv_fd);
    ::unlink(sock_path.c_str());
}

/* ── The same application through the C API, with C callbacks ───────────── */

struct CStore {
    std::mutex mutex;
    std::map<std::string, std::map<std::string, std::string>> items = {
        {"Device.TestApp.Item.1.", {{"Name", "a"}, {"Count", "1"}}},
        {"Device.TestApp.Item.2.", {{"Name", "b"}, {"Count", "2"}}},
    };
    int next_instance = 3;
    std::vector<std::string> operated;
};

static int write_text(char* out, size_t len, const std::string& text) {
    if (text.size() + 1 > len) return USP_ERR_BUFFER_TOO_SMALL;
    std::memcpy(out, text.data(), text.size() + 1);
    return USP_OK;
}

static int c_get(void* ud, const char* path, char* out, size_t len) {
    auto* s = static_cast<CStore*>(ud);
    std::lock_guard lk(s->mutex);
    if (std::string(path) == "Device.TestApp.") return write_text(out, len, "PARAM\tVersion\t1.0\nPARAM\tEnable\ttrue\n");
    auto it = s->items.find(path);
    if (it == s->items.end()) return USP_ERR_NOT_FOUND;
    std::string text;
    for (auto& [k, v] : it->second) text += "PARAM\t" + k + "\t" + v + "\n";
    return write_text(out, len, text);
}

static int c_instances(void* ud, const char* table, char* out, size_t len) {
    auto* s = static_cast<CStore*>(ud);
    std::lock_guard lk(s->mutex);
    if (std::string(table) != "Device.TestApp.Item.") return write_text(out, len, "");
    std::string text;
    for (auto& [path, values] : s->items)
        text += "INSTANCE\t" + path + "\nKEY\t" + path + "\tName\t" + values.at("Name") + "\n";
    return write_text(out, len, text);
}

static int c_set(void* ud, const char* path, const char* const* names, const char* const* values, size_t n,
                 char* out, size_t len) {
    auto* s = static_cast<CStore*>(ud);
    std::lock_guard lk(s->mutex);
    auto it = s->items.find(path);
    if (it == s->items.end()) return USP_ERR_NOT_FOUND;
    std::string errors;
    for (size_t i = 0; i < n; ++i) {
        if (std::string(names[i]) == "Name") it->second["Name"] = values[i];
        else errors += std::string("ERROR\t") + names[i] + "\t7013\tNon-writable parameter\n";
    }
    return write_text(out, len, errors);
}

static int c_add(void* ud, const char* table, const char* const* names, const char* const* values, size_t n,
                 char* out, size_t len, UspServiceError* err) {
    auto* s = static_cast<CStore*>(ud);
    std::lock_guard lk(s->mutex);
    if (std::string(table) != "Device.TestApp.Item.") {
        err->code = 7026;
        std::snprintf(err->msg, sizeof err->msg, "Invalid path");
        return USP_ERR_USP;
    }
    std::string path = std::string(table) + std::to_string(s->next_instance++) + ".";
    std::map<std::string, std::string> item = {{"Name", ""}, {"Count", "0"}};
    for (size_t i = 0; i < n; ++i) if (std::string(names[i]) == "Name") item["Name"] = values[i];
    s->items[path] = item;
    return write_text(out, len, "INSTANCE\t" + path + "\nKEY\tName\t" + item["Name"] + "\n");
}

static int c_del(void* ud, const char* path, UspServiceError* err) {
    auto* s = static_cast<CStore*>(ud);
    std::lock_guard lk(s->mutex);
    if (s->items.erase(path) == 0) {
        err->code = 7016;
        std::snprintf(err->msg, sizeof err->msg, "Object does not exist");
        return USP_ERR_USP;
    }
    return USP_OK;
}

static int c_operate(void* ud, const char* path, const char* command, const char* const* names,
                     const char* const*, size_t n, char* out, size_t len, UspServiceError* err) {
    auto* s = static_cast<CStore*>(ud);
    std::lock_guard lk(s->mutex);
    s->operated.push_back(std::string(path) + command);
    if (std::string(command) != "Reset()") {
        err->code = 7022;
        std::snprintf(err->msg, sizeof err->msg, "Command failure");
        return USP_ERR_USP;
    }
    bool hard = false;
    for (size_t i = 0; i < n; ++i) if (std::string(names[i]) == "Hard") hard = true;
    return write_text(out, len, std::string("OUTPUT\tStatus\t") + (hard ? "HardDone" : "Done") + "\n");
}

static void test_c_api_guards() {
    std::puts("test_c_api_guards");

    CHECK(usp_service_new(nullptr, "proto::svc", "", 1) == nullptr);
    CHECK(usp_service_new("/tmp/x.sock", nullptr, "", 1) == nullptr);
    CHECK_EQ(usp_service_running(nullptr), 0);
    char buf[64];
    CHECK_EQ(usp_service_last_error(nullptr, buf, sizeof buf), USP_ERR_NULL_POINTER);
    CHECK_EQ(usp_service_stop(nullptr), USP_ERR_NULL_POINTER);

    UspServiceHandle* h = usp_service_new("/nonexistent/broker.sock", "proto::svc", "", 2);
    CHECK(h != nullptr);
    if (!h) return;
    CHECK_EQ(usp_service_add_param(h, "Device.Missing.", "X", USP_PARAM_ACCESS_READ_ONLY, USP_PARAM_TYPE_STRING), USP_ERR_NOT_FOUND);
    CHECK_EQ(usp_service_add_object(h, "Device.TestApp.", 0, 99, nullptr), USP_ERR_INVALID_ARGUMENT);
    CHECK_EQ(usp_service_add_object(h, "Device.TestApp.", 0, USP_OBJ_ACCESS_READ_ONLY, nullptr), USP_OK);
    CHECK_EQ(usp_service_add_param(h, "Device.TestApp.", "X", 7, USP_PARAM_TYPE_STRING), USP_ERR_INVALID_ARGUMENT);
    CHECK_EQ(usp_service_add_command(h, "Device.Missing.", "Reset()", nullptr, nullptr, 0), USP_ERR_NOT_FOUND);
    CHECK_EQ(usp_service_add_event(h, "Device.Missing.", "Changed!", nullptr), USP_ERR_NOT_FOUND);
    CHECK_EQ(usp_service_set_callbacks(h, nullptr), USP_ERR_NULL_POINTER);
    CHECK_EQ(usp_service_start(h, nullptr, 1, 0, buf, sizeof buf), USP_ERR_NULL_POINTER);
    CHECK_EQ(usp_service_start(h, nullptr, 0, 0, buf, sizeof buf), USP_ERR_INVALID_ARGUMENT);
    const char* roots[] = {"Device.TestApp."};
    CHECK_EQ(usp_service_start(h, roots, 1, 0, buf, sizeof buf), USP_ERR_USP);
    char err[256] = {0};
    usp_service_last_error(h, err, sizeof err);
    CHECK(std::string(err).find("connection failed") != std::string::npos);
    CHECK_EQ(usp_service_running(h), 0);
    CHECK_EQ(usp_service_value_changed(h, nullptr, "x"), USP_ERR_NULL_POINTER);
    CHECK_EQ(usp_service_value_changed(h, "Device.TestApp.X", "x"), USP_OK);   /* not running: nothing to send */
    usp_service_free(h);
    usp_service_free(nullptr);
}

static void test_c_api_exchange() {
    std::puts("test_c_api_exchange");

    std::string sock_path = make_tmp_socket_path();
    int srv_fd = listen_unix(sock_path);
    if (srv_fd < 0) { std::puts("  SKIP: cannot bind/listen"); return; }

    struct Seen { std::optional<proto::Msg> gsdm, get_obj, set, add, del, operate, sub_add, notify, dereg; } seen;
    std::promise<void> subscribed, notified;
    auto subscribed_f = subscribed.get_future();
    auto notified_f = notified.get_future();

    std::thread broker([&]() {
        int fd = broker_accept(srv_fd);
        if (fd < 0) { subscribed.set_value(); notified.set_value(); return; }
        auto reg = read_msg(fd);
        if (reg && reg->header) {
            proto::RegisterResp resp;
            proto::RegisteredPathResult ok;
            ok.requested_path = "Device.TestApp.";
            ok.oper_status = proto::RegisterOperationStatus{proto::RegisterOperationSuccess{"Device.TestApp."}};
            resp.registered_path_results = {ok};
            send_msg(fd, response_msg(reg->header->msg_id, resp));
        }
        proto::GetSupportedDM gsdm;
        gsdm.obj_paths = {"Device.TestApp."};
        gsdm.return_commands = gsdm.return_events = gsdm.return_params = gsdm.return_unique_key_sets = true;
        send_msg(fd, request_msg("c1", gsdm));
        seen.gsdm = read_msg(fd);

        proto::Get get_obj;
        get_obj.param_paths = {"Device.TestApp."};
        send_msg(fd, request_msg("c2", get_obj));
        seen.get_obj = read_msg(fd);

        proto::Set set;
        proto::UpdateObject update;
        update.obj_path = "Device.TestApp.Item.1.";
        update.param_settings = {{"Name", "renamed", true}, {"Count", "9", false}};
        set.update_objs = {update};
        send_msg(fd, request_msg("c3", set));
        seen.set = read_msg(fd);

        proto::Add add;
        proto::CreateObject create;
        create.obj_path = "Device.TestApp.Item.";
        create.param_settings = {{"Name", "new", true}};
        add.create_objs = {create};
        send_msg(fd, request_msg("c4", add));
        seen.add = read_msg(fd);

        proto::Delete del;
        del.obj_paths = {"Device.TestApp.Item.2."};
        send_msg(fd, request_msg("c5", del));
        seen.del = read_msg(fd);

        proto::Operate op;
        op.command = "Device.TestApp.Reset()";
        op.send_resp = true;
        op.input_args = {{"Hard", "true"}};
        send_msg(fd, request_msg("c6", op));
        seen.operate = read_msg(fd);

        proto::Add sub_add;
        proto::CreateObject sub;
        sub.obj_path = "Device.LocalAgent.Subscription.";
        sub.param_settings = {{"ID", "sub-c", true}, {"NotifType", "ObjectCreation", true},
                              {"ReferenceList", "Device.TestApp.Item.", true}};
        sub_add.create_objs = {sub};
        send_msg(fd, request_msg("c7", sub_add));
        seen.sub_add = read_msg(fd);
        subscribed.set_value();

        seen.notify = read_msg(fd);
        notified.set_value();

        seen.dereg = read_msg(fd);
        if (seen.dereg && seen.dereg->header) {
            proto::DeregisterResp resp;
            proto::DeregisteredPathResult ok;
            ok.requested_path = "Device.TestApp.";
            ok.oper_status = proto::DeregisterOperationStatus{proto::DeregisterOperationSuccess{{"Device.TestApp."}}};
            resp.deregistered_path_results = {ok};
            send_msg(fd, response_msg(seen.dereg->header->msg_id, resp));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ::close(fd);
    });

    CStore store;
    UspServiceHandle* h = usp_service_new(sock_path.c_str(), "proto::svc", "", 5);
    CHECK(h != nullptr);
    if (h) {
        CHECK_EQ(usp_service_add_object(h, "Device.TestApp.", 0, USP_OBJ_ACCESS_READ_ONLY, nullptr), USP_OK);
        CHECK_EQ(usp_service_add_param(h, "Device.TestApp.", "Version", USP_PARAM_ACCESS_READ_ONLY, USP_PARAM_TYPE_STRING), USP_OK);
        CHECK_EQ(usp_service_add_param(h, "Device.TestApp.", "Enable", USP_PARAM_ACCESS_READ_WRITE, USP_PARAM_TYPE_BOOLEAN), USP_OK);
        CHECK_EQ(usp_service_add_command(h, "Device.TestApp.", "Reset()", "Hard", "Status", 0), USP_OK);
        CHECK_EQ(usp_service_add_event(h, "Device.TestApp.", "Changed!", "Reason"), USP_OK);
        CHECK_EQ(usp_service_add_object(h, "Device.TestApp.Item.{i}.", 1, USP_OBJ_ACCESS_ADD_DELETE, "Name"), USP_OK);
        CHECK_EQ(usp_service_add_param(h, "Device.TestApp.Item.{i}.", "Name", USP_PARAM_ACCESS_READ_WRITE, USP_PARAM_TYPE_STRING), USP_OK);
        CHECK_EQ(usp_service_add_param(h, "Device.TestApp.Item.{i}.", "Count", USP_PARAM_ACCESS_READ_ONLY, USP_PARAM_TYPE_UNSIGNED_INT), USP_OK);

        UspServiceCallbacks cb{};
        cb.user_data = &store;
        cb.get = c_get; cb.instances = c_instances; cb.set = c_set; cb.add = c_add; cb.del = c_del; cb.operate = c_operate;
        CHECK_EQ(usp_service_set_callbacks(h, &cb), USP_OK);

        char result[256] = {0};
        const char* roots[] = {"Device.TestApp."};
        CHECK_EQ(usp_service_start(h, roots, 1, 0, result, sizeof result), USP_OK);
        CHECK_EQ(std::string(result), "REGISTERED\tDevice.TestApp.\n");
        CHECK_EQ(usp_service_running(h), 1);
        char broker_id[64] = {0};
        CHECK_EQ(usp_service_broker_endpoint_id(h, broker_id, sizeof broker_id), USP_OK);
        CHECK_EQ(std::string(broker_id), "proto::broker");

        CHECK(subscribed_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
        const char* key_names[] = {"Name"};
        const char* key_values[] = {"new"};
        CHECK_EQ(usp_service_object_created(h, "Device.TestApp.Item.3.", key_names, key_values, 1), USP_OK);
        CHECK(notified_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);

        CHECK_EQ(usp_service_stop(h), USP_OK);
        CHECK_EQ(usp_service_running(h), 0);
        usp_service_free(h);
    }
    broker.join();
    ::close(srv_fd);
    ::unlink(sock_path.c_str());

    auto* gsdm = response_of<proto::GetSupportedDMResp>(seen.gsdm);
    CHECK(gsdm != nullptr);
    if (gsdm && gsdm->req_obj_results.size() == 1 && gsdm->req_obj_results[0].supported_objs.size() == 2) {
        const auto& objs = gsdm->req_obj_results[0].supported_objs;
        CHECK(objs[0].supported_params.size() == 2 && objs[0].supported_params[1].value_type == proto::ParamValueType::Boolean);
        CHECK(objs[0].supported_commands.size() == 1 && objs[0].supported_commands[0].input_arg_names == std::vector<std::string>{"Hard"});
        CHECK(objs[0].supported_events.size() == 1);
        CHECK(objs[1].is_multi_instance && objs[1].unique_key_sets.size() == 1);
    } else {
        CHECK(false);
    }
    auto* get = response_of<proto::GetResp>(seen.get_obj);
    CHECK(get != nullptr);
    if (get && get->req_path_results.size() == 1) {
        std::map<std::string, std::map<std::string, std::string>> by_path;
        for (auto& r : get->req_path_results[0].resolved_path_results) by_path[r.resolved_path] = r.result_params;
        CHECK_EQ(by_path.size(), 3u);
        CHECK_EQ(by_path["Device.TestApp."]["Version"], "1.0");
        CHECK_EQ(by_path["Device.TestApp.Item.2."]["Name"], "b");
    }
    auto* set = response_of<proto::SetResp>(seen.set);
    CHECK(set != nullptr);
    if (set && set->updated_obj_results.size() == 1 && set->updated_obj_results[0].oper_status) {
        auto* ok = std::get_if<proto::OperationSuccess>(&set->updated_obj_results[0].oper_status->oper_status);
        CHECK(ok != nullptr && ok->updated_inst_results.size() == 1);
        if (ok && ok->updated_inst_results.size() == 1) {
            CHECK_EQ(ok->updated_inst_results[0].updated_params.at("Name"), "renamed");
            CHECK(ok->updated_inst_results[0].param_errs.size() == 1 && ok->updated_inst_results[0].param_errs[0].err_code == 7013);
        }
    }
    auto* add = response_of<proto::AddResp>(seen.add);
    CHECK(add != nullptr);
    if (add && add->created_obj_results.size() == 1 && add->created_obj_results[0].oper_status) {
        auto* ok = std::get_if<proto::AddOperationSuccess>(&add->created_obj_results[0].oper_status->oper_status);
        CHECK(ok != nullptr);
        if (ok) {
            CHECK_EQ(ok->instantiated_path, "Device.TestApp.Item.3.");
            CHECK_EQ(ok->unique_keys.at("Name"), "new");
        }
    }
    auto* del = response_of<proto::DeleteResp>(seen.del);
    CHECK(del != nullptr);
    if (del && del->deleted_obj_results.size() == 1 && del->deleted_obj_results[0].oper_status)
        CHECK(std::get_if<proto::DeleteOperationSuccess>(&del->deleted_obj_results[0].oper_status->oper_status) != nullptr);
    auto* op = response_of<proto::OperateResp>(seen.operate);
    CHECK(op != nullptr);
    if (op && op->operation_results.size() == 1) {
        auto* args = std::get_if<proto::OutputArgs>(&op->operation_results[0].operation_resp);
        CHECK(args != nullptr);
        if (args) CHECK_EQ(args->output_args.at("Status"), "HardDone");
    }
    {
        std::lock_guard lk(store.mutex);
        CHECK_EQ(store.items["Device.TestApp.Item.1."]["Name"], "renamed");
        CHECK(store.items.count("Device.TestApp.Item.2.") == 0);
        CHECK(store.items.count("Device.TestApp.Item.3.") == 1);
        CHECK_EQ(store.operated, std::vector<std::string>{"Device.TestApp.Reset()"});
    }
    auto* req = seen.notify && seen.notify->body ? std::get_if<proto::Request>(&seen.notify->body->msg_body) : nullptr;
    auto* notify = req ? std::get_if<proto::Notify>(&req->req_type) : nullptr;
    CHECK(notify != nullptr);
    if (notify) {
        CHECK_EQ(notify->subscription_id, "sub-c");
        auto* oc = std::get_if<proto::ObjectCreation>(&notify->notification);
        CHECK(oc != nullptr);
        if (oc) {
            CHECK_EQ(oc->obj_path, "Device.TestApp.Item.3.");
            CHECK_EQ(oc->unique_keys.at("Name"), "new");
        }
    }
    auto* dreq = seen.dereg && seen.dereg->body ? std::get_if<proto::Request>(&seen.dereg->body->msg_body) : nullptr;
    CHECK(dreq != nullptr && std::get_if<proto::Deregister>(&dreq->req_type) != nullptr);
}

int main() {
    ::signal(SIGPIPE, SIG_IGN);

    test_start_without_broker();
    test_register_refused();
    test_full_exchange();
    test_error_replies();
    test_destroy_while_connected();
    test_start_retries_after_dropped_connection();
    test_c_api_guards();
    test_c_api_exchange();

    std::printf("\n%s: %d passed, %d failed\n", (g_fail == 0) ? "PASS" : "FAIL", g_pass, g_fail);
    return g_fail != 0 ? 1 : 0;
}
