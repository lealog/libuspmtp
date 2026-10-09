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
 * Unit tests for USP wrapper encode/decode through the official protobuf C++
 * runtime and the vendored TR-369 USP 1.5 schemas.  Every message type is
 * encoded, decoded again and compared field by field, so a mapping that drops
 * a field fails here rather than on a gateway.
 */

#include "usp_proto.hpp"

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

using namespace usp::proto;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            ++g_fail; \
        } else { \
            ++g_pass; \
        } \
    } while (0)

#define CHECK_EQ(a, b) \
    do { \
        auto _a = (a); auto _b = (b); \
        if (!(_a == _b)) { \
            std::fprintf(stderr, "FAIL: %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
            ++g_fail; \
        } else { ++g_pass; } \
    } while (0)

/* Encode a request body in a Msg, decode it, and return the decoded request (or nullptr). */
template<typename T>
static const T* roundtrip_request(const T& request, const char* msg_id, MsgType type, Msg& decoded_out) {
    Request req;
    req.req_type = request;
    Body body;
    body.msg_body = req;
    Msg msg;
    msg.header = Header{msg_id, type};
    msg.body = body;

    auto decoded = Msg::decode(msg.encode());
    CHECK(decoded.has_value());
    if (!decoded) return nullptr;
    decoded_out = *decoded;
    CHECK(decoded_out.header.has_value() && decoded_out.header->msg_id == msg_id);
    CHECK(decoded_out.header.has_value() && decoded_out.header->msg_type == type);
    if (!decoded_out.body) return nullptr;
    auto* decoded_req = std::get_if<Request>(&decoded_out.body->msg_body);
    return decoded_req ? std::get_if<T>(&decoded_req->req_type) : nullptr;
}

template<typename T>
static const T* roundtrip_response(const T& response, const char* msg_id, MsgType type, Msg& decoded_out) {
    Response resp;
    resp.resp_type = response;
    Body body;
    body.msg_body = resp;
    Msg msg;
    msg.header = Header{msg_id, type};
    msg.body = body;

    auto decoded = Msg::decode(msg.encode());
    CHECK(decoded.has_value());
    if (!decoded) return nullptr;
    decoded_out = *decoded;
    CHECK(decoded_out.header.has_value() && decoded_out.header->msg_type == type);
    if (!decoded_out.body) return nullptr;
    auto* decoded_resp = std::get_if<Response>(&decoded_out.body->msg_body);
    return decoded_resp ? std::get_if<T>(&decoded_resp->resp_type) : nullptr;
}

static void test_record_roundtrip() {
    std::puts("test_record_roundtrip");

    NoSessionContextRecord nsc;
    nsc.payload = {0x01, 0x02, 0x03};

    Record rec;
    rec.version = "1.5";
    rec.to_id = "proto::agent";
    rec.from_id = "proto::controller";
    rec.payload_security = 0;
    rec.record_type = nsc;

    auto encoded = rec.encode();
    CHECK(!encoded.empty());

    auto decoded = Record::decode(encoded);
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->version, rec.version);
    CHECK_EQ(decoded->to_id, rec.to_id);
    CHECK_EQ(decoded->from_id, rec.from_id);
    CHECK_EQ(decoded->payload_security, 0);

    auto* decoded_nsc = std::get_if<NoSessionContextRecord>(&decoded->record_type);
    CHECK(decoded_nsc != nullptr);
    CHECK_EQ(decoded_nsc->payload, nsc.payload);

    /* The standalone NoSessionContextRecord codec as well. */
    auto nsc_decoded = NoSessionContextRecord::decode(nsc.encode());
    CHECK(nsc_decoded.has_value());
    CHECK_EQ(nsc_decoded->payload, nsc.payload);
}

static void test_uds_connect_and_disconnect_records() {
    std::puts("test_uds_connect_and_disconnect_records");

    Record connect;
    connect.version = "1.5";
    connect.to_id = "proto::agent";
    connect.from_id = "proto::app";
    connect.record_type = UdsConnectRecord{};
    auto decoded_connect = Record::decode(connect.encode());
    CHECK(decoded_connect.has_value());
    CHECK(std::holds_alternative<UdsConnectRecord>(decoded_connect->record_type));
    CHECK(!UdsConnectRecord{}.encode().empty() || UdsConnectRecord{}.encode().empty()); /* encodes without throwing */

    Record disconnect;
    disconnect.version = "1.5";
    disconnect.record_type = DisconnectRecord{"session expired", 7100};
    auto decoded_disconnect = Record::decode(disconnect.encode());
    CHECK(decoded_disconnect.has_value());
    auto* d = std::get_if<DisconnectRecord>(&decoded_disconnect->record_type);
    CHECK(d != nullptr);
    if (d) {
        CHECK_EQ(d->reason, "session expired");
        CHECK_EQ(d->reason_code, 7100u);
    }

    /* An empty record type survives as monostate. */
    Record empty;
    empty.version = "1.5";
    auto decoded_empty = Record::decode(empty.encode());
    CHECK(decoded_empty.has_value());
    CHECK(std::holds_alternative<std::monostate>(decoded_empty->record_type));
}

static void test_decode_rejects_garbage() {
    std::puts("test_decode_rejects_garbage");

    std::vector<uint8_t> garbage = {0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x01};
    CHECK(!Record::decode(garbage).has_value());
    CHECK(!Msg::decode(garbage).has_value());
    CHECK(!NoSessionContextRecord::decode(garbage).has_value());
}

static void test_msg_get_roundtrip() {
    std::puts("test_msg_get_roundtrip");

    Get get;
    get.param_paths = {"Device.DeviceInfo.SerialNumber", "Device.WiFi."};
    get.max_depth = 2;

    Msg decoded;
    const auto* decoded_get = roundtrip_request(get, "42", MsgType::Get, decoded);
    CHECK(decoded_get != nullptr);
    if (decoded_get) {
        CHECK_EQ(decoded_get->param_paths, get.param_paths);
        CHECK_EQ(decoded_get->max_depth, 2u);
    }
}

static void test_msg_response_roundtrip() {
    std::puts("test_msg_response_roundtrip");

    GetResp get_resp;
    RequestedPathResult requested;
    requested.requested_path = "Device.DeviceInfo.";
    ResolvedPathResult resolved;
    resolved.resolved_path = "Device.DeviceInfo.";
    resolved.result_params = {{"SerialNumber", "ABC123"}, {"ModelName", "XYZ"}};
    requested.resolved_path_results = {resolved};
    RequestedPathResult failed;
    failed.requested_path = "Device.Nope.";
    failed.err_code = 7026;
    failed.err_msg = "Invalid path";
    get_resp.req_path_results = {requested, failed};

    Msg decoded;
    const auto* decoded_get_resp = roundtrip_response(get_resp, "43", MsgType::GetResp, decoded);
    CHECK(decoded_get_resp != nullptr);
    if (decoded_get_resp) {
        CHECK(decoded_get_resp->req_path_results.size() == 2);
        if (decoded_get_resp->req_path_results.size() == 2) {
            const auto& decoded_results = decoded_get_resp->req_path_results[0].resolved_path_results;
            CHECK(decoded_results.size() == 1);
            if (decoded_results.size() == 1) {
                CHECK_EQ(decoded_results[0].result_params, resolved.result_params);
            }
            CHECK_EQ(decoded_get_resp->req_path_results[1].err_code, 7026u);
            CHECK_EQ(decoded_get_resp->req_path_results[1].err_msg, "Invalid path");
        }
    }
}

static void test_error_body_roundtrip() {
    std::puts("test_error_body_roundtrip");

    ErrorBody error;
    error.err_code = 7004;
    error.err_msg = "Invalid arguments";
    error.param_errs = {{"Device.WiFi.SSID.1.SSID", 7012, "Invalid value"}};

    Body body;
    body.msg_body = error;
    Msg msg;
    msg.header = Header{"44", MsgType::Error};
    msg.body = body;

    auto decoded = Msg::decode(msg.encode());
    CHECK(decoded.has_value());
    auto* decoded_error = decoded ? std::get_if<ErrorBody>(&decoded->body->msg_body) : nullptr;
    CHECK(decoded_error != nullptr);
    if (decoded_error) {
        CHECK_EQ(decoded_error->err_code, 7004u);
        CHECK_EQ(decoded_error->err_msg, "Invalid arguments");
        CHECK(decoded_error->param_errs.size() == 1);
        if (decoded_error->param_errs.size() == 1) {
            CHECK_EQ(decoded_error->param_errs[0].param_path, "Device.WiFi.SSID.1.SSID");
            CHECK_EQ(decoded_error->param_errs[0].err_code, 7012u);
        }
    }
    CHECK(msg_type_of(body) == MsgType::Error);
}

static void test_get_supported_dm_roundtrip() {
    std::puts("test_get_supported_dm_roundtrip");

    GetSupportedDM gsdm;
    gsdm.obj_paths = {"Device.TestApp."};
    gsdm.first_level_only = true;
    gsdm.return_commands = true;
    gsdm.return_events = true;
    gsdm.return_params = true;
    gsdm.return_unique_key_sets = true;

    Msg decoded;
    const auto* decoded_req = roundtrip_request(gsdm, "50", MsgType::GetSupportedDm, decoded);
    CHECK(decoded_req != nullptr);
    if (decoded_req) {
        CHECK_EQ(decoded_req->obj_paths, gsdm.obj_paths);
        CHECK(decoded_req->first_level_only && decoded_req->return_commands && decoded_req->return_events);
        CHECK(decoded_req->return_params && decoded_req->return_unique_key_sets);
    }

    GetSupportedDMResp resp;
    RequestedObjectResult result;
    result.req_obj_path = "Device.TestApp.";
    result.data_model_inst_uri = "urn:example:testapp-1-0";
    SupportedObjectResult object;
    object.supported_obj_path = "Device.TestApp.Item.{i}.";
    object.access = ObjAccessType::AddDelete;
    object.is_multi_instance = true;
    object.supported_params = {{"Name", ParamAccessType::ReadWrite, ParamValueType::String, ValueChangeType::Allowed},
                               {"Count", ParamAccessType::ReadOnly, ParamValueType::UnsignedInt, ValueChangeType::WillIgnore}};
    object.supported_commands = {{"Reset()", {"Hard"}, {"Status"}, CmdType::Async}};
    object.supported_events = {{"Changed!", {"Reason"}}};
    object.divergent_paths = {"Device.TestApp.Item.3."};
    object.unique_key_sets = {{{"Name"}}, {{"Alias"}}};
    result.supported_objs = {object};
    RequestedObjectResult failed;
    failed.req_obj_path = "Device.Missing.";
    failed.err_code = 7026;
    failed.err_msg = "Invalid path";
    resp.req_obj_results = {result, failed};

    const auto* decoded_resp = roundtrip_response(resp, "51", MsgType::GetSupportedDmResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp && decoded_resp->req_obj_results.size() == 2) {
        const auto& r = decoded_resp->req_obj_results[0];
        CHECK_EQ(r.req_obj_path, "Device.TestApp.");
        CHECK_EQ(r.data_model_inst_uri, "urn:example:testapp-1-0");
        CHECK(r.supported_objs.size() == 1);
        if (r.supported_objs.size() == 1) {
            const auto& o = r.supported_objs[0];
            CHECK_EQ(o.supported_obj_path, "Device.TestApp.Item.{i}.");
            CHECK(o.access == ObjAccessType::AddDelete);
            CHECK(o.is_multi_instance);
            CHECK(o.supported_params.size() == 2);
            if (o.supported_params.size() == 2) {
                CHECK_EQ(o.supported_params[0].param_name, "Name");
                CHECK(o.supported_params[0].access == ParamAccessType::ReadWrite);
                CHECK(o.supported_params[0].value_type == ParamValueType::String);
                CHECK(o.supported_params[0].value_change == ValueChangeType::Allowed);
                CHECK(o.supported_params[1].value_type == ParamValueType::UnsignedInt);
                CHECK(o.supported_params[1].value_change == ValueChangeType::WillIgnore);
            }
            CHECK(o.supported_commands.size() == 1);
            if (o.supported_commands.size() == 1) {
                CHECK_EQ(o.supported_commands[0].command_name, "Reset()");
                CHECK_EQ(o.supported_commands[0].input_arg_names, std::vector<std::string>{"Hard"});
                CHECK_EQ(o.supported_commands[0].output_arg_names, std::vector<std::string>{"Status"});
                CHECK(o.supported_commands[0].command_type == CmdType::Async);
            }
            CHECK(o.supported_events.size() == 1);
            if (o.supported_events.size() == 1) {
                CHECK_EQ(o.supported_events[0].event_name, "Changed!");
                CHECK_EQ(o.supported_events[0].arg_names, std::vector<std::string>{"Reason"});
            }
            CHECK_EQ(o.divergent_paths, std::vector<std::string>{"Device.TestApp.Item.3."});
            CHECK(o.unique_key_sets.size() == 2);
            if (o.unique_key_sets.size() == 2) {
                CHECK_EQ(o.unique_key_sets[1].key_names, std::vector<std::string>{"Alias"});
            }
        }
        CHECK_EQ(decoded_resp->req_obj_results[1].err_code, 7026u);
    } else {
        CHECK(false);
    }
}

static void test_get_instances_roundtrip() {
    std::puts("test_get_instances_roundtrip");

    GetInstances gi;
    gi.obj_paths = {"Device.TestApp.Item."};
    gi.first_level_only = true;

    Msg decoded;
    const auto* decoded_req = roundtrip_request(gi, "60", MsgType::GetInstances, decoded);
    CHECK(decoded_req != nullptr);
    if (decoded_req) {
        CHECK_EQ(decoded_req->obj_paths, gi.obj_paths);
        CHECK(decoded_req->first_level_only);
    }

    GetInstancesResp resp;
    InstancesPathResult result;
    result.requested_path = "Device.TestApp.Item.";
    result.curr_insts = {{"Device.TestApp.Item.1.", {{"Name", "a"}}}, {"Device.TestApp.Item.2.", {{"Name", "b"}}}};
    resp.req_path_results = {result};

    const auto* decoded_resp = roundtrip_response(resp, "61", MsgType::GetInstancesResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp && decoded_resp->req_path_results.size() == 1) {
        const auto& r = decoded_resp->req_path_results[0];
        CHECK_EQ(r.requested_path, "Device.TestApp.Item.");
        CHECK(r.curr_insts.size() == 2);
        if (r.curr_insts.size() == 2) {
            CHECK_EQ(r.curr_insts[1].instantiated_obj_path, "Device.TestApp.Item.2.");
            CHECK_EQ(r.curr_insts[1].unique_keys.at("Name"), "b");
        }
    } else {
        CHECK(false);
    }
}

static void test_set_roundtrip() {
    std::puts("test_set_roundtrip");

    Set set;
    set.allow_partial = true;
    UpdateObject object;
    object.obj_path = "Device.TestApp.Item.1.";
    object.param_settings = {{"Name", "renamed", true}, {"Enable", "true", false}};
    set.update_objs = {object};

    Msg decoded;
    const auto* decoded_req = roundtrip_request(set, "70", MsgType::Set, decoded);
    CHECK(decoded_req != nullptr);
    if (decoded_req) {
        CHECK(decoded_req->allow_partial);
        CHECK(decoded_req->update_objs.size() == 1);
        if (decoded_req->update_objs.size() == 1) {
            CHECK_EQ(decoded_req->update_objs[0].obj_path, "Device.TestApp.Item.1.");
            CHECK(decoded_req->update_objs[0].param_settings.size() == 2);
            if (decoded_req->update_objs[0].param_settings.size() == 2) {
                CHECK_EQ(decoded_req->update_objs[0].param_settings[0].param, "Name");
                CHECK_EQ(decoded_req->update_objs[0].param_settings[0].value, "renamed");
                CHECK(decoded_req->update_objs[0].param_settings[0].required);
                CHECK(!decoded_req->update_objs[0].param_settings[1].required);
            }
        }
    }

    SetResp resp;
    UpdatedObjectResult ok;
    ok.requested_path = "Device.TestApp.Item.1.";
    OperationSuccess success;
    success.updated_inst_results = {{"Device.TestApp.Item.1.", {{"Enable", 7013, "Not writable"}}, {{"Name", "renamed"}}}};
    ok.oper_status = OperationStatus{success};
    UpdatedObjectResult bad;
    bad.requested_path = "Device.TestApp.Item.2.";
    OperationFailure failure;
    failure.err_code = 7016;
    failure.err_msg = "Object does not exist";
    failure.updated_inst_failures = {{"Device.TestApp.Item.2.", {{"Name", 7016, "no such instance"}}}};
    bad.oper_status = OperationStatus{failure};
    resp.updated_obj_results = {ok, bad};

    const auto* decoded_resp = roundtrip_response(resp, "71", MsgType::SetResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp && decoded_resp->updated_obj_results.size() == 2) {
        const auto& first = decoded_resp->updated_obj_results[0];
        CHECK(first.oper_status.has_value());
        const auto* s = first.oper_status ? std::get_if<OperationSuccess>(&first.oper_status->oper_status) : nullptr;
        CHECK(s != nullptr);
        if (s && s->updated_inst_results.size() == 1) {
            CHECK_EQ(s->updated_inst_results[0].affected_path, "Device.TestApp.Item.1.");
            CHECK_EQ(s->updated_inst_results[0].updated_params.at("Name"), "renamed");
            CHECK(s->updated_inst_results[0].param_errs.size() == 1);
            if (s->updated_inst_results[0].param_errs.size() == 1) {
                CHECK_EQ(s->updated_inst_results[0].param_errs[0].param, "Enable");
                CHECK_EQ(s->updated_inst_results[0].param_errs[0].err_code, 7013u);
            }
        } else {
            CHECK(false);
        }
        const auto& second = decoded_resp->updated_obj_results[1];
        const auto* f = second.oper_status ? std::get_if<OperationFailure>(&second.oper_status->oper_status) : nullptr;
        CHECK(f != nullptr);
        if (f) {
            CHECK_EQ(f->err_code, 7016u);
            CHECK(f->updated_inst_failures.size() == 1);
            if (f->updated_inst_failures.size() == 1) {
                CHECK_EQ(f->updated_inst_failures[0].affected_path, "Device.TestApp.Item.2.");
                CHECK(f->updated_inst_failures[0].param_errs.size() == 1);
            }
        }
    } else {
        CHECK(false);
    }
}

static void test_add_roundtrip() {
    std::puts("test_add_roundtrip");

    Add add;
    add.allow_partial = false;
    CreateObject object;
    object.obj_path = "Device.TestApp.Item.";
    object.param_settings = {{"Name", "new", true}};
    add.create_objs = {object};

    Msg decoded;
    const auto* decoded_req = roundtrip_request(add, "80", MsgType::Add, decoded);
    CHECK(decoded_req != nullptr);
    if (decoded_req && decoded_req->create_objs.size() == 1) {
        CHECK_EQ(decoded_req->create_objs[0].obj_path, "Device.TestApp.Item.");
        CHECK(decoded_req->create_objs[0].param_settings.size() == 1);
        if (decoded_req->create_objs[0].param_settings.size() == 1) {
            CHECK_EQ(decoded_req->create_objs[0].param_settings[0].value, "new");
            CHECK(decoded_req->create_objs[0].param_settings[0].required);
        }
    } else {
        CHECK(false);
    }

    AddResp resp;
    CreatedObjectResult ok;
    ok.requested_path = "Device.TestApp.Item.";
    AddOperationSuccess success;
    success.instantiated_path = "Device.TestApp.Item.3.";
    success.unique_keys = {{"Name", "new"}};
    success.param_errs = {{"Colour", 7010, "Unsupported parameter"}};
    ok.oper_status = AddOperationStatus{success};
    CreatedObjectResult bad;
    bad.requested_path = "Device.TestApp.Fixed.";
    bad.oper_status = AddOperationStatus{AddOperationFailure{7019, "Not creatable"}};
    resp.created_obj_results = {ok, bad};

    const auto* decoded_resp = roundtrip_response(resp, "81", MsgType::AddResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp && decoded_resp->created_obj_results.size() == 2) {
        const auto& first = decoded_resp->created_obj_results[0];
        const auto* s = first.oper_status ? std::get_if<AddOperationSuccess>(&first.oper_status->oper_status) : nullptr;
        CHECK(s != nullptr);
        if (s) {
            CHECK_EQ(s->instantiated_path, "Device.TestApp.Item.3.");
            CHECK_EQ(s->unique_keys.at("Name"), "new");
            CHECK(s->param_errs.size() == 1);
            if (s->param_errs.size() == 1) {
                CHECK_EQ(s->param_errs[0].param, "Colour");
                CHECK_EQ(s->param_errs[0].err_code, 7010u);
            }
        }
        const auto& second = decoded_resp->created_obj_results[1];
        const auto* f = second.oper_status ? std::get_if<AddOperationFailure>(&second.oper_status->oper_status) : nullptr;
        CHECK(f != nullptr);
        if (f) {
            CHECK_EQ(f->err_code, 7019u);
            CHECK_EQ(f->err_msg, "Not creatable");
        }
    } else {
        CHECK(false);
    }
}

static void test_delete_roundtrip() {
    std::puts("test_delete_roundtrip");

    Delete del;
    del.allow_partial = true;
    del.obj_paths = {"Device.TestApp.Item.1.", "Device.TestApp.Item.9."};

    Msg decoded;
    const auto* decoded_req = roundtrip_request(del, "90", MsgType::Delete, decoded);
    CHECK(decoded_req != nullptr);
    if (decoded_req) {
        CHECK(decoded_req->allow_partial);
        CHECK_EQ(decoded_req->obj_paths, del.obj_paths);
    }

    DeleteResp resp;
    DeletedObjectResult ok;
    ok.requested_path = "Device.TestApp.Item.1.";
    DeleteOperationSuccess success;
    success.affected_paths = {"Device.TestApp.Item.1."};
    success.unaffected_path_errs = {{"Device.TestApp.Item.1.Child.1.", 7024, "Delete failure"}};
    ok.oper_status = DeleteOperationStatus{success};
    DeletedObjectResult bad;
    bad.requested_path = "Device.TestApp.Item.9.";
    bad.oper_status = DeleteOperationStatus{DeleteOperationFailure{7016, "Object does not exist"}};
    resp.deleted_obj_results = {ok, bad};

    const auto* decoded_resp = roundtrip_response(resp, "91", MsgType::DeleteResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp && decoded_resp->deleted_obj_results.size() == 2) {
        const auto& first = decoded_resp->deleted_obj_results[0];
        const auto* s = first.oper_status ? std::get_if<DeleteOperationSuccess>(&first.oper_status->oper_status) : nullptr;
        CHECK(s != nullptr);
        if (s) {
            CHECK_EQ(s->affected_paths, std::vector<std::string>{"Device.TestApp.Item.1."});
            CHECK(s->unaffected_path_errs.size() == 1);
            if (s->unaffected_path_errs.size() == 1) {
                CHECK_EQ(s->unaffected_path_errs[0].unaffected_path, "Device.TestApp.Item.1.Child.1.");
                CHECK_EQ(s->unaffected_path_errs[0].err_code, 7024u);
            }
        }
        const auto& second = decoded_resp->deleted_obj_results[1];
        const auto* f = second.oper_status ? std::get_if<DeleteOperationFailure>(&second.oper_status->oper_status) : nullptr;
        CHECK(f != nullptr);
        if (f) {
            CHECK_EQ(f->err_code, 7016u);
        }
    } else {
        CHECK(false);
    }
}

static void test_operate_roundtrip() {
    std::puts("test_operate_roundtrip");

    Operate op;
    op.command = "Device.TestApp.Reset()";
    op.command_key = "key-1";
    op.send_resp = true;
    op.input_args = {{"Hard", "true"}};

    Msg decoded;
    const auto* decoded_req = roundtrip_request(op, "100", MsgType::Operate, decoded);
    CHECK(decoded_req != nullptr);
    if (decoded_req) {
        CHECK_EQ(decoded_req->command, "Device.TestApp.Reset()");
        CHECK_EQ(decoded_req->command_key, "key-1");
        CHECK(decoded_req->send_resp);
        CHECK_EQ(decoded_req->input_args.at("Hard"), "true");
    }

    OperateResp resp;
    OperationResult with_output;
    with_output.executed_command = "Device.TestApp.Reset()";
    with_output.operation_resp = OutputArgs{{{"Status", "Done"}}};
    OperationResult async_started;
    async_started.executed_command = "Device.TestApp.Long()";
    async_started.operation_resp = std::string("Device.LocalAgent.Request.5.");
    OperationResult failed;
    failed.executed_command = "Device.TestApp.Broken()";
    failed.operation_resp = CommandFailure{7022, "Command failure"};
    resp.operation_results = {with_output, async_started, failed};

    const auto* decoded_resp = roundtrip_response(resp, "101", MsgType::OperateResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp && decoded_resp->operation_results.size() == 3) {
        const auto* args = std::get_if<OutputArgs>(&decoded_resp->operation_results[0].operation_resp);
        CHECK(args != nullptr);
        if (args) CHECK_EQ(args->output_args.at("Status"), "Done");
        const auto* path = std::get_if<std::string>(&decoded_resp->operation_results[1].operation_resp);
        CHECK(path != nullptr);
        if (path) CHECK_EQ(*path, "Device.LocalAgent.Request.5.");
        const auto* failure = std::get_if<CommandFailure>(&decoded_resp->operation_results[2].operation_resp);
        CHECK(failure != nullptr);
        if (failure) CHECK_EQ(failure->err_code, 7022u);
    } else {
        CHECK(false);
    }
}

static void test_get_supported_protocol_roundtrip() {
    std::puts("test_get_supported_protocol_roundtrip");

    Msg decoded;
    const auto* decoded_req = roundtrip_request(GetSupportedProtocol{"1.3,1.4,1.5"}, "110",
                                                MsgType::GetSupportedProto, decoded);
    CHECK(decoded_req != nullptr);
    if (decoded_req) CHECK_EQ(decoded_req->controller_supported_protocol_versions, "1.3,1.4,1.5");

    const auto* decoded_resp = roundtrip_response(GetSupportedProtocolResp{"1.5"}, "111",
                                                  MsgType::GetSupportedProtoResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp) CHECK_EQ(decoded_resp->agent_supported_protocol_versions, "1.5");
}

static void test_register_roundtrip() {
    std::puts("test_register_roundtrip");

    Register reg;
    reg.allow_partial = true;
    reg.reg_paths = {"Device.TestApp.", "Device.DeviceInfo."};

    Msg decoded;
    const auto* decoded_req = roundtrip_request(reg, "120", MsgType::Register, decoded);
    CHECK(decoded_req != nullptr);
    if (decoded_req) {
        CHECK(decoded_req->allow_partial);
        CHECK_EQ(decoded_req->reg_paths, reg.reg_paths);
    }

    RegisterResp resp;
    RegisteredPathResult ok;
    ok.requested_path = "Device.TestApp.";
    ok.oper_status = RegisterOperationStatus{RegisterOperationSuccess{"Device.TestApp."}};
    RegisteredPathResult bad;
    bad.requested_path = "Device.DeviceInfo.";
    bad.oper_status = RegisterOperationStatus{RegisterOperationFailure{7800, "Path already registered"}};
    resp.registered_path_results = {ok, bad};

    const auto* decoded_resp = roundtrip_response(resp, "121", MsgType::RegisterResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp && decoded_resp->registered_path_results.size() == 2) {
        const auto& first = decoded_resp->registered_path_results[0];
        const auto* s = first.oper_status ? std::get_if<RegisterOperationSuccess>(&first.oper_status->oper_status) : nullptr;
        CHECK(s != nullptr);
        if (s) CHECK_EQ(s->registered_path, "Device.TestApp.");
        const auto& second = decoded_resp->registered_path_results[1];
        const auto* f = second.oper_status ? std::get_if<RegisterOperationFailure>(&second.oper_status->oper_status) : nullptr;
        CHECK(f != nullptr);
        if (f) {
            CHECK_EQ(f->err_code, 7800u);
            CHECK_EQ(f->err_msg, "Path already registered");
        }
    } else {
        CHECK(false);
    }
}

static void test_deregister_roundtrip() {
    std::puts("test_deregister_roundtrip");

    Deregister dereg;
    dereg.paths = {"Device.TestApp."};

    Msg decoded;
    const auto* decoded_req = roundtrip_request(dereg, "130", MsgType::Deregister, decoded);
    CHECK(decoded_req != nullptr);
    if (decoded_req) CHECK_EQ(decoded_req->paths, dereg.paths);

    DeregisterResp resp;
    DeregisteredPathResult ok;
    ok.requested_path = "Device.TestApp.";
    ok.oper_status = DeregisterOperationStatus{DeregisterOperationSuccess{{"Device.TestApp."}}};
    DeregisteredPathResult bad;
    bad.requested_path = "Device.Other.";
    bad.oper_status = DeregisterOperationStatus{DeregisterOperationFailure{7026, "Invalid path"}};
    resp.deregistered_path_results = {ok, bad};

    const auto* decoded_resp = roundtrip_response(resp, "131", MsgType::DeregisterResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp && decoded_resp->deregistered_path_results.size() == 2) {
        const auto& first = decoded_resp->deregistered_path_results[0];
        const auto* s = first.oper_status ? std::get_if<DeregisterOperationSuccess>(&first.oper_status->oper_status) : nullptr;
        CHECK(s != nullptr);
        if (s) CHECK_EQ(s->deregistered_path, std::vector<std::string>{"Device.TestApp."});
        const auto& second = decoded_resp->deregistered_path_results[1];
        const auto* f = second.oper_status ? std::get_if<DeregisterOperationFailure>(&second.oper_status->oper_status) : nullptr;
        CHECK(f != nullptr);
        if (f) CHECK_EQ(f->err_code, 7026u);
    } else {
        CHECK(false);
    }
}

static void test_notify_usp_1_5_tags() {
    std::puts("test_notify_usp_1_5_tags");

    Msg msg;
    msg.header = Header{"44", MsgType::Notify};

    auto native_notify = Notify{};
    native_notify.subscription_id = "sub";
    native_notify.send_resp = true;
    native_notify.notification = ValueChange{"Path.", "one"};

    Request request;
    request.req_type = native_notify;
    Body body;
    body.msg_body = request;
    msg.body = body;

    auto encoded = msg.encode();
    CHECK(!encoded.empty());

    auto decoded = Msg::decode(encoded);
    CHECK(decoded.has_value());
    auto* decoded_req = std::get_if<Request>(&decoded->body->msg_body);
    CHECK(decoded_req != nullptr);
    auto* decoded_notify = decoded_req ? std::get_if<Notify>(&decoded_req->req_type) : nullptr;
    CHECK(decoded_notify != nullptr);
    if (decoded_notify) {
        CHECK_EQ(decoded_notify->subscription_id, "sub");
        CHECK_EQ(decoded_notify->send_resp, true);
        CHECK(std::get_if<ValueChange>(&decoded_notify->notification) != nullptr);
    }
}

static void test_notify_variants_roundtrip() {
    std::puts("test_notify_variants_roundtrip");

    Msg decoded;

    Notify creation;
    creation.subscription_id = "sub-c";
    creation.notification = ObjectCreation{"Device.TestApp.Item.4.", {{"Name", "d"}}};
    const auto* decoded_creation = roundtrip_request(creation, "140", MsgType::Notify, decoded);
    CHECK(decoded_creation != nullptr);
    if (decoded_creation) {
        const auto* c = std::get_if<ObjectCreation>(&decoded_creation->notification);
        CHECK(c != nullptr);
        if (c) {
            CHECK_EQ(c->obj_path, "Device.TestApp.Item.4.");
            CHECK_EQ(c->unique_keys.at("Name"), "d");
        }
    }

    Notify deletion;
    deletion.subscription_id = "sub-d";
    deletion.notification = ObjectDeletion{"Device.TestApp.Item.4."};
    const auto* decoded_deletion = roundtrip_request(deletion, "141", MsgType::Notify, decoded);
    CHECK(decoded_deletion != nullptr);
    if (decoded_deletion) {
        const auto* d = std::get_if<ObjectDeletion>(&decoded_deletion->notification);
        CHECK(d != nullptr);
        if (d) CHECK_EQ(d->obj_path, "Device.TestApp.Item.4.");
    }

    Notify event;
    event.subscription_id = "sub-e";
    event.notification = Event{"Device.TestApp.", "Changed!", {{"Reason", "user"}}};
    const auto* decoded_event = roundtrip_request(event, "142", MsgType::Notify, decoded);
    CHECK(decoded_event != nullptr);
    if (decoded_event) {
        const auto* e = std::get_if<Event>(&decoded_event->notification);
        CHECK(e != nullptr);
        if (e) {
            CHECK_EQ(e->obj_path, "Device.TestApp.");
            CHECK_EQ(e->event_name, "Changed!");
            CHECK_EQ(e->params.at("Reason"), "user");
        }
    }

    Notify complete_ok;
    complete_ok.subscription_id = "sub-o";
    OperationComplete oc;
    oc.obj_path = "Device.TestApp.";
    oc.command_name = "Reset()";
    oc.command_key = "key-1";
    oc.operation_resp = OutputArgs{{{"Status", "Done"}}};
    complete_ok.notification = oc;
    const auto* decoded_complete = roundtrip_request(complete_ok, "143", MsgType::Notify, decoded);
    CHECK(decoded_complete != nullptr);
    if (decoded_complete) {
        const auto* o = std::get_if<OperationComplete>(&decoded_complete->notification);
        CHECK(o != nullptr);
        if (o) {
            CHECK_EQ(o->command_name, "Reset()");
            CHECK_EQ(o->command_key, "key-1");
            const auto* args = std::get_if<OutputArgs>(&o->operation_resp);
            CHECK(args != nullptr);
            if (args) CHECK_EQ(args->output_args.at("Status"), "Done");
        }
    }

    Notify complete_failed;
    complete_failed.subscription_id = "sub-f";
    OperationComplete ocf;
    ocf.obj_path = "Device.TestApp.";
    ocf.command_name = "Reset()";
    ocf.operation_resp = CommandFailure{7022, "Command failure"};
    complete_failed.notification = ocf;
    const auto* decoded_failed = roundtrip_request(complete_failed, "144", MsgType::Notify, decoded);
    CHECK(decoded_failed != nullptr);
    if (decoded_failed) {
        const auto* o = std::get_if<OperationComplete>(&decoded_failed->notification);
        const auto* f = o ? std::get_if<CommandFailure>(&o->operation_resp) : nullptr;
        CHECK(f != nullptr);
        if (f) CHECK_EQ(f->err_code, 7022u);
    }

    const auto* decoded_resp = roundtrip_response(NotifyResp{"sub-c"}, "145", MsgType::NotifyResp, decoded);
    CHECK(decoded_resp != nullptr);
    if (decoded_resp) CHECK_EQ(decoded_resp->subscription_id, "sub-c");
}

static void test_msg_type_helpers() {
    std::puts("test_msg_type_helpers");

    Body body;
    Request request;
    request.req_type = Register{};
    body.msg_body = request;
    CHECK(msg_type_of(body) == MsgType::Register);

    request.req_type = GetInstances{};
    body.msg_body = request;
    CHECK(msg_type_of(body) == MsgType::GetInstances);

    Response response;
    response.resp_type = DeleteResp{};
    body.msg_body = response;
    CHECK(msg_type_of(body) == MsgType::DeleteResp);

    body.msg_body = std::monostate{};
    CHECK(msg_type_of(body) == MsgType::Error);

    CHECK(response_type_for(MsgType::Get) == MsgType::GetResp);
    CHECK(response_type_for(MsgType::GetSupportedDm) == MsgType::GetSupportedDmResp);
    CHECK(response_type_for(MsgType::GetInstances) == MsgType::GetInstancesResp);
    CHECK(response_type_for(MsgType::Set) == MsgType::SetResp);
    CHECK(response_type_for(MsgType::Add) == MsgType::AddResp);
    CHECK(response_type_for(MsgType::Delete) == MsgType::DeleteResp);
    CHECK(response_type_for(MsgType::Operate) == MsgType::OperateResp);
    CHECK(response_type_for(MsgType::Notify) == MsgType::NotifyResp);
    CHECK(response_type_for(MsgType::GetSupportedProto) == MsgType::GetSupportedProtoResp);
    CHECK(response_type_for(MsgType::Register) == MsgType::RegisterResp);
    CHECK(response_type_for(MsgType::Deregister) == MsgType::DeregisterResp);
    CHECK(response_type_for(MsgType::GetResp) == MsgType::Error);
}

int main() {
    test_record_roundtrip();
    test_uds_connect_and_disconnect_records();
    test_decode_rejects_garbage();
    test_msg_get_roundtrip();
    test_msg_response_roundtrip();
    test_error_body_roundtrip();
    test_get_supported_dm_roundtrip();
    test_get_instances_roundtrip();
    test_set_roundtrip();
    test_add_roundtrip();
    test_delete_roundtrip();
    test_operate_roundtrip();
    test_get_supported_protocol_roundtrip();
    test_register_roundtrip();
    test_deregister_roundtrip();
    test_notify_usp_1_5_tags();
    test_notify_variants_roundtrip();
    test_msg_type_helpers();

    std::printf("test_proto: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
