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

#include "service.hpp"

#include "session.hpp"
#include "transport.hpp"

#include <cerrno>
#include <condition_variable>
#include <future>
#include <iostream>
#include <queue>

#include <poll.h>
#include <unistd.h>

namespace usp {

static constexpr std::chrono::seconds SERVICE_IO_TIMEOUT{1};

/* USP error codes used in replies (TR-369 Annex A). */
static constexpr uint32_t ERR_MESSAGE_NOT_SUPPORTED = 7001;
static constexpr uint32_t ERR_INTERNAL              = 7003;
static constexpr uint32_t ERR_INVALID_ARGUMENTS     = 7004;
static constexpr uint32_t ERR_INVALID_PATH          = 7026;

static const std::string SUBSCRIPTION_TABLE = "Device.LocalAgent.Subscription.";

/* ═══════════════════════════════════════════════════════════════════════════
 * Shared state between the public object and the worker thread
 * ═══════════════════════════════════════════════════════════════════════════ */

struct UspService::State {
    /* Outgoing records queued by the public API; the worker owns the transport. */
    struct Outgoing {
        proto::Record                         record;
        std::string                           msg_id;   /* non-empty: a reply is expected */
        std::shared_ptr<std::promise<proto::Msg>> reply;
    };

    std::mutex                      mutex;
    std::queue<Outgoing>            outgoing;
    std::map<std::string, std::shared_ptr<std::promise<proto::Msg>>> pending;
    bool                            dead{false};

    std::string                     endpoint_id;
    std::string                     broker_endpoint_id;
    std::vector<ServiceObject>      objects;
    ServiceHandlers                 handlers;
    std::vector<ServiceSubscription> subscriptions;
    int                             next_subscription_instance{1};

    UspController::WakePipe         wake_pipe;   /* declared before `worker`: closed only after it is joined */
    std::jthread                    worker;

    void wake() noexcept { wake_pipe.wake(); }
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Path helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

namespace {

static bool is_number(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (c < '0' || c > '9') return false;
    return true;
}

/* "Device.TestApp.Item.3." -> "Device.TestApp.Item.{i}." */
static std::string schema_path_of(const std::string& instantiated) {
    std::string out;
    size_t start = 0;
    while (start < instantiated.size()) {
        size_t dot = instantiated.find('.', start);
        if (dot == std::string::npos) dot = instantiated.size();
        std::string segment = instantiated.substr(start, dot - start);
        out += is_number(segment) ? "{i}" : segment;
        if (dot < instantiated.size()) out += '.';
        start = dot + 1;
    }
    return out;
}

/* Number of '.'-separated segments in a schema path ("Device.A.{i}." -> 3). */
static size_t segment_count(const std::string& path) {
    size_t n = 0;
    for (char c : path)
        if (c == '.') ++n;
    return n;
}

static const ServiceObject* find_object(const std::vector<ServiceObject>& objects, const std::string& schema_path) {
    for (const auto& object : objects)
        if (object.path == schema_path) return &object;
    return nullptr;
}

/* Direct child objects of a schema path: "Device.A.B." and "Device.A.B.{i}." for parent "Device.A.". */
static std::vector<const ServiceObject*> children_of(const std::vector<ServiceObject>& objects,
                                                     const std::string& parent_schema_path)
{
    std::vector<const ServiceObject*> out;
    size_t parent_segments = segment_count(parent_schema_path);
    for (const auto& object : objects) {
        if (object.path.size() <= parent_schema_path.size()) continue;
        if (object.path.compare(0, parent_schema_path.size(), parent_schema_path) != 0) continue;
        size_t extra = segment_count(object.path) - parent_segments;
        if ((object.multi_instance && extra == 2) || (!object.multi_instance && extra == 1))
            out.push_back(&object);
    }
    return out;
}

/* The last segment of a schema path without its "{i}." suffix: "Device.A.Item.{i}." -> "Item." */
static std::string table_segment(const ServiceObject& table) {
    std::string path = table.path;
    const std::string suffix = "{i}.";
    if (path.size() >= suffix.size() && path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0)
        path.erase(path.size() - suffix.size());
    size_t dot = path.rfind('.', path.size() - 2);
    return dot == std::string::npos ? path : path.substr(dot + 1);
}

static std::string last_segment(const std::string& schema_path) {
    std::string path = schema_path;
    size_t dot = path.rfind('.', path.size() - 2);
    return dot == std::string::npos ? path : path.substr(dot + 1);
}

static proto::ErrorBody make_error(uint32_t code, const std::string& msg) {
    proto::ErrorBody error;
    error.err_code = code;
    error.err_msg  = msg;
    return error;
}

/* A subscription reference "Device.A." matches "Device.A.B.C"; "Device.A.B" matches only itself. */
static bool reference_matches(const std::string& reference, const std::string& path) {
    if (reference.empty()) return false;
    if (reference.back() == '.')
        return path.compare(0, reference.size(), reference) == 0;
    return reference == path;
}

} // namespace

/* ═══════════════════════════════════════════════════════════════════════════
 * Request handling (runs on the worker thread)
 * ═══════════════════════════════════════════════════════════════════════════ */

namespace {

/* A reply body carrying one response message. */
template<typename Resp>
static proto::Body wrap(Resp resp) {
    proto::Response response;
    response.resp_type = std::move(resp);
    proto::Body body;
    body.msg_body = std::move(response);
    return body;
}

/* A reply body carrying a USP error. */
static proto::Body error_body(uint32_t code, const std::string& msg) {
    proto::Body body;
    body.msg_body = make_error(code, msg);
    return body;
}

class RequestHandler {
public:
    explicit RequestHandler(UspService::State& state) : state_(state) {}

    /* Returns the body of the reply to send (a Response or an Error). */
    proto::Body handle(const proto::Request& request) {
        return std::visit([&](const auto& req) -> proto::Body {
            using T = std::decay_t<decltype(req)>;
            if constexpr (std::is_same_v<T, proto::Get>)             return wrap(handle_get(req));
            else if constexpr (std::is_same_v<T, proto::GetSupportedDM>) return wrap(handle_get_supported_dm(req));
            else if constexpr (std::is_same_v<T, proto::GetInstances>)   return wrap(handle_get_instances(req));
            else if constexpr (std::is_same_v<T, proto::Set>)            return handle_set(req);
            else if constexpr (std::is_same_v<T, proto::Add>)            return handle_add(req);
            else if constexpr (std::is_same_v<T, proto::Delete>)         return handle_delete(req);
            else if constexpr (std::is_same_v<T, proto::Operate>)        return handle_operate(req);
            else {
                proto::Body body;
                body.msg_body = make_error(ERR_MESSAGE_NOT_SUPPORTED, "message type not supported by this service");
                return body;
            }
        }, request.req_type);
    }

private:
    /* ── Get ─────────────────────────────────────────────────────────────── */

    /* Collect the values of one instantiated object, then its children while depth allows. */
    void collect(const std::string& obj_path, const ServiceObject& schema, uint32_t depth_left,
                 std::vector<proto::ResolvedPathResult>& out)
    {
        if (obj_path.compare(0, SUBSCRIPTION_TABLE.size(), SUBSCRIPTION_TABLE) == 0) {
            collect_subscriptions(obj_path, out);
            return;
        }
        if (!state_.handlers.get) return;
        auto values = state_.handlers.get(obj_path);
        if (!values) return;

        proto::ResolvedPathResult resolved;
        resolved.resolved_path = obj_path;
        resolved.result_params = std::move(*values);
        out.push_back(std::move(resolved));

        if (depth_left == 1) return;
        uint32_t next_depth = depth_left == 0 ? 0 : depth_left - 1;

        for (const auto* child : children_of(state_.objects, schema.path)) {
            if (child->multi_instance) {
                std::string table_path = obj_path + table_segment(*child);
                for (const auto& instance : list_instances(table_path))
                    collect(instance.instantiated_obj_path, *child, next_depth, out);
            } else {
                collect(obj_path + last_segment(child->path), *child, next_depth, out);
            }
        }
    }

    std::vector<proto::CurrInstance> list_instances(const std::string& table_path) {
        if (table_path == SUBSCRIPTION_TABLE) {
            std::vector<proto::CurrInstance> out;
            int n = 1;
            for (const auto& sub : state_.subscriptions) {
                out.push_back({SUBSCRIPTION_TABLE + std::to_string(n++) + ".", {{"ID", sub.id}}});
            }
            return out;
        }
        if (!state_.handlers.instances) return {};
        return state_.handlers.instances(table_path);
    }

    void collect_subscriptions(const std::string& obj_path, std::vector<proto::ResolvedPathResult>& out) {
        int n = 1;
        for (const auto& sub : state_.subscriptions) {
            std::string path = SUBSCRIPTION_TABLE + std::to_string(n++) + ".";
            if (obj_path != SUBSCRIPTION_TABLE && obj_path != path) continue;
            std::string refs;
            for (const auto& r : sub.reference_list) {
                if (!refs.empty()) refs += ",";
                refs += r;
            }
            proto::ResolvedPathResult resolved;
            resolved.resolved_path = path;
            resolved.result_params = {{"ID", sub.id}, {"NotifType", sub.notif_type},
                                      {"ReferenceList", refs}, {"Enable", sub.enable ? "true" : "false"}};
            out.push_back(std::move(resolved));
        }
    }

    proto::RequestedPathResult resolve_get(const std::string& path, uint32_t max_depth) {
        proto::RequestedPathResult result;
        result.requested_path = path;

        if (path.empty()) {
            result.err_code = ERR_INVALID_PATH;
            result.err_msg  = "Invalid path";
            return result;
        }

        if (path.back() == '.') {
            if (path == SUBSCRIPTION_TABLE || path.compare(0, SUBSCRIPTION_TABLE.size(), SUBSCRIPTION_TABLE) == 0) {
                collect_subscriptions(path, result.resolved_path_results);
                return result;
            }
            std::string schema_path = schema_path_of(path);
            if (const auto* object = find_object(state_.objects, schema_path)) {
                /* An instantiated object ("A.1.") or a single object ("A."). */
                if (object->multi_instance && schema_path == path) {
                    result.err_code = ERR_INVALID_PATH;
                    result.err_msg  = "Invalid path";
                    return result;
                }
                collect(path, *object, max_depth, result.resolved_path_results);
                return result;
            }
            /* A table path ("A.Item.") lists all its instances. */
            if (const auto* table = find_object(state_.objects, schema_path + "{i}.")) {
                for (const auto& instance : list_instances(path))
                    collect(instance.instantiated_obj_path, *table, max_depth, result.resolved_path_results);
                return result;
            }
            result.err_code = ERR_INVALID_PATH;
            result.err_msg  = "Invalid path";
            return result;
        }

        /* A parameter path. */
        size_t dot = path.rfind('.');
        if (dot == std::string::npos) {
            result.err_code = ERR_INVALID_PATH;
            result.err_msg  = "Invalid path";
            return result;
        }
        std::string obj_path = path.substr(0, dot + 1);
        std::string param    = path.substr(dot + 1);

        std::vector<proto::ResolvedPathResult> objects;
        if (obj_path.compare(0, SUBSCRIPTION_TABLE.size(), SUBSCRIPTION_TABLE) == 0) {
            collect_subscriptions(obj_path, objects);
        } else if (const auto* object = find_object(state_.objects, schema_path_of(obj_path))) {
            collect(obj_path, *object, 1, objects);
        }
        for (auto& object : objects) {
            auto it = object.result_params.find(param);
            if (it == object.result_params.end()) continue;
            proto::ResolvedPathResult resolved;
            resolved.resolved_path = object.resolved_path;
            resolved.result_params = {{param, it->second}};
            result.resolved_path_results.push_back(std::move(resolved));
            return result;
        }
        result.err_code = ERR_INVALID_PATH;
        result.err_msg  = "Invalid path";
        return result;
    }

    proto::GetResp handle_get(const proto::Get& get) {
        proto::GetResp resp;
        for (const auto& path : get.param_paths)
            resp.req_path_results.push_back(resolve_get(path, get.max_depth));
        return resp;
    }

    /* ── GetSupportedDM ──────────────────────────────────────────────────── */

    proto::SupportedObjectResult describe(const ServiceObject& object, const proto::GetSupportedDM& req) {
        proto::SupportedObjectResult out;
        out.supported_obj_path = object.path;
        out.access             = object.access;
        out.is_multi_instance  = object.multi_instance;
        if (req.return_params) {
            for (const auto& param : object.params)
                out.supported_params.push_back({param.name, param.access, param.type,
                                                proto::ValueChangeType::Allowed});
        }
        if (req.return_commands) {
            for (const auto& command : object.commands)
                out.supported_commands.push_back({command.name, command.input_args, command.output_args,
                                                  command.async ? proto::CmdType::Async : proto::CmdType::Sync});
        }
        if (req.return_events) {
            for (const auto& event : object.events)
                out.supported_events.push_back({event.name, event.args});
        }
        if (req.return_unique_key_sets && !object.unique_keys.empty()) {
            out.unique_key_sets.push_back({object.unique_keys});
        }
        return out;
    }

    proto::GetSupportedDMResp handle_get_supported_dm(const proto::GetSupportedDM& req) {
        proto::GetSupportedDMResp resp;
        for (const auto& obj_path : req.obj_paths) {
            proto::RequestedObjectResult result;
            result.req_obj_path = obj_path;
            std::string schema_path = schema_path_of(obj_path);
            bool found = false;
            for (const auto& object : state_.objects) {
                bool match = req.first_level_only ? object.path == schema_path
                                                  : object.path.compare(0, schema_path.size(), schema_path) == 0;
                if (!match) continue;
                found = true;
                result.supported_objs.push_back(describe(object, req));
            }
            if (!found) {
                result.err_code = ERR_INVALID_PATH;
                result.err_msg  = "Invalid path";
            }
            resp.req_obj_results.push_back(std::move(result));
        }
        return resp;
    }

    /* ── GetInstances ────────────────────────────────────────────────────── */

    void enumerate(const ServiceObject& schema, const std::string& obj_path, bool first_level_only,
                   std::vector<proto::CurrInstance>& out)
    {
        for (const auto* child : children_of(state_.objects, schema.path)) {
            if (child->multi_instance) {
                std::string table_path = obj_path + table_segment(*child);
                for (const auto& instance : list_instances(table_path)) {
                    out.push_back(instance);
                    if (!first_level_only) enumerate(*child, instance.instantiated_obj_path, false, out);
                }
            } else if (!first_level_only) {
                enumerate(*child, obj_path + last_segment(child->path), false, out);
            }
        }
    }

    proto::GetInstancesResp handle_get_instances(const proto::GetInstances& req) {
        proto::GetInstancesResp resp;
        for (const auto& obj_path : req.obj_paths) {
            proto::InstancesPathResult result;
            result.requested_path = obj_path;
            std::string schema_path = schema_path_of(obj_path);
            if (const auto* table = find_object(state_.objects, schema_path + "{i}.");
                table && !obj_path.empty() && obj_path.back() == '.' && schema_path == obj_path) {
                for (const auto& instance : list_instances(obj_path)) {
                    result.curr_insts.push_back(instance);
                    if (!req.first_level_only) enumerate(*table, instance.instantiated_obj_path, false, result.curr_insts);
                }
            } else if (const auto* object = find_object(state_.objects, schema_path)) {
                enumerate(*object, obj_path, req.first_level_only, result.curr_insts);
            } else if (obj_path == SUBSCRIPTION_TABLE) {
                result.curr_insts = list_instances(obj_path);
            } else {
                result.err_code = ERR_INVALID_PATH;
                result.err_msg  = "Invalid path";
            }
            resp.req_path_results.push_back(std::move(result));
        }
        return resp;
    }

    /* ── Set ─────────────────────────────────────────────────────────────── */

    proto::Body handle_set(const proto::Set& set) {
        proto::SetResp resp;
        for (const auto& update : set.update_objs) {
            proto::UpdatedObjectResult result;
            result.requested_path = update.obj_path;

            std::map<std::string, std::string> params;
            bool any_required = false;
            for (const auto& setting : update.param_settings) {
                params[setting.param] = setting.value;
                any_required = any_required || setting.required;
            }

            std::optional<ParamErrors> errors;
            if (update.obj_path.compare(0, SUBSCRIPTION_TABLE.size(), SUBSCRIPTION_TABLE) == 0) {
                errors = set_subscription(update.obj_path, params);
            } else if (state_.handlers.set && find_object(state_.objects, schema_path_of(update.obj_path))) {
                errors = state_.handlers.set(update.obj_path, params);
            }

            proto::OperationStatus status;
            if (!errors) {
                if (!set.allow_partial)
                    return error_body(ERR_INVALID_PATH, "Invalid path: " + update.obj_path);
                status.oper_status = proto::OperationFailure{ERR_INVALID_PATH, "Invalid path", {}};
            } else {
                bool required_failed = false;
                for (const auto& e : *errors) {
                    for (const auto& setting : update.param_settings)
                        if (setting.param == e.param && setting.required) required_failed = true;
                }
                if (required_failed && !set.allow_partial)
                    return error_body(errors->front().err_code, errors->front().err_msg);

                proto::UpdatedInstanceResult instance;
                instance.affected_path = update.obj_path;
                instance.param_errs    = *errors;
                for (const auto& [name, value] : params) {
                    bool failed = false;
                    for (const auto& e : *errors) if (e.param == name) failed = true;
                    if (!failed) instance.updated_params[name] = value;
                }
                if (required_failed) {
                    status.oper_status = proto::OperationFailure{errors->front().err_code, errors->front().err_msg,
                                                                 {{update.obj_path, *errors}}};
                } else {
                    proto::OperationSuccess success;
                    success.updated_inst_results.push_back(std::move(instance));
                    status.oper_status = std::move(success);
                }
            }
            result.oper_status = std::move(status);
            resp.updated_obj_results.push_back(std::move(result));
        }
        return wrap(std::move(resp));
    }

    /* ── Add ─────────────────────────────────────────────────────────────── */

    proto::Body handle_add(const proto::Add& add) {
        proto::AddResp resp;
        for (const auto& create : add.create_objs) {
            proto::CreatedObjectResult result;
            result.requested_path = create.obj_path;

            std::map<std::string, std::string> params;
            for (const auto& setting : create.param_settings)
                params[setting.param] = setting.value;

            UspResult<AddResponse> created = UspError::agent_rejected(ERR_INVALID_PATH, "Invalid path");
            if (create.obj_path == SUBSCRIPTION_TABLE) {
                created = add_subscription(params);
            } else if (state_.handlers.add && find_object(state_.objects, schema_path_of(create.obj_path) + "{i}.")) {
                created = state_.handlers.add(create.obj_path, params);
            } else if (!state_.handlers.add) {
                created = UspError::agent_rejected(ERR_MESSAGE_NOT_SUPPORTED, "Add not supported by this service");
            }

            proto::AddOperationStatus status;
            if (auto* err = std::get_if<UspError>(&created)) {
                if (!add.allow_partial)
                    return error_body(err->code() ? err->code() : ERR_INTERNAL, err->message());
                status.oper_status = proto::AddOperationFailure{err->code() ? err->code() : ERR_INTERNAL, err->message()};
            } else {
                auto& ok = std::get<AddResponse>(created);
                proto::AddOperationSuccess success;
                success.instantiated_path = ok.instantiated_path;
                success.unique_keys       = ok.unique_keys;
                for (const auto& e : ok.param_errors)
                    success.param_errs.push_back({e.path, e.err_code, e.err_msg});
                status.oper_status = std::move(success);
            }
            result.oper_status = std::move(status);
            resp.created_obj_results.push_back(std::move(result));
        }
        return wrap(std::move(resp));
    }

    /* ── Delete ──────────────────────────────────────────────────────────── */

    proto::Body handle_delete(const proto::Delete& del) {
        proto::DeleteResp resp;
        for (const auto& obj_path : del.obj_paths) {
            proto::DeletedObjectResult result;
            result.requested_path = obj_path;

            std::optional<UspError> err;
            if (obj_path.compare(0, SUBSCRIPTION_TABLE.size(), SUBSCRIPTION_TABLE) == 0) {
                err = delete_subscription(obj_path);
            } else if (!state_.handlers.del) {
                err = UspError::agent_rejected(ERR_MESSAGE_NOT_SUPPORTED, "Delete not supported by this service");
            } else if (!find_object(state_.objects, schema_path_of(obj_path))) {
                err = UspError::agent_rejected(ERR_INVALID_PATH, "Invalid path");
            } else {
                err = state_.handlers.del(obj_path);
            }

            proto::DeleteOperationStatus status;
            if (err) {
                if (!del.allow_partial)
                    return error_body(err->code() ? err->code() : ERR_INTERNAL, err->message());
                status.oper_status = proto::DeleteOperationFailure{err->code() ? err->code() : ERR_INTERNAL, err->message()};
            } else {
                proto::DeleteOperationSuccess success;
                success.affected_paths = {obj_path};
                status.oper_status = std::move(success);
            }
            result.oper_status = std::move(status);
            resp.deleted_obj_results.push_back(std::move(result));
        }
        return wrap(std::move(resp));
    }

    /* ── Operate ─────────────────────────────────────────────────────────── */

    proto::Body handle_operate(const proto::Operate& op) {
        size_t dot = op.command.rfind('.');
        if (dot == std::string::npos)
            return error_body(ERR_INVALID_PATH, "Invalid command path");
        std::string obj_path = op.command.substr(0, dot + 1);
        std::string name     = op.command.substr(dot + 1);

        if (!state_.handlers.operate)
            return error_body(ERR_MESSAGE_NOT_SUPPORTED, "Operate not supported by this service");
        if (!find_object(state_.objects, schema_path_of(obj_path)))
            return error_body(ERR_INVALID_PATH, "Invalid path: " + obj_path);

        auto outcome = state_.handlers.operate(obj_path, name, op.input_args);

        proto::OperationResult result;
        result.executed_command = op.command;
        if (auto* err = std::get_if<UspError>(&outcome)) {
            result.operation_resp = proto::CommandFailure{err->code() ? err->code() : ERR_INTERNAL, err->message()};
        } else {
            result.operation_resp = proto::OutputArgs{std::get<std::map<std::string, std::string>>(outcome)};
        }
        proto::OperateResp resp;
        resp.operation_results.push_back(std::move(result));
        return wrap(std::move(resp));
    }

    /* ── The service's own Device.LocalAgent.Subscription. table ─────────── */

    UspResult<AddResponse> add_subscription(const std::map<std::string, std::string>& params) {
        ServiceSubscription sub;
        auto id = params.find("ID");
        auto type = params.find("NotifType");
        auto refs = params.find("ReferenceList");
        if (id == params.end() || type == params.end() || refs == params.end())
            return UspError::agent_rejected(ERR_INVALID_ARGUMENTS, "ID, NotifType and ReferenceList are required");
        sub.id         = id->second;
        sub.notif_type = type->second;
        size_t start = 0;
        while (start <= refs->second.size()) {
            size_t comma = refs->second.find(',', start);
            if (comma == std::string::npos) comma = refs->second.size();
            std::string ref = refs->second.substr(start, comma - start);
            if (!ref.empty()) sub.reference_list.push_back(ref);
            start = comma + 1;
        }
        auto enable = params.find("Enable");
        sub.enable = enable == params.end() || enable->second == "true" || enable->second == "1";

        state_.subscriptions.push_back(sub);
        AddResponse out;
        out.instantiated_path = SUBSCRIPTION_TABLE + std::to_string(state_.subscriptions.size()) + ".";
        out.unique_keys       = {{"ID", sub.id}};
        return out;
    }

    std::optional<UspError> delete_subscription(const std::string& obj_path) {
        std::string rest = obj_path.substr(SUBSCRIPTION_TABLE.size());
        if (!rest.empty() && rest.back() == '.') rest.pop_back();
        if (!is_number(rest)) return UspError::agent_rejected(ERR_INVALID_PATH, "Invalid path");
        size_t index = static_cast<size_t>(std::stoul(rest));
        if (index == 0 || index > state_.subscriptions.size())
            return UspError::agent_rejected(ERR_INVALID_PATH, "Invalid path");
        state_.subscriptions.erase(state_.subscriptions.begin() + static_cast<long>(index - 1));
        return std::nullopt;
    }

    std::optional<ParamErrors> set_subscription(const std::string& obj_path,
                                                const std::map<std::string, std::string>& params) {
        std::string rest = obj_path.substr(SUBSCRIPTION_TABLE.size());
        if (!rest.empty() && rest.back() == '.') rest.pop_back();
        if (!is_number(rest)) return std::nullopt;
        size_t index = static_cast<size_t>(std::stoul(rest));
        if (index == 0 || index > state_.subscriptions.size()) return std::nullopt;
        auto& sub = state_.subscriptions[index - 1];
        ParamErrors errors;
        for (const auto& [name, value] : params) {
            if (name == "Enable") sub.enable = (value == "true" || value == "1");
            else if (name == "NotifType") sub.notif_type = value;
            else errors.push_back({name, 7013, "Non-writable parameter"});
        }
        return errors;
    }

    UspService::State& state_;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Worker thread
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Fail every pending and queued reply when the worker is gone, so no caller waits forever. */
struct DeadServiceGuard {
    UspService::State* s;
    ~DeadServiceGuard() {
        std::unique_lock lk(s->mutex);
        s->dead = true;
        for (auto& [id, reply] : s->pending) {
            try { reply->set_exception(std::make_exception_ptr(std::runtime_error("USP session closed"))); } catch (...) {}
        }
        s->pending.clear();
        while (!s->outgoing.empty()) {
            auto& item = s->outgoing.front();
            if (item.reply) {
                try { item.reply->set_exception(std::make_exception_ptr(std::runtime_error("USP session closed"))); } catch (...) {}
            }
            s->outgoing.pop();
        }
    }
};

static void service_worker(std::stop_token stop_token, Transport transport, UspService::State* state) {
    std::stop_callback wake_on_stop(stop_token, [state] { state->wake(); });
    DeadServiceGuard dead_guard{state};
    RequestHandler handler(*state);

    while (!stop_token.stop_requested()) {
        /* 1. Send everything the public API queued. */
        for (;;) {
            UspService::State::Outgoing item;
            {
                std::unique_lock lk(state->mutex);
                if (state->outgoing.empty()) break;
                item = std::move(state->outgoing.front());
                state->outgoing.pop();
                if (item.reply) state->pending[item.msg_id] = item.reply;
            }
            if (auto err = transport.send(item.record)) {
                std::cerr << "USP service: send failed: " << err->to_string() << "\n";
                return;
            }
        }

        /* 2. Sleep until the broker sends something or the API queues something. */
        pollfd fds[2];
        fds[0] = {transport.native_handle(), POLLIN, 0};
        fds[1] = {state->wake_pipe.rd, POLLIN, 0};
        int prc = ::poll(fds, 2, 1000);
        if (prc < 0) {
            if (errno == EINTR) continue;
            std::cerr << "USP service: poll failed\n";
            return;
        }
        if (fds[1].revents & POLLIN) {
            char drain[64];
            while (::read(state->wake_pipe.rd, drain, sizeof drain) > 0) {}
            continue;
        }
        if (prc == 0 || !(fds[0].revents & (POLLIN | POLLHUP | POLLERR))) continue;

        /* 3. One record from the broker. */
        auto result = transport.recv();
        if (auto* transport_err = std::get_if<TransportError>(&result)) {
            if (transport_err->is_timeout()) continue;
            std::cerr << "USP service: session worker stopping: " << transport_err->to_string() << "\n";
            return;
        }
        auto& record = std::get<proto::Record>(result);

        if (std::holds_alternative<proto::DisconnectRecord>(record.record_type)) {
            std::cerr << "USP service: broker disconnected\n";
            return;
        }

        auto msg_var = detail::extract_msg(record);
        if (std::holds_alternative<UspError>(msg_var)) continue; /* a UDSConnect or undecodable record */
        auto& msg = std::get<proto::Msg>(msg_var);
        if (!msg.header || !msg.body) continue;

        const std::string& from = record.from_id;

        if (auto* request = std::get_if<proto::Request>(&msg.body->msg_body)) {
            if (auto* notify = std::get_if<proto::Notify>(&request->req_type)) {
                if (notify->send_resp) {
                    proto::Response resp;
                    resp.resp_type = proto::NotifyResp{notify->subscription_id};
                    proto::Body body;
                    body.msg_body = std::move(resp);
                    transport.send(detail::build_reply_record(state->endpoint_id, from, msg.header->msg_id, std::move(body)));
                }
                continue;
            }
            proto::Body reply = handler.handle(*request);
            if (auto err = transport.send(detail::build_reply_record(state->endpoint_id, from, msg.header->msg_id, std::move(reply)))) {
                std::cerr << "USP service: reply failed: " << err->to_string() << "\n";
                return;
            }
            continue;
        }

        /* A Response or Error answering one of our requests (Register, Deregister). */
        std::shared_ptr<std::promise<proto::Msg>> reply;
        {
            std::unique_lock lk(state->mutex);
            auto it = state->pending.find(msg.header->msg_id);
            if (it != state->pending.end()) {
                reply = it->second;
                state->pending.erase(it);
            }
        }
        if (reply) reply->set_value(std::move(msg));
    }
}

} // namespace

/* ═══════════════════════════════════════════════════════════════════════════
 * UspService
 * ═══════════════════════════════════════════════════════════════════════════ */

UspService::UspService(std::string socket_path, std::string endpoint_id, std::string broker_endpoint_id)
    : socket_path_(std::move(socket_path))
    , endpoint_id_(std::move(endpoint_id))
    , broker_endpoint_id_(std::move(broker_endpoint_id))
    , state_(std::make_shared<State>())
{
    state_->endpoint_id = endpoint_id_;
}

UspService::~UspService() {
    stop();
}

void UspService::set_timeout(std::chrono::seconds timeout) { timeout_ = timeout; }
void UspService::set_password(std::string password)        { password_ = std::move(password); }

void UspService::add_object(ServiceObject object) {
    std::lock_guard lk(state_->mutex);
    state_->objects.push_back(std::move(object));
}

void UspService::set_handlers(ServiceHandlers handlers) {
    std::lock_guard lk(state_->mutex);
    state_->handlers = std::move(handlers);
}

bool UspService::running() const {
    std::lock_guard lk(state_->mutex);
    return state_->worker.joinable() && !state_->dead;
}

std::string UspService::broker_endpoint_id() const {
    std::lock_guard lk(state_->mutex);
    return state_->broker_endpoint_id;
}

std::vector<ServiceSubscription> UspService::subscriptions() const {
    std::lock_guard lk(state_->mutex);
    return state_->subscriptions;
}

std::optional<UspError> UspService::send_request_and_wait(proto::MsgType type, proto::Body body, proto::Msg& reply) {
    std::string broker;
    {
        std::lock_guard lk(state_->mutex);
        if (state_->dead || !state_->worker.joinable())
            return UspError::connection_failed("service not started");
        broker = state_->broker_endpoint_id;
    }
    auto record = detail::build_record(endpoint_id_, broker, type, std::move(body));
    auto promise = std::make_shared<std::promise<proto::Msg>>();
    auto future  = promise->get_future();

    std::string msg_id;
    {
        auto msg = detail::extract_msg(record);
        msg_id = std::get<proto::Msg>(msg).header->msg_id;
    }
    {
        std::lock_guard lk(state_->mutex);
        state_->outgoing.push({std::move(record), msg_id, promise});
    }
    state_->wake();

    if (future.wait_for(timeout_) != std::future_status::ready) {
        std::lock_guard lk(state_->mutex);
        state_->pending.erase(msg_id);
        return UspError::timeout();
    }
    try {
        reply = future.get();
    } catch (const std::exception& e) {
        return UspError::connection_failed(e.what());
    }
    return std::nullopt;
}

UspResult<std::vector<RegisterResult>> UspService::start(const std::vector<std::string>& roots, bool allow_partial) {
    if (running())
        return UspError::protocol("service already started");
    if (roots.empty())
        return UspError::protocol("no paths to register");

    /* A broker can drop a freshly connected peer once (seen on a gateway right after a container start); like
     * the controller's round_trip(), a recoverable failure gets one more attempt on a new connection. */
    auto result = start_once(roots, allow_partial);
    if (auto* err = std::get_if<UspError>(&result); err && err->is_recoverable())
        return start_once(roots, allow_partial);
    return result;
}

UspResult<std::vector<RegisterResult>> UspService::start_once(const std::vector<std::string>& roots, bool allow_partial) {

    /* Connect and establish the session on the caller's thread, so a refusal is reported here. */
    std::string peer;
    auto transport_result = Transport::connect(socket_path_, SERVICE_IO_TIMEOUT, endpoint_id_, &peer, password_);
    if (auto* err = std::get_if<TransportError>(&transport_result))
        return UspError::from_transport(*err);
    Transport transport = std::move(std::get<Transport>(transport_result));

    std::string broker = broker_endpoint_id_.empty() ? peer : broker_endpoint_id_;
    if (auto err = detail::establish_uds_session(transport, endpoint_id_, broker, timeout_, /*expect_ack=*/false))
        return UspError::from_transport(*err);

    {
        std::lock_guard lk(state_->mutex);
        state_->broker_endpoint_id = broker;
        state_->dead = false;
        state_->subscriptions.clear();
        if (!state_->wake_pipe.open() && state_->wake_pipe.rd < 0)
            return UspError::connection_failed("pipe() for service wake-up failed");
        State* raw = state_.get();
        state_->worker = std::jthread(
            [raw](std::stop_token token, Transport t) {
                service_worker(std::move(token), std::move(t), raw);
            },
            std::move(transport));
    }

    proto::Register reg;
    reg.allow_partial = allow_partial;
    reg.reg_paths     = roots;
    proto::Request req;
    req.req_type = std::move(reg);
    proto::Body body;
    body.msg_body = std::move(req);

    proto::Msg reply;
    if (auto err = send_request_and_wait(proto::MsgType::Register, std::move(body), reply)) {
        stop();
        return *err;
    }
    if (!reply.body) {
        stop();
        return UspError::protocol("empty body in REGISTER response");
    }
    if (auto* eb = std::get_if<proto::ErrorBody>(&reply.body->msg_body)) {
        auto err = UspError::agent_rejected(eb->err_code, eb->err_msg);
        stop();
        return err;
    }
    auto* resp = std::get_if<proto::Response>(&reply.body->msg_body);
    auto* rr   = resp ? std::get_if<proto::RegisterResp>(&resp->resp_type) : nullptr;
    if (!rr) {
        stop();
        return UspError::protocol("unexpected response type for REGISTER");
    }

    std::vector<RegisterResult> results;
    for (const auto& path_result : rr->registered_path_results) {
        RegisterResult r;
        r.path = path_result.requested_path;
        if (path_result.oper_status) {
            if (auto* f = std::get_if<proto::RegisterOperationFailure>(&path_result.oper_status->oper_status)) {
                r.err_code = f->err_code;
                r.err_msg  = f->err_msg;
            } else if (std::get_if<proto::RegisterOperationSuccess>(&path_result.oper_status->oper_status)) {
                r.ok = true;
            }
        }
        results.push_back(std::move(r));
    }
    return results;
}

void UspService::stop() {
    bool was_running;
    {
        std::lock_guard lk(state_->mutex);
        was_running = state_->worker.joinable() && !state_->dead;
    }
    if (was_running) {
        /* Best effort: tell the broker, then stop the worker. */
        proto::Deregister dereg;
        {
            std::lock_guard lk(state_->mutex);
            for (const auto& object : state_->objects) dereg.paths.push_back(object.path);
        }
        if (!dereg.paths.empty()) {
            proto::Request req;
            req.req_type = std::move(dereg);
            proto::Body body;
            body.msg_body = std::move(req);
            proto::Msg reply;
            send_request_and_wait(proto::MsgType::Deregister, std::move(body), reply);
        }
    }
    std::jthread worker;
    {
        std::lock_guard lk(state_->mutex);
        worker = std::move(state_->worker);
    }
    if (worker.joinable()) {
        worker.request_stop();
        worker.join();
    }
    std::lock_guard lk(state_->mutex);
    state_->dead = true;
}

void UspService::send_notify(const std::string& notif_type, const std::string& path, proto::Notify notify) {
    std::vector<ServiceSubscription> matching;
    std::string broker;
    {
        std::lock_guard lk(state_->mutex);
        if (state_->dead || !state_->worker.joinable()) return;
        broker = state_->broker_endpoint_id;
        for (const auto& sub : state_->subscriptions) {
            if (!sub.enable || sub.notif_type != notif_type) continue;
            for (const auto& ref : sub.reference_list)
                if (reference_matches(ref, path)) { matching.push_back(sub); break; }
        }
    }
    for (const auto& sub : matching) {
        proto::Notify n = notify;
        n.subscription_id = sub.id;
        n.send_resp       = false;
        proto::Request req;
        req.req_type = std::move(n);
        proto::Body body;
        body.msg_body = std::move(req);
        auto record = detail::build_record(endpoint_id_, broker, proto::MsgType::Notify, std::move(body));
        {
            std::lock_guard lk(state_->mutex);
            state_->outgoing.push({std::move(record), "", nullptr});
        }
    }
    if (!matching.empty()) state_->wake();
}

void UspService::value_changed(const std::string& param_path, const std::string& value) {
    proto::Notify notify;
    notify.notification = proto::ValueChange{param_path, value};
    send_notify("ValueChange", param_path, std::move(notify));
}

void UspService::object_created(const std::string& obj_path, const std::map<std::string, std::string>& unique_keys) {
    proto::Notify notify;
    notify.notification = proto::ObjectCreation{obj_path, unique_keys};
    send_notify("ObjectCreation", obj_path, std::move(notify));
}

void UspService::object_deleted(const std::string& obj_path) {
    proto::Notify notify;
    notify.notification = proto::ObjectDeletion{obj_path};
    send_notify("ObjectDeletion", obj_path, std::move(notify));
}

void UspService::event(const std::string& obj_path, const std::string& event_name,
                       const std::map<std::string, std::string>& params) {
    proto::Notify notify;
    notify.notification = proto::Event{obj_path, event_name, params};
    send_notify("Event", obj_path + event_name, std::move(notify));
}

} // namespace usp
