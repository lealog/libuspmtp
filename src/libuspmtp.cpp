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
 * libuspmtp.cpp
 *
 * C FFI layer — wraps UspController in a C-compatible opaque handle.
 *
 * All exported functions:
 *  – Guard against null pointers.
 *  – Catch all C++ exceptions at the boundary (USP_ERR_PANIC).
 *  – Never let exceptions propagate through the C ABI.
 */

#include "client.hpp"
#include "service.hpp"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "libuspmtp.h"

/* ── Handle type ─────────────────────────────────────────────────────────── */

struct UspControllerHandle {
    usp::UspController controller;
    mutable std::mutex  last_error_mutex;
    mutable std::string last_error;

    explicit UspControllerHandle(usp::UspController ctrl)
        : controller(std::move(ctrl)) {}

    void set_last_error(const std::string& msg) const {
        std::lock_guard lk(last_error_mutex);
        last_error = msg;
    }

    std::string get_last_error() const {
        std::lock_guard lk(last_error_mutex);
        return last_error;
    }
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/** Catch-all panic boundary — returns USP_ERR_PANIC on any exception. */
static int with_panic_boundary(auto&& f) noexcept {
    try {
        return f();
    } catch (...) {
        return USP_ERR_PANIC;
    }
}

/** Write value into a caller-supplied buffer. */
static int write_c_string(const std::string& value,
                           char* out_ptr, size_t out_len) {
    if (!out_ptr) return USP_ERR_NULL_POINTER;
    if (out_len == 0) return USP_ERR_INVALID_ARGUMENT;
    if (value.size() + 1 > out_len) return USP_ERR_BUFFER_TOO_SMALL;
    std::memcpy(out_ptr, value.data(), value.size());
    out_ptr[value.size()] = '\0';
    return USP_OK;
}

/** Same, but accepts null out_ptr with out_len==0 (discard result). */
static int write_optional_c_string(const std::string& value,
                                    char* out_ptr, size_t out_len) {
    if (!out_ptr) {
        if (out_len == 0) return USP_OK;
        return USP_ERR_NULL_POINTER;
    }
    return write_c_string(value, out_ptr, out_len);
}

/** Convert an array of C strings to a vector; returns error code. */
static int cstr_array_to_vec(const char* const* ptrs, size_t count,
                              std::vector<std::string>& out) {
    if (count == 0) { out.clear(); return USP_OK; }
    if (!ptrs) return USP_ERR_NULL_POINTER;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        if (!ptrs[i]) return USP_ERR_NULL_POINTER;
        out.push_back(ptrs[i]);
    }
    return USP_OK;
}

/** Convert two parallel arrays to a vector of pairs; returns error code. */
static int cstr_pairs_to_vec(const char* const* keys, const char* const* vals,
                              size_t count,
                              std::vector<std::pair<std::string,std::string>>& out) {
    if (count == 0) { out.clear(); return USP_OK; }
    if (!keys || !vals) return USP_ERR_NULL_POINTER;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        if (!keys[i] || !vals[i]) return USP_ERR_NULL_POINTER;
        out.emplace_back(keys[i], vals[i]);
    }
    return USP_OK;
}

/* ── Response text formatting ────────────────────────────────────────────── */

static std::string escape_field(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '\t') out += "\\t";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

static std::string format_get_response(const usp::GetResponse& resp) {
    std::string out;
    for (auto& [path, value] : resp.params) {
        out += "PARAM\t" + escape_field(path) + "\t" + escape_field(value) + "\n";
    }
    for (const auto& e : resp.errors) {
        out += "ERROR\t" + escape_field(e.path) + "\t" +
               std::to_string(e.err_code) + "\t" + escape_field(e.err_msg) + "\n";
    }
    return out;
}

static std::string format_set_response(const usp::SetResponse& resp) {
    std::string out;
    for (const auto& path : resp.updated) {
        out += "UPDATED\t" + escape_field(path) + "\n";
    }
    for (const auto& e : resp.errors) {
        out += "ERROR\t" + escape_field(e.path) + "\t" +
               std::to_string(e.err_code) + "\t" + escape_field(e.err_msg) + "\n";
    }
    return out;
}

static std::string format_operate_response(const usp::OperateResponse& resp) {
    std::string out;
    for (auto& [key, value] : resp.output_args) {
        out += "OUTPUT\t" + escape_field(key) + "\t" + escape_field(value) + "\n";
    }
    return out;
}

static std::string format_add_response(const usp::AddResponse& resp) {
    std::string out = "INSTANCE\t" + escape_field(resp.instantiated_path) + "\n";
    for (auto& [name, value] : resp.unique_keys) {
        out += "KEY\t" + escape_field(name) + "\t" + escape_field(value) + "\n";
    }
    for (const auto& e : resp.param_errors) {
        out += "ERROR\t" + escape_field(e.path) + "\t" +
               std::to_string(e.err_code) + "\t" + escape_field(e.err_msg) + "\n";
    }
    return out;
}

static std::string format_delete_response(const usp::DeleteResponse& resp) {
    std::string out;
    for (const auto& path : resp.affected_paths) {
        out += "AFFECTED\t" + escape_field(path) + "\n";
    }
    for (const auto& e : resp.unaffected_paths) {
        out += "UNAFFECTED\t" + escape_field(e.path) + "\t" +
               std::to_string(e.err_code) + "\t" + escape_field(e.err_msg) + "\n";
    }
    return out;
}

static const char* obj_access_str(usp::proto::ObjAccessType access) {
    switch (access) {
    case usp::proto::ObjAccessType::ReadOnly:   return "ReadOnly";
    case usp::proto::ObjAccessType::AddDelete:  return "AddDelete";
    case usp::proto::ObjAccessType::AddOnly:    return "AddOnly";
    case usp::proto::ObjAccessType::DeleteOnly: return "DeleteOnly";
    }
    return "ReadOnly";
}

static const char* param_access_str(usp::proto::ParamAccessType access) {
    switch (access) {
    case usp::proto::ParamAccessType::ReadOnly:  return "ReadOnly";
    case usp::proto::ParamAccessType::ReadWrite: return "ReadWrite";
    case usp::proto::ParamAccessType::WriteOnly: return "WriteOnly";
    }
    return "ReadOnly";
}

static const char* value_type_str(usp::proto::ParamValueType type) {
    switch (type) {
    case usp::proto::ParamValueType::Unknown:      return "Unknown";
    case usp::proto::ParamValueType::Base64:       return "Base64";
    case usp::proto::ParamValueType::Boolean:      return "Boolean";
    case usp::proto::ParamValueType::DateTime:     return "DateTime";
    case usp::proto::ParamValueType::Decimal:      return "Decimal";
    case usp::proto::ParamValueType::HexBinary:    return "HexBinary";
    case usp::proto::ParamValueType::Int:          return "Int";
    case usp::proto::ParamValueType::Long:         return "Long";
    case usp::proto::ParamValueType::String:       return "String";
    case usp::proto::ParamValueType::UnsignedInt:  return "UnsignedInt";
    case usp::proto::ParamValueType::UnsignedLong: return "UnsignedLong";
    }
    return "Unknown";
}

static const char* cmd_type_str(usp::proto::CmdType type) {
    switch (type) {
    case usp::proto::CmdType::Unknown: return "Unknown";
    case usp::proto::CmdType::Sync:    return "Sync";
    case usp::proto::CmdType::Async:   return "Async";
    }
    return "Unknown";
}

static std::string join_names(const std::vector<std::string>& names) {
    std::string out;
    for (const auto& name : names) {
        if (!out.empty()) out += ",";
        out += escape_field(name);
    }
    return out;
}

static std::string format_supported_dm_response(const usp::SupportedDMResponse& resp) {
    std::string out;
    for (const auto& object : resp.objects) {
        const std::string path = escape_field(object.supported_obj_path);
        out += "OBJECT\t" + path + "\t" + obj_access_str(object.access) + "\t" +
               (object.is_multi_instance ? "1" : "0") + "\n";
        for (const auto& param : object.supported_params) {
            out += "PARAM\t" + path + "\t" + escape_field(param.param_name) + "\t" +
                   param_access_str(param.access) + "\t" + value_type_str(param.value_type) + "\n";
        }
        for (const auto& command : object.supported_commands) {
            out += "COMMAND\t" + path + "\t" + escape_field(command.command_name) + "\t" +
                   cmd_type_str(command.command_type) + "\t" + join_names(command.input_arg_names) + "\t" +
                   join_names(command.output_arg_names) + "\n";
        }
        for (const auto& event : object.supported_events) {
            out += "EVENT\t" + path + "\t" + escape_field(event.event_name) + "\t" +
                   join_names(event.arg_names) + "\n";
        }
    }
    for (const auto& e : resp.errors) {
        out += "ERROR\t" + escape_field(e.path) + "\t" +
               std::to_string(e.err_code) + "\t" + escape_field(e.err_msg) + "\n";
    }
    return out;
}

static std::string format_instances_response(const usp::InstancesResponse& resp) {
    std::string out;
    for (const auto& instance : resp.instances) {
        const std::string path = escape_field(instance.instantiated_obj_path);
        out += "INSTANCE\t" + path + "\n";
        for (auto& [name, value] : instance.unique_keys) {
            out += "KEY\t" + path + "\t" + escape_field(name) + "\t" + escape_field(value) + "\n";
        }
    }
    for (const auto& e : resp.errors) {
        out += "ERROR\t" + escape_field(e.path) + "\t" +
               std::to_string(e.err_code) + "\t" + escape_field(e.err_msg) + "\n";
    }
    return out;
}

static usp::SubscriptionNotificationType
notif_type_from_int(int value, int& err_out) {
    err_out = USP_OK;
    switch (value) {
    case USP_SUBSCRIPTION_VALUE_CHANGE:
        return usp::SubscriptionNotificationType::ValueChange;
    case USP_SUBSCRIPTION_OBJECT_CREATION:
        return usp::SubscriptionNotificationType::ObjectCreation;
    case USP_SUBSCRIPTION_OBJECT_DELETION:
        return usp::SubscriptionNotificationType::ObjectDeletion;
    default:
        err_out = USP_ERR_INVALID_ARGUMENT;
        return usp::SubscriptionNotificationType::ValueChange;
    }
}


/* ── USP Service handle and callback adapters ────────────────────────────── */

static constexpr size_t SERVICE_CALLBACK_BUFFER = 64 * 1024;

struct UspServiceHandle {
    usp::UspService                 service;
    std::vector<usp::ServiceObject> objects;      /* described before the first start */
    bool                            described{false};
    UspServiceCallbacks             callbacks{};
    mutable std::mutex              last_error_mutex;
    mutable std::string             last_error;

    UspServiceHandle(std::string socket_path, std::string endpoint_id, std::string broker_endpoint_id)
        : service(std::move(socket_path), std::move(endpoint_id), std::move(broker_endpoint_id)) {}

    void set_last_error(const std::string& msg) const {
        std::lock_guard lk(last_error_mutex);
        last_error = msg;
    }

    std::string get_last_error() const {
        std::lock_guard lk(last_error_mutex);
        return last_error;
    }

    usp::ServiceObject* find_object(const std::string& path) {
        for (auto& object : objects)
            if (object.path == path) return &object;
        return nullptr;
    }
};

static std::string unescape_field(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            ++i;
            if (s[i] == 't') out += '\t';
            else if (s[i] == 'n') out += '\n';
            else out += s[i];
        } else {
            out += s[i];
        }
    }
    return out;
}

/* Split callback text into lines of tab-separated, unescaped fields. */
static std::vector<std::vector<std::string>> parse_lines(const char* text) {
    std::vector<std::vector<std::string>> lines;
    std::string all = text ? text : "";
    size_t start = 0;
    while (start < all.size()) {
        size_t nl = all.find('\n', start);
        if (nl == std::string::npos) nl = all.size();
        std::string line = all.substr(start, nl - start);
        start = nl + 1;
        if (line.empty()) continue;
        std::vector<std::string> fields;
        size_t fstart = 0;
        for (;;) {
            size_t tab = line.find('\t', fstart);
            fields.push_back(unescape_field(line.substr(fstart, tab == std::string::npos ? std::string::npos : tab - fstart)));
            if (tab == std::string::npos) break;
            fstart = tab + 1;
        }
        lines.push_back(std::move(fields));
    }
    return lines;
}

static std::vector<std::string> split_csv(const char* text) {
    std::vector<std::string> out;
    if (!text) return out;
    std::string all = text;
    size_t start = 0;
    while (start <= all.size()) {
        size_t comma = all.find(',', start);
        if (comma == std::string::npos) comma = all.size();
        std::string item = all.substr(start, comma - start);
        if (!item.empty()) out.push_back(item);
        start = comma + 1;
    }
    return out;
}

/* Parallel C arrays for a std::map, valid while `keys`/`vals` live. */
struct CStringPairs {
    std::vector<const char*> keys;
    std::vector<const char*> vals;
    explicit CStringPairs(const std::map<std::string, std::string>& m) {
        for (auto& [k, v] : m) {
            keys.push_back(k.c_str());
            vals.push_back(v.c_str());
        }
    }
    const char* const* names() const { return keys.empty() ? nullptr : keys.data(); }
    const char* const* values() const { return vals.empty() ? nullptr : vals.data(); }
    size_t count() const { return keys.size(); }
};

static usp::UspError callback_error(const UspServiceError& err, uint32_t fallback) {
    return usp::UspError::agent_rejected(err.code ? err.code : fallback, err.msg);
}

static usp::ServiceHandlers make_handlers(UspServiceHandle* h) {
    usp::ServiceHandlers out;
    const UspServiceCallbacks cb = h->callbacks;

    if (cb.get) {
        out.get = [cb](const std::string& path) -> std::optional<std::map<std::string, std::string>> {
            std::vector<char> buf(SERVICE_CALLBACK_BUFFER, '\0');
            if (cb.get(cb.user_data, path.c_str(), buf.data(), buf.size()) != USP_OK) return std::nullopt;
            std::map<std::string, std::string> values;
            for (auto& fields : parse_lines(buf.data()))
                if (fields.size() >= 3 && fields[0] == "PARAM") values[fields[1]] = fields[2];
            return values;
        };
    }
    if (cb.instances) {
        out.instances = [cb](const std::string& table) {
            std::vector<usp::proto::CurrInstance> instances;
            std::vector<char> buf(SERVICE_CALLBACK_BUFFER, '\0');
            if (cb.instances(cb.user_data, table.c_str(), buf.data(), buf.size()) != USP_OK) return instances;
            for (auto& fields : parse_lines(buf.data())) {
                if (fields.size() >= 2 && fields[0] == "INSTANCE") {
                    instances.push_back({fields[1], {}});
                } else if (fields.size() >= 4 && fields[0] == "KEY") {
                    for (auto& instance : instances)
                        if (instance.instantiated_obj_path == fields[1]) instance.unique_keys[fields[2]] = fields[3];
                }
            }
            return instances;
        };
    }
    if (cb.set) {
        out.set = [cb](const std::string& path, const std::map<std::string, std::string>& params)
            -> std::optional<usp::ParamErrors> {
            CStringPairs pairs(params);
            std::vector<char> buf(SERVICE_CALLBACK_BUFFER, '\0');
            if (cb.set(cb.user_data, path.c_str(), pairs.names(), pairs.values(), pairs.count(),
                       buf.data(), buf.size()) != USP_OK) return std::nullopt;
            usp::ParamErrors errors;
            for (auto& fields : parse_lines(buf.data()))
                if (fields.size() >= 4 && fields[0] == "ERROR")
                    errors.push_back({fields[1], static_cast<uint32_t>(std::strtoul(fields[2].c_str(), nullptr, 10)), fields[3]});
            return errors;
        };
    }
    if (cb.add) {
        out.add = [cb](const std::string& table, const std::map<std::string, std::string>& params)
            -> usp::UspResult<usp::AddResponse> {
            CStringPairs pairs(params);
            std::vector<char> buf(SERVICE_CALLBACK_BUFFER, '\0');
            UspServiceError err{};
            if (cb.add(cb.user_data, table.c_str(), pairs.names(), pairs.values(), pairs.count(),
                       buf.data(), buf.size(), &err) != USP_OK) return callback_error(err, 7017);
            usp::AddResponse resp;
            for (auto& fields : parse_lines(buf.data())) {
                if (fields.size() >= 2 && fields[0] == "INSTANCE") resp.instantiated_path = fields[1];
                else if (fields.size() >= 3 && fields[0] == "KEY") resp.unique_keys[fields[1]] = fields[2];
            }
            if (resp.instantiated_path.empty())
                return usp::UspError::agent_rejected(7017, "add callback returned no INSTANCE line");
            return resp;
        };
    }
    if (cb.del) {
        out.del = [cb](const std::string& path) -> std::optional<usp::UspError> {
            UspServiceError err{};
            if (cb.del(cb.user_data, path.c_str(), &err) != USP_OK) return callback_error(err, 7024);
            return std::nullopt;
        };
    }
    if (cb.operate) {
        out.operate = [cb](const std::string& path, const std::string& command,
                           const std::map<std::string, std::string>& input)
            -> usp::UspResult<std::map<std::string, std::string>> {
            CStringPairs pairs(input);
            std::vector<char> buf(SERVICE_CALLBACK_BUFFER, '\0');
            UspServiceError err{};
            if (cb.operate(cb.user_data, path.c_str(), command.c_str(), pairs.names(), pairs.values(), pairs.count(),
                           buf.data(), buf.size(), &err) != USP_OK) return callback_error(err, 7022);
            std::map<std::string, std::string> output;
            for (auto& fields : parse_lines(buf.data()))
                if (fields.size() >= 3 && fields[0] == "OUTPUT") output[fields[1]] = fields[2];
            return output;
        };
    }
    return out;
}

static std::string format_register_results(const std::vector<usp::RegisterResult>& results) {
    std::string out;
    for (const auto& r : results) {
        if (r.ok) out += "REGISTERED\t" + escape_field(r.path) + "\n";
        else out += "ERROR\t" + escape_field(r.path) + "\t" + std::to_string(r.err_code) + "\t" + escape_field(r.err_msg) + "\n";
    }
    return out;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Exported C functions
 * ═══════════════════════════════════════════════════════════════════════════ */

extern "C" {

LIBUSP_API
UspControllerHandle* usp_controller_new(const char* socket_path,
                                         const char* app_endpoint_id,
                                         const char* agent_endpoint_id,
                                         uint64_t    timeout_secs) {
    try {
        if (!socket_path || !app_endpoint_id || !agent_endpoint_id)
            return nullptr;

        usp::UspController ctrl(socket_path, app_endpoint_id, agent_endpoint_id);
        if (timeout_secs > 0)
            ctrl.set_timeout(std::chrono::seconds(timeout_secs));

        return new UspControllerHandle(std::move(ctrl));
    } catch (...) {
        return nullptr;
    }
}

LIBUSP_API
void usp_controller_free(UspControllerHandle* handle) {
    delete handle;
}

LIBUSP_API
int usp_controller_get(UspControllerHandle* handle,
                        const char* path,
                        char*       out_value,
                        size_t      out_value_len) {
    return with_panic_boundary([&] {
        if (!handle || !path) return USP_ERR_NULL_POINTER;

        auto result = handle->controller.get(path);

        if (auto* resp = std::get_if<usp::GetResponse>(&result)) {
            const std::string* value = nullptr;

            /* Exact path match first. */
            auto it = resp->params.find(path);
            if (it != resp->params.end()) {
                value = &it->second;
            } else if (resp->params.size() == 1) {
                value = &resp->params.begin()->second;
            }

            if (!value) {
                handle->set_last_error("path not found in response: " + std::string(path));
                return USP_ERR_NOT_FOUND;
            }

            if (int rc = write_c_string(*value, out_value, out_value_len); rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

static int get_many_impl(UspControllerHandle* handle,
                             const char* const*   paths,
                             size_t               path_count,
                             uint32_t             max_depth,
                             char*                out_result,
                             size_t               out_result_len) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;

        std::vector<std::string> path_vec;
        if (int rc = cstr_array_to_vec(paths, path_count, path_vec); rc != USP_OK) return rc;
        if (path_vec.empty()) return USP_ERR_INVALID_ARGUMENT;

        auto result = handle->controller.get_many(path_vec, max_depth);

        if (auto* resp = std::get_if<usp::GetResponse>(&result)) {
            std::string encoded = format_get_response(*resp);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len);
                rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}


LIBUSP_API
int usp_controller_get_many(UspControllerHandle* handle,
                             const char* const*   paths,
                             size_t               path_count,
                             char*                out_result,
                             size_t               out_result_len) {
    return get_many_impl(handle, paths, path_count, 0, out_result, out_result_len);
}

LIBUSP_API
int usp_controller_get_many_depth(UspControllerHandle* handle,
                                   const char* const*   paths,
                                   size_t               path_count,
                                   uint32_t             max_depth,
                                   char*                out_result,
                                   size_t               out_result_len) {
    return get_many_impl(handle, paths, path_count, max_depth, out_result, out_result_len);
}

LIBUSP_API
int usp_controller_set(UspControllerHandle* handle,
                        const char* path,
                        const char* value) {
    return with_panic_boundary([&] {
        if (!handle || !path || !value) return USP_ERR_NULL_POINTER;

        auto result = handle->controller.set(path, value);

        if (std::holds_alternative<usp::SetResponse>(result)) return USP_OK;

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_set_many(UspControllerHandle* handle,
                             const char* const*   paths,
                             const char* const*   values,
                             size_t               param_count,
                             char*                out_result,
                             size_t               out_result_len) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;

        std::vector<std::pair<std::string,std::string>> params;
        if (int rc = cstr_pairs_to_vec(paths, values, param_count, params); rc != USP_OK) return rc;
        if (params.empty()) return USP_ERR_INVALID_ARGUMENT;

        auto result = handle->controller.set_many(params);

        if (auto* resp = std::get_if<usp::SetResponse>(&result)) {
            std::string encoded = format_set_response(*resp);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len);
                rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_operate(UspControllerHandle* handle,
                            const char*          command,
                            const char* const*   arg_names,
                            const char* const*   arg_values,
                            size_t               arg_count,
                            char*                out_result,
                            size_t               out_result_len) {
    return with_panic_boundary([&] {
        if (!handle || !command) return USP_ERR_NULL_POINTER;

        std::vector<std::pair<std::string,std::string>> args;
        if (int rc = cstr_pairs_to_vec(arg_names, arg_values, arg_count, args); rc != USP_OK)
            return rc;

        auto result = handle->controller.operate(command, args);

        if (auto* resp = std::get_if<usp::OperateResponse>(&result)) {
            std::string encoded = format_operate_response(*resp);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len);
                rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_subscribe_and_get(UspControllerHandle*   handle,
                                      const char*            path,
                                      int                    notification_type,
                                      UspNotificationCallback callback,
                                      void*                  user_data,
                                      char*                  out_result,
                                      size_t                 out_result_len) {
    return with_panic_boundary([&] {
        if (!handle || !path) return USP_ERR_NULL_POINTER;

        int notif_err = USP_OK;
        auto notif_type = notif_type_from_int(notification_type, notif_err);
        if (notif_err != USP_OK) return notif_err;

        UspNotificationCallback cb_copy = callback;
        void* ud_copy = user_data;
        std::function<void()> cb_fn;
        if (cb_copy) {
            cb_fn = [cb_copy, ud_copy]() { cb_copy(ud_copy); };
        }

        auto result = handle->controller.subscribe_and_get(path, notif_type, std::move(cb_fn));

        if (auto* resp = std::get_if<usp::GetResponse>(&result)) {
            std::string encoded = format_get_response(*resp);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len);
                rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_subscribe_many_and_get(UspControllerHandle*    handle,
                                           const char* const*      paths,
                                           const int*              notification_types,
                                           size_t                  subscription_count,
                                           UspNotificationCallback callback,
                                           void*                   user_data,
                                           char*                   out_result,
                                           size_t                  out_result_len) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;
        if (subscription_count == 0) return USP_ERR_INVALID_ARGUMENT;
        if (!paths || !notification_types) return USP_ERR_NULL_POINTER;

        std::vector<std::pair<std::string, usp::SubscriptionNotificationType>> subs;
        for (size_t i = 0; i < subscription_count; ++i) {
            if (!paths[i]) return USP_ERR_NULL_POINTER;
            int notif_err = USP_OK;
            auto nt = notif_type_from_int(notification_types[i], notif_err);
            if (notif_err != USP_OK) return notif_err;
            subs.emplace_back(paths[i], nt);
        }

        UspNotificationCallback cb_copy = callback;
        void* ud_copy = user_data;
        std::function<void()> cb_fn;
        if (cb_copy) {
            cb_fn = [cb_copy, ud_copy]() { cb_copy(ud_copy); };
        }

        auto result = handle->controller.subscribe_many_and_get(subs, std::move(cb_fn));

        if (auto* resp = std::get_if<usp::GetResponse>(&result)) {
            std::string encoded = format_get_response(*resp);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len);
                rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_register(UspControllerHandle* handle, const char* obj) {
    return with_panic_boundary([&] {
        if (!handle || !obj) return USP_ERR_NULL_POINTER;
        auto err = handle->controller.register_obj(obj);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_add(UspControllerHandle* handle,
                        const char*          obj,
                        const char* const*   param_paths,
                        const char* const*   param_values,
                        size_t               param_count,
                        char*                out_result,
                        size_t               out_result_len) {
    return with_panic_boundary([&] {
        if (!handle || !obj) return USP_ERR_NULL_POINTER;
        std::vector<std::pair<std::string,std::string>> params;
        if (int rc = cstr_pairs_to_vec(param_paths, param_values, param_count, params);
            rc != USP_OK) return rc;

        auto result = handle->controller.add(obj, params);

        if (auto* resp = std::get_if<usp::AddResponse>(&result)) {
            std::string encoded = format_add_response(*resp);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len);
                rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_delete(UspControllerHandle* handle,
                           const char*          instance,
                           char*                out_result,
                           size_t               out_result_len) {
    return with_panic_boundary([&] {
        if (!handle || !instance) return USP_ERR_NULL_POINTER;

        auto result = handle->controller.delete_instance(instance);

        if (auto* resp = std::get_if<usp::DeleteResponse>(&result)) {
            std::string encoded = format_delete_response(*resp);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len);
                rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_get_supported_dm(UspControllerHandle* handle,
                                     const char*          obj,
                                     int                  first_level_only,
                                     char*                out_result,
                                     size_t               out_result_len) {
    return with_panic_boundary([&] {
        if (!handle || !obj) return USP_ERR_NULL_POINTER;

        auto result = handle->controller.get_supported_dm(obj, first_level_only != 0);

        if (auto* resp = std::get_if<usp::SupportedDMResponse>(&result)) {
            std::string encoded = format_supported_dm_response(*resp);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len);
                rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_get_instances(UspControllerHandle* handle,
                                  const char*          obj,
                                  int                  first_level_only,
                                  char*                out_result,
                                  size_t               out_result_len) {
    return with_panic_boundary([&] {
        if (!handle || !obj) return USP_ERR_NULL_POINTER;

        auto result = handle->controller.get_instances(obj, first_level_only != 0);

        if (auto* resp = std::get_if<usp::InstancesResponse>(&result)) {
            std::string encoded = format_instances_response(*resp);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len);
                rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_get_supported_protocol(UspControllerHandle* handle,
                                           char*                out_versions,
                                           size_t               out_versions_len) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;

        auto result = handle->controller.get_supported_protocol();

        if (auto* versions = std::get_if<std::string>(&result)) {
            if (int rc = write_c_string(*versions, out_versions, out_versions_len); rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_set_password(UspControllerHandle* handle,
                                const char*          password) {
    return with_panic_boundary([&] {
        if (!handle || !password) return USP_ERR_NULL_POINTER;
        handle->controller.set_password(password);
        return USP_OK;
    });
}

LIBUSP_API
int usp_controller_set_timeout(UspControllerHandle* handle, uint64_t timeout_secs) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;
        handle->controller.set_timeout(
            std::chrono::seconds(timeout_secs > 0 ? timeout_secs : 10));
        return USP_OK;
    });
}

LIBUSP_API
int usp_error_is_vendor_defined(uint32_t code) {
    return (code >= 7800u && code <= 7999u) ? 1 : 0;
}

LIBUSP_API
int usp_controller_last_error(const UspControllerHandle* handle,
                               char*  out_error,
                               size_t out_error_len) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;
        auto msg = handle->get_last_error();
        return write_c_string(msg, out_error, out_error_len);
    });
}

/* ══════════════════════════════════════════════════════════════════════════
 * USP Service API
 * ══════════════════════════════════════════════════════════════════════════ */

LIBUSP_API
UspServiceHandle* usp_service_new(const char* socket_path,
                                  const char* endpoint_id,
                                  const char* broker_endpoint_id,
                                  uint64_t    timeout_secs) {
    try {
        if (!socket_path || !endpoint_id || !broker_endpoint_id)
            return nullptr;

        auto* handle = new UspServiceHandle(socket_path, endpoint_id, broker_endpoint_id);
        if (timeout_secs > 0)
            handle->service.set_timeout(std::chrono::seconds(timeout_secs));
        return handle;
    } catch (...) {
        return nullptr;
    }
}

LIBUSP_API
void usp_service_free(UspServiceHandle* handle) {
    delete handle;
}

LIBUSP_API
int usp_service_set_password(UspServiceHandle* handle, const char* password) {
    return with_panic_boundary([&] {
        if (!handle || !password) return USP_ERR_NULL_POINTER;
        handle->service.set_password(password);
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_add_object(UspServiceHandle* handle, const char* path, int multi_instance,
                           int access, const char* unique_keys) {
    return with_panic_boundary([&] {
        if (!handle || !path) return USP_ERR_NULL_POINTER;
        if (access < USP_OBJ_ACCESS_READ_ONLY || access > USP_OBJ_ACCESS_DELETE_ONLY) return USP_ERR_INVALID_ARGUMENT;
        usp::ServiceObject object;
        object.path           = path;
        object.multi_instance = multi_instance != 0;
        object.access         = static_cast<usp::proto::ObjAccessType>(access);
        object.unique_keys    = split_csv(unique_keys);
        handle->objects.push_back(std::move(object));
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_add_param(UspServiceHandle* handle, const char* obj_path, const char* name,
                          int access, int value_type) {
    return with_panic_boundary([&] {
        if (!handle || !obj_path || !name) return USP_ERR_NULL_POINTER;
        if (access < USP_PARAM_ACCESS_READ_ONLY || access > USP_PARAM_ACCESS_WRITE_ONLY) return USP_ERR_INVALID_ARGUMENT;
        if (value_type < USP_PARAM_TYPE_UNKNOWN || value_type > USP_PARAM_TYPE_UNSIGNED_LONG) return USP_ERR_INVALID_ARGUMENT;
        auto* object = handle->find_object(obj_path);
        if (!object) return USP_ERR_NOT_FOUND;
        object->params.push_back({name, static_cast<usp::proto::ParamAccessType>(access),
                                  static_cast<usp::proto::ParamValueType>(value_type)});
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_add_command(UspServiceHandle* handle, const char* obj_path, const char* name,
                            const char* input_args, const char* output_args, int async) {
    return with_panic_boundary([&] {
        if (!handle || !obj_path || !name) return USP_ERR_NULL_POINTER;
        auto* object = handle->find_object(obj_path);
        if (!object) return USP_ERR_NOT_FOUND;
        object->commands.push_back({name, split_csv(input_args), split_csv(output_args), async != 0});
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_add_event(UspServiceHandle* handle, const char* obj_path, const char* name,
                          const char* args) {
    return with_panic_boundary([&] {
        if (!handle || !obj_path || !name) return USP_ERR_NULL_POINTER;
        auto* object = handle->find_object(obj_path);
        if (!object) return USP_ERR_NOT_FOUND;
        object->events.push_back({name, split_csv(args)});
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_set_callbacks(UspServiceHandle* handle, const UspServiceCallbacks* callbacks) {
    return with_panic_boundary([&] {
        if (!handle || !callbacks) return USP_ERR_NULL_POINTER;
        handle->callbacks = *callbacks;
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_start(UspServiceHandle* handle, const char* const* roots, size_t root_count,
                      int allow_partial, char* out_result, size_t out_result_len) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;
        std::vector<std::string> root_vec;
        if (int rc = cstr_array_to_vec(roots, root_count, root_vec); rc != USP_OK) return rc;
        if (root_vec.empty()) return USP_ERR_INVALID_ARGUMENT;

        if (!handle->described) {
            for (const auto& object : handle->objects)
                handle->service.add_object(object);
            handle->described = true;
        }
        handle->service.set_handlers(make_handlers(handle));

        auto result = handle->service.start(root_vec, allow_partial != 0);

        if (auto* results = std::get_if<std::vector<usp::RegisterResult>>(&result)) {
            std::string encoded = format_register_results(*results);
            if (int rc = write_optional_c_string(encoded, out_result, out_result_len); rc != USP_OK) {
                handle->set_last_error("output buffer too small or invalid");
                return rc;
            }
            return USP_OK;
        }

        auto& err = std::get<usp::UspError>(result);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_service_stop(UspServiceHandle* handle) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;
        handle->service.stop();
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_running(const UspServiceHandle* handle) {
    try {
        return handle && handle->service.running() ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

LIBUSP_API
int usp_service_broker_endpoint_id(const UspServiceHandle* handle, char* out, size_t out_len) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;
        return write_c_string(handle->service.broker_endpoint_id(), out, out_len);
    });
}

LIBUSP_API
int usp_service_value_changed(UspServiceHandle* handle, const char* param_path, const char* value) {
    return with_panic_boundary([&] {
        if (!handle || !param_path || !value) return USP_ERR_NULL_POINTER;
        handle->service.value_changed(param_path, value);
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_object_created(UspServiceHandle* handle, const char* obj_path,
                               const char* const* key_names, const char* const* key_values, size_t count) {
    return with_panic_boundary([&] {
        if (!handle || !obj_path) return USP_ERR_NULL_POINTER;
        std::vector<std::pair<std::string, std::string>> pairs;
        if (int rc = cstr_pairs_to_vec(key_names, key_values, count, pairs); rc != USP_OK) return rc;
        std::map<std::string, std::string> keys(pairs.begin(), pairs.end());
        handle->service.object_created(obj_path, keys);
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_object_deleted(UspServiceHandle* handle, const char* obj_path) {
    return with_panic_boundary([&] {
        if (!handle || !obj_path) return USP_ERR_NULL_POINTER;
        handle->service.object_deleted(obj_path);
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_event(UspServiceHandle* handle, const char* obj_path, const char* event_name,
                      const char* const* names, const char* const* values, size_t count) {
    return with_panic_boundary([&] {
        if (!handle || !obj_path || !event_name) return USP_ERR_NULL_POINTER;
        std::vector<std::pair<std::string, std::string>> pairs;
        if (int rc = cstr_pairs_to_vec(names, values, count, pairs); rc != USP_OK) return rc;
        std::map<std::string, std::string> params(pairs.begin(), pairs.end());
        handle->service.event(obj_path, event_name, params);
        return USP_OK;
    });
}

LIBUSP_API
int usp_service_last_error(const UspServiceHandle* handle, char* out_error, size_t out_error_len) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;
        return write_c_string(handle->get_last_error(), out_error, out_error_len);
    });
}

} /* extern "C" */
