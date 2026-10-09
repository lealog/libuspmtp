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

#include <cassert>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>

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
                        size_t               param_count) {
    return with_panic_boundary([&] {
        if (!handle || !obj) return USP_ERR_NULL_POINTER;
        std::vector<std::pair<std::string,std::string>> params;
        if (int rc = cstr_pairs_to_vec(param_paths, param_values, param_count, params);
            rc != USP_OK) return rc;
        auto err = handle->controller.add(obj, params);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_delete(UspControllerHandle* handle, const char* instance) {
    return with_panic_boundary([&] {
        if (!handle || !instance) return USP_ERR_NULL_POINTER;
        auto err = handle->controller.delete_instance(instance);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_get_supported_dm(UspControllerHandle* handle, const char* obj) {
    return with_panic_boundary([&] {
        if (!handle || !obj) return USP_ERR_NULL_POINTER;
        auto err = handle->controller.get_supported_dm(obj);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_get_instances(UspControllerHandle* handle, const char* obj) {
    return with_panic_boundary([&] {
        if (!handle || !obj) return USP_ERR_NULL_POINTER;
        auto err = handle->controller.get_instances(obj);
        handle->set_last_error(err.to_string());
        return USP_ERR_USP;
    });
}

LIBUSP_API
int usp_controller_get_supported_protocol(UspControllerHandle* handle) {
    return with_panic_boundary([&] {
        if (!handle) return USP_ERR_NULL_POINTER;
        auto err = handle->controller.get_supported_protocol();
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

} /* extern "C" */
