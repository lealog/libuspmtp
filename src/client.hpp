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
 * client.hpp
 *
 * UspController — USP (TR-369) client that communicates with OB-USPA over a
 * UNIX domain socket.
 *
 * UspController is cheap to copy: all copies share the same underlying
 * connection via a shared_ptr to the session state.
 *
 * Thread-safety: all public methods are internally serialised.  A single
 * session background worker thread owns the socket connection.
 */

#pragma once

#include "transport.hpp"
#include "usp_proto.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace usp {

/* ── Public error type ───────────────────────────────────────────────────── */

/**
 * USP-level error returned by UspController operations.
 */
class UspError {
public:
    enum class Kind {
        Timeout,
        Protocol,
        ConnectionFailed,
        AgentRejected,   ///< Agent returned a USP error body.
        NotImplemented,
    };

    static UspError timeout()
    { return UspError(Kind::Timeout, "timeout"); }

    static UspError protocol(std::string msg)
    { return UspError(Kind::Protocol, std::move(msg)); }

    static UspError connection_failed(std::string msg)
    { return UspError(Kind::ConnectionFailed, std::move(msg)); }

    static UspError agent_rejected(uint32_t code, std::string msg)
    { UspError e(Kind::AgentRejected, std::move(msg)); e.code_ = code; return e; }

    static UspError not_implemented(std::string what)
    { return UspError(Kind::NotImplemented, "Not yet implemented: " + std::move(what)); }

    static UspError from_transport(const TransportError& te) {
        switch (te.kind()) {
        case TransportError::Kind::Timeout:
            return timeout();
        case TransportError::Kind::ConnectionFailed:
        case TransportError::Kind::Io: /* peer closed / broken pipe: reconnect, do not treat as a bad frame */
            return connection_failed(te.message());
        default:
            return protocol(te.to_string());
        }
    }

    Kind               kind()    const noexcept { return kind_; }
    const std::string& message() const noexcept { return message_; }
    uint32_t           code()    const noexcept { return code_; }

    bool is_recoverable() const noexcept {
        return kind_ == Kind::ConnectionFailed || kind_ == Kind::Timeout;
    }

    std::string to_string() const {
        switch (kind_) {
        case Kind::Timeout:          return "timeout";
        case Kind::ConnectionFailed: return "connection failed: " + message_;
        case Kind::Protocol:         return "protocol error: " + message_;
        case Kind::AgentRejected:
            return "USP agent error " + std::to_string(code_) + ": " + message_;
        case Kind::NotImplemented:   return message_;
        }
        return message_;
    }

private:
    UspError(Kind k, std::string m)
        : kind_(k), message_(std::move(m)), code_(0) {}

    Kind        kind_;
    std::string message_;
    uint32_t    code_;
};

/* ── Response types ─────────────────────────────────────────────────────── */

/** A per-path error returned inside GET or SET responses. */
struct PathError {
    std::string path;
    uint32_t    err_code{0};
    std::string err_msg;
};

/** Response returned by get() / get_many(). */
struct GetResponse {
    std::map<std::string, std::string> params;
    std::vector<PathError>             errors;
};

/** Response returned by set() / set_many(). */
struct SetResponse {
    std::vector<std::string> updated;
    std::vector<PathError>   errors;
};

/** Response returned by operate(). */
struct OperateResponse {
    std::map<std::string, std::string> output_args;
};

/* ── Result type ────────────────────────────────────────────────────────── */

template<typename T>
using UspResult = std::variant<T, UspError>;

/* ── Subscription type ──────────────────────────────────────────────────── */

enum class SubscriptionNotificationType {
    ValueChange,
    ObjectCreation,
    ObjectDeletion,
};

/* ── UspController ──────────────────────────────────────────────────────── */

/**
 * USP (TR-369) controller client.
 *
 * The connection to the agent is established lazily on the first request.
 * If the connection is lost it is re-established automatically on the next
 * request.
 *
 * UspController is cheap to copy — all copies share the same underlying
 * connection.
 */
class UspController {
public:
    /**
     * Construct a USP controller.
     *
     * @param socket_path       Filesystem path of the OB-USPA UNIX domain socket.
     * @param app_endpoint_id   USP endpoint ID of this application (from_id).
     * @param agent_endpoint_id USP endpoint ID of the agent (to_id). Empty means
     *                          use the ID the agent reports in the UDS handshake.
     */
    UspController(std::string socket_path,
                  std::string app_endpoint_id,
                  std::string agent_endpoint_id);

    /** Set the per-request timeout (default: 10 seconds). */
    void set_timeout(std::chrono::seconds timeout);

    /** Current per-request timeout. */
    std::chrono::seconds timeout() const;

    /* ── GET ─────────────────────────────────────────────────────────── */

    UspResult<GetResponse> get(const std::string& path);
    UspResult<GetResponse> get_many(const std::vector<std::string>& paths,
                                    uint32_t max_depth = 0);

    /* ── SET ─────────────────────────────────────────────────────────── */

    UspResult<SetResponse> set(const std::string& path, const std::string& value);
    UspResult<SetResponse> set_many(const std::vector<std::pair<std::string,std::string>>& params);

    /* ── OPERATE ─────────────────────────────────────────────────────── */

    UspResult<OperateResponse> operate(
        const std::string& command,
        const std::vector<std::pair<std::string,std::string>>& args);

    /* ── Subscribe + GET ─────────────────────────────────────────────── */

    UspResult<GetResponse> subscribe_and_get(
        const std::string& path,
        SubscriptionNotificationType notif_type,
        std::function<void()> callback);

    UspResult<GetResponse> subscribe_many_and_get(
        const std::vector<std::pair<std::string, SubscriptionNotificationType>>& subs,
        std::function<void()> callback);

    /* ── Not-yet-implemented stubs ───────────────────────────────────── */

    UspError register_obj(const std::string& obj);
    UspError add(const std::string& obj,
                 const std::vector<std::pair<std::string,std::string>>& params);
    UspError delete_instance(const std::string& instance);
    UspError get_supported_dm(const std::string& obj);
    UspError get_instances(const std::string& obj);
    UspError get_supported_protocol();

    /* ── Session worker command/reply types (public for free-function access) */

    struct RequestCmd {
        proto::Record                               record;
        std::promise<UspResult<proto::Record>>      reply;
    };

    struct SubscribeCmd {
        /* (sub_id, notif_type_str, path) triples */
        std::vector<std::tuple<std::string,std::string,std::string>> subscriptions;
        std::function<void()>                    callback;
        std::promise<std::optional<UspError>>    reply;
    };

    using WorkerCommand = std::variant<RequestCmd, SubscribeCmd>;

    /* ── Session handle (shared across copies) ─────────────────────────── */

    /* Self-pipe used to wake the session worker the moment a command is queued. */
    struct WakePipe {
        int rd{-1};
        int wr{-1};
        WakePipe() = default;
        WakePipe(const WakePipe&) = delete;
        WakePipe& operator=(const WakePipe&) = delete;
        ~WakePipe();
        bool open() noexcept;
        void wake() noexcept;
    };

    struct SessionState {
        std::queue<WorkerCommand> commands;
        std::mutex                cmd_mutex;
        bool                      dead{false}; /* guarded by cmd_mutex; set when the worker has exited */
        WakePipe                  wake_pipe;   /* declared before `worker`: destroyed (closed) only after it is joined */
        std::jthread              worker;

        void wake() noexcept { wake_pipe.wake(); }
        ~SessionState(); /* join happens in jthread destructor */
    };

private:

    /* ── Internal helpers ─────────────────────────────────────────────── */

    UspResult<proto::Record> round_trip(proto::Record record);
    std::optional<UspError>  do_subscribe(
        const std::vector<std::tuple<std::string,std::string,std::string>>& subs,
        std::function<void()> callback);

    /** Ensure a session worker is running; create one if not. */
    std::shared_ptr<SessionState> ensure_session();
    void clear_session();

    proto::Record build_record(proto::MsgType msg_type, proto::Body body) const;

    static std::string notif_type_str(SubscriptionNotificationType t);

    /* ── Fields ────────────────────────────────────────────────────────── */

    std::string          socket_path_;
    std::string          endpoint_id_;
    std::string          agent_endpoint_id_;
    std::chrono::seconds timeout_{10};

    /* Shared session state across all copies. */
    std::shared_ptr<std::mutex>                     session_mutex_;
    std::shared_ptr<std::optional<std::shared_ptr<SessionState>>> session_;
};

} // namespace usp
