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
 * client.cpp
 *
 * UspController implementation.
 *
 * Session worker design:
 *
 *   The worker thread loops indefinitely:
 *
 *     1. Non-blocking check for a pending command.
 *     2. If a command is present:
 *          – Execute it (send record, wait for non-Notify response with timeout).
 *          – Fulfill the caller's promise.
 *     3. Otherwise: call transport.recv() (1-second socket timeout).
 *          – Timeout → continue loop (check stop token).
 *          – Notify record → send NotifyResp (if requested), fire all callbacks.
 *          – Other record → log; continue.
 *          – Hard I/O error → stop worker.
 */

#include "client.hpp"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <iostream>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <map>
#include <set>
#include <string>
#include <tuple>

namespace usp {

/* ── Global message counter ─────────────────────────────────────────────── */

static std::atomic<uint64_t> g_msg_counter{1};

static std::string next_msg_id() {
    return std::to_string(g_msg_counter.fetch_add(1, std::memory_order_relaxed));
}

/* ── Protocol version ───────────────────────────────────────────────────── */

static constexpr std::chrono::seconds SESSION_IO_TIMEOUT{1};
static constexpr std::chrono::seconds DEFAULT_TIMEOUT{10};

/* ═══════════════════════════════════════════════════════════════════════════
 * Session worker function (runs inside SessionState::worker jthread)
 * ═══════════════════════════════════════════════════════════════════════════ */

namespace {

/* Forward declarations */
static std::optional<UspError>
handle_notification_record(Transport& transport,
                            const proto::Record& record,
                            const std::string& endpoint_id,
                            const std::string& agent_endpoint_id,
                            const std::vector<std::function<void()>>& callbacks);

static std::variant<proto::Record, UspError>
wait_for_non_notify(Transport& transport,
                    std::chrono::seconds timeout,
                    const std::string& endpoint_id,
                    const std::string& agent_endpoint_id,
                    std::vector<std::function<void()>>& callbacks);

/* Build a USP Record wrapping an inner Msg. */
static proto::Record build_record_fn(const std::string& from_id,
                                     const std::string& to_id,
                                     proto::MsgType msg_type,
                                     proto::Body body)
{
    proto::Msg msg;
    msg.header = proto::Header{next_msg_id(), msg_type};
    msg.body   = std::move(body);

    proto::NoSessionContextRecord nsc;
    nsc.payload = msg.encode();

    proto::Record rec;
    rec.version         = "1.5";
    rec.to_id           = to_id;
    rec.from_id         = from_id;
    rec.payload_security = 0; /* Plaintext */
    rec.record_type     = std::move(nsc);
    return rec;
}

/* Extract inner Msg from a NoSessionContextRecord. */
static std::variant<proto::Msg, UspError> extract_msg(const proto::Record& record) {
    const auto* nsc = std::get_if<proto::NoSessionContextRecord>(&record.record_type);
    if (!nsc)
        return UspError::protocol("expected NoSessionContextRecord in response");

    auto msg = proto::Msg::decode(nsc->payload);
    if (!msg)
        return UspError::protocol("failed to decode inner Msg");

    return std::move(*msg);
}

/* Check if this record contains a Notify, return it if so. */
static std::optional<proto::Notify> extract_notify(const proto::Record& record) {
    auto msg_var = extract_msg(record);
    if (std::holds_alternative<UspError>(msg_var)) return std::nullopt;

    auto& msg = std::get<proto::Msg>(msg_var);
    if (!msg.body) return std::nullopt;

    auto* req = std::get_if<proto::Request>(&msg.body->msg_body);
    if (!req) return std::nullopt;

    auto* notify = std::get_if<proto::Notify>(&req->req_type);
    if (!notify) return std::nullopt;

    return *notify;
}

/* True if an ADD result indicates the subscription was already registered,
 * which is not a failure: the subscription is present either because this
 * ADD created it or because it already existed on the agent.  Success for a
 * subscription requires that it exists (newly created or pre-existing), not
 * that it was created by this specific ADD. */
static bool is_already_subscribed(const proto::AddOperationFailure& f) {
    if (f.err_code == 7025) return true; /* subscription ID already in use */
    return f.err_msg.find("already in use") != std::string::npos ||
           f.err_msg.find("already exists") != std::string::npos;
}

/* Handle an incoming record that might be a Notify.
 * Returns nullopt if the record was a Notify (handled).
 * Returns the record itself if it was not a Notify (pass back to caller). */
static std::optional<UspError>
handle_notification_record(Transport& transport,
                            const proto::Record& record,
                            const std::string& endpoint_id,
                            const std::string& agent_endpoint_id,
                            const std::vector<std::function<void()>>& callbacks)
{
    auto notify_opt = extract_notify(record);
    if (!notify_opt) return std::nullopt; /* Not a notify – caller handles it */

    const auto& notify = *notify_opt;

    if (notify.send_resp) {
        proto::NotifyResp nr;
        nr.subscription_id = notify.subscription_id;

        proto::Response resp;
        resp.resp_type = std::move(nr);

        proto::Body body;
        body.msg_body = std::move(resp);

        auto resp_record = build_record_fn(endpoint_id, agent_endpoint_id,
                                           proto::MsgType::NotifyResp,
                                           std::move(body));
        transport.send(resp_record);
    }

    /* Fire all notification callbacks. */
    for (const auto& cb : callbacks) {
        if (cb) cb();
    }

    return std::nullopt;
}

/* Wait for the first non-Notify record; handle any Notify records inline. */
static std::variant<proto::Record, UspError>
wait_for_non_notify(Transport& transport,
                    std::chrono::seconds timeout,
                    const std::string& endpoint_id,
                    const std::string& agent_endpoint_id,
                    std::vector<std::function<void()>>& callbacks)
{
    auto deadline = std::chrono::steady_clock::now() + timeout;

    for (;;) {
        auto result = transport.recv();

        if (auto* rec = std::get_if<proto::Record>(&result)) {
            /* Check if it's a Notify. */
            auto notify_opt = extract_notify(*rec);
            if (notify_opt) {
                /* Handle it and continue waiting. */
                handle_notification_record(transport, *rec,
                                           endpoint_id, agent_endpoint_id,
                                           callbacks);
                continue;
            }
            /* Non-notify response: return to caller. */
            return std::move(*rec);
        }

        auto& err = std::get<TransportError>(result);
        if (err.is_timeout()) {
            if (std::chrono::steady_clock::now() >= deadline)
                return UspError::timeout();
            continue;
        }
        return UspError::from_transport(err);
    }
}

/* ── Worker function ──────────────────────────────────────────────────────── */

void session_worker(std::stop_token stop_token,
                    Transport transport_in,
                    UspController::SessionState* state_ptr,
                    std::chrono::seconds timeout,
                    std::string endpoint_id,
                    std::string agent_endpoint_id)
{
    Transport transport = std::move(transport_in);
    std::vector<std::function<void()>> notify_callbacks;
    std::stop_callback wake_on_stop(stop_token, [state_ptr] { state_ptr->wake(); });

    /* Whatever way the worker exits, mark the session dead and fail anything still queued, so a caller
     * never waits on a future that no thread will ever fulfil. */
    struct DeadSessionGuard {
        UspController::SessionState* s;
        ~DeadSessionGuard() {
            std::unique_lock lk(s->cmd_mutex);
            s->dead = true;
            const auto err = UspError::connection_failed("USP session closed");
            while (!s->commands.empty()) {
                auto c = std::move(s->commands.front());
                s->commands.pop();
                if (auto* r = std::get_if<UspController::RequestCmd>(&c))
                    r->reply.set_value(err);
                else if (auto* sc = std::get_if<UspController::SubscribeCmd>(&c))
                    sc->reply.set_value(err);
            }
        }
    } dead_guard{state_ptr};

    while (!stop_token.stop_requested()) {
        /* 1. Non-blocking check for a pending command. */
        std::optional<UspController::WorkerCommand> cmd;
        {
            std::unique_lock lk(state_ptr->cmd_mutex);
            if (!state_ptr->commands.empty()) {
                cmd = std::move(state_ptr->commands.front());
                state_ptr->commands.pop();
            }
        }

        if (cmd) {
            /* 2. Process the command. */
            if (auto* req = std::get_if<UspController::RequestCmd>(&*cmd)) {
                /* Send the record, wait for a response. */
                if (auto send_err = transport.send(req->record)) {
                    req->reply.set_value(UspError::from_transport(*send_err));
                    if (send_err->is_recoverable()) return;
                } else {
                    auto resp = wait_for_non_notify(transport, timeout,
                                                   endpoint_id, agent_endpoint_id,
                                                   notify_callbacks);
                    if (auto* rec = std::get_if<proto::Record>(&resp)) {
                        req->reply.set_value(std::move(*rec));
                    } else {
                        auto& err = std::get<UspError>(resp);
                        bool recoverable = err.is_recoverable();
                        req->reply.set_value(err);
                        if (recoverable) return;
                    }
                }
            } else if (auto* sub = std::get_if<UspController::SubscribeCmd>(&*cmd)) {
                /* Build and send an ADD request for subscriptions. */
                std::vector<proto::CreateObject> create_objs;
                for (auto& [sub_id, notif_type, path] : sub->subscriptions) {
                    proto::CreateObject co;
                    co.obj_path = "Device.LocalAgent.Subscription.";
                    co.param_settings = {
                        proto::CreateParamSetting{"Enable",        "true",  true},
                        proto::CreateParamSetting{"ID",            sub_id,  true},
                        proto::CreateParamSetting{"NotifType",     notif_type, true},
                        proto::CreateParamSetting{"ReferenceList", path,    false},
                        proto::CreateParamSetting{"Persistent",    "false", false},
                    };
                    create_objs.push_back(std::move(co));
                }

                proto::Add add_msg;
                add_msg.allow_partial = true;
                add_msg.create_objs   = std::move(create_objs);

                proto::Request req_body;
                req_body.req_type = std::move(add_msg);

                proto::Body body;
                body.msg_body = std::move(req_body);

                auto add_record = build_record_fn(endpoint_id, agent_endpoint_id,
                                                  proto::MsgType::Add,
                                                  std::move(body));

                if (auto send_err = transport.send(add_record)) {
                    sub->reply.set_value(UspError::from_transport(*send_err));
                    if (send_err->is_recoverable()) return;
                } else {
                    auto resp = wait_for_non_notify(transport, timeout,
                                                   endpoint_id, agent_endpoint_id,
                                                   notify_callbacks);
                    if (auto* rec = std::get_if<proto::Record>(&resp)) {
                        /* Parse ADD response. */
                        auto msg_var = extract_msg(*rec);
                        if (auto* msg = std::get_if<proto::Msg>(&msg_var)) {
                            bool ok = false;
                            std::string err_detail;

                            if (msg->body) {
                                if (auto* resp_var = std::get_if<proto::Response>(&msg->body->msg_body)) {
                                    if (auto* ar = std::get_if<proto::AddResp>(&resp_var->resp_type)) {
                                        /* A subscription "already exists" failure is a success:
                                         * the subscription is registered whether it was created
                                         * by this ADD or previously.  Any other failure is real. */
                                        ok = true;
                                        for (auto& cor : ar->created_obj_results) {
                                            if (!cor.oper_status) continue;
                                            if (auto* f = std::get_if<proto::AddOperationFailure>(
                                                    &cor.oper_status->oper_status)) {
                                                if (is_already_subscribed(*f))
                                                    continue;
                                                ok = false;
                                                err_detail = "subscription ADD failed for '" +
                                                             cor.requested_path + "': " + f->err_msg;
                                                break;
                                            }
                                        }
                                    }
                                } else if (auto* eb = std::get_if<proto::ErrorBody>(&msg->body->msg_body)) {
                                    ok = false;
                                    err_detail = "agent error " + std::to_string(eb->err_code) +
                                                 ": " + eb->err_msg;
                                }
                            }

                            if (ok) {
                                /* Register the callback. */
                                notify_callbacks.push_back(std::move(sub->callback));
                                sub->reply.set_value(std::nullopt);
                                std::cout << "OB-USPA: subscription listener active ("
                                          << sub->subscriptions.size() << " subscription(s))\n";
                            } else {
                                sub->reply.set_value(UspError::protocol(
                                    err_detail.empty() ? "unexpected ADD response" : err_detail));
                            }
                        } else {
                            sub->reply.set_value(
                                UspError::protocol("failed to decode ADD response"));
                        }
                    } else {
                        auto& err = std::get<UspError>(resp);
                        bool recoverable = err.is_recoverable();
                        sub->reply.set_value(err);
                        if (recoverable) return;
                    }
                }
            }
            continue; /* Go back to check for more commands */
        }

        /* 3. No command: sleep until the agent sends something OR a command is queued (self-pipe), so a new request
         * starts immediately instead of waiting out a socket read timeout.  The 1 s cap only bounds how late a stop
         * request or a silently dead socket is noticed. */
        {
            pollfd fds[2];
            fds[0] = {transport.native_handle(), POLLIN, 0};
            fds[1] = {state_ptr->wake_pipe.rd, POLLIN, 0};
            int prc = ::poll(fds, 2, 1000);
            if (prc < 0) {
                if (errno == EINTR) continue;
                std::cerr << "USP: session worker stopping: poll failed\n";
                return;
            }
            if (fds[1].revents & POLLIN) {
                char drain[64];
                while (::read(state_ptr->wake_pipe.rd, drain, sizeof drain) > 0) {}
                continue; /* new command (or stop request): go back to the top */
            }
            if (prc == 0 || !(fds[0].revents & (POLLIN | POLLHUP | POLLERR)))
                continue; /* idle timeout */
        }
        auto result = transport.recv();

        if (auto* rec = std::get_if<proto::Record>(&result)) {
            auto notify_opt = extract_notify(*rec);
            if (notify_opt) {
                handle_notification_record(transport, *rec,
                                           endpoint_id, agent_endpoint_id,
                                           notify_callbacks);
            } else {
                std::cerr << "USP: unexpected record received in idle loop; ignoring.\n";
            }
        } else {
            auto* transport_err = std::get_if<TransportError>(&result);
            if (transport_err && !transport_err->is_timeout()) {
                std::cerr << "USP: session worker stopping: " << transport_err->to_string() << "\n";
                return;
            }
            /* Timeout — normal, loop again. */
        }
    }
}

/* Complete the UDS session-establishment handshake.
 *
 * Returns nullopt on success.  On failure returns a TransportError that the
 * caller (ensure_session) converts and throws.
 *
 * The agent expects a UDSConnectRecord to begin a controller session; it
 * acknowledges with its own UDSConnectRecord before it will process
 * NoSessionContext requests.  Without this handshake the agent only ever
 * responds with a UDSConnectRecord and libuspmtp would report
 * "expected NoSessionContextRecord in response". */
static std::optional<TransportError>
establish_uds_session(Transport& transport,
                      const std::string& from_id,
                      const std::string& to_id,
                      std::chrono::seconds timeout)
{
    proto::Record connect_record;
    connect_record.version           = "1.5";
    connect_record.to_id             = to_id;
    connect_record.from_id           = from_id;
    connect_record.payload_security  = 0;
    connect_record.record_type       = proto::UdsConnectRecord{};

    if (auto err = transport.send(connect_record))
        return err;

    /* Await the agent's UDSConnectRecord acknowledgement. */
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto result = transport.recv();

        if (auto* rec = std::get_if<proto::Record>(&result)) {
            if (std::holds_alternative<proto::UdsConnectRecord>(rec->record_type))
                return std::nullopt; /* Session established. */

            /* Unexpected record at handshake. */
            return TransportError::protocol(
                "expected UDSConnectRecord during session establishment");
        }

        auto& err = std::get<TransportError>(result);
        if (err.is_timeout())
            continue; /* Keep waiting until the deadline. */
        return err;
    }

    return TransportError::connection_failed(
        "no UDS Connect acknowledgement from agent (session not established)");
}

} // anonymous namespace

/* ═══════════════════════════════════════════════════════════════════════════
 * SessionState destructor
 * ═══════════════════════════════════════════════════════════════════════════ */

UspController::SessionState::~SessionState() {
    /* jthread destructor requests stop and joins automatically; wake_pipe is closed after that. */
}

UspController::WakePipe::~WakePipe() {
    if (rd >= 0) ::close(rd);
    if (wr >= 0) ::close(wr);
}

bool UspController::WakePipe::open() noexcept {
    int p[2];
    if (::pipe(p) != 0) return false;
    for (int fd : p) {
        ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    rd = p[0];
    wr = p[1];
    return true;
}

void UspController::WakePipe::wake() noexcept {
    if (wr >= 0) {
        const char b = 1;
        ssize_t r = ::write(wr, &b, 1); /* non-blocking; a full pipe already means "wake up" */
        (void)r;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * UspController
 * ═══════════════════════════════════════════════════════════════════════════ */

UspController::UspController(std::string socket_path,
                             std::string app_endpoint_id,
                             std::string agent_endpoint_id)
    : socket_path_(std::move(socket_path))
    , endpoint_id_(std::move(app_endpoint_id))
    , agent_endpoint_id_(std::move(agent_endpoint_id))
    , timeout_(DEFAULT_TIMEOUT)
    , session_mutex_(std::make_shared<std::mutex>())
    , session_(std::make_shared<std::optional<std::shared_ptr<SessionState>>>())
{}

void UspController::set_timeout(std::chrono::seconds t) {
    timeout_ = t;
}

std::chrono::seconds UspController::timeout() const {
    return timeout_;
}

void UspController::set_password(std::string password) {
    password_ = std::move(password);
}

/* ── ensure_session ─────────────────────────────────────────────────────── */

std::shared_ptr<UspController::SessionState> UspController::ensure_session() {
    std::lock_guard lk(*session_mutex_);

    if (*session_) {
        auto existing = **session_;
        std::lock_guard cl(existing->cmd_mutex);
        if (!existing->dead) return existing;
        *session_ = std::nullopt; /* worker is gone: reconnect below */
    }

    /* Connect transport with a 1-second I/O timeout (for the worker poll). */
    std::string peer_id;
    auto transport_result = Transport::connect(
        socket_path_, SESSION_IO_TIMEOUT, endpoint_id_, &peer_id, password_);

    if (auto* err = std::get_if<TransportError>(&transport_result))
        throw *err; /* caller converts to UspError */

    Transport transport = std::move(std::get<Transport>(transport_result));

    /* An empty agent endpoint ID means "address whichever agent answered the
     * handshake". */
    if (agent_endpoint_id_.empty())
        agent_endpoint_id_ = peer_id;

    /* Perform the UDS session-establishment handshake required by the
     * OB-USPA UDS MTP.  After the socket handshake completes, the agent
     * responds to requests with a UDSConnectRecord until the controller
     * establishes the USP session.  Send a UDSConnectRecord and wait for
     * the agent's UDSConnectRecord acknowledgement before any commands are
     * processed. */
    if (auto connect_err = establish_uds_session(transport, endpoint_id_,
                                                  agent_endpoint_id_, timeout_)) {
        throw *connect_err;
    }

    auto state = std::make_shared<SessionState>();
    if (!state->wake_pipe.open())
        throw TransportError::io("pipe() for session wake-up failed");

    /* The worker gets a plain pointer, never an owning reference: ~SessionState joins the
     * worker before any member is destroyed (the jthread is declared last), and a worker
     * that owned its own SessionState would end up joining itself when the controller is
     * destroyed first (std::system_error "Resource deadlock avoided", then terminate). */
    UspController::SessionState* state_raw = state.get();
    std::string ep = endpoint_id_;
    std::string aep = agent_endpoint_id_;
    std::chrono::seconds to = timeout_;

    state->worker = std::jthread(
        [state_raw, ep, aep, to](std::stop_token token, Transport t) {
            session_worker(std::move(token), std::move(t),
                           state_raw, to, ep, aep);
        },
        std::move(transport));

    *session_ = state;
    return state;
}

void UspController::clear_session() {
    std::lock_guard lk(*session_mutex_);
    *session_ = std::nullopt;
}

/* ── build_record ───────────────────────────────────────────────────────── */

proto::Record UspController::build_record(proto::MsgType msg_type, proto::Body body) const {
    return build_record_fn(endpoint_id_, agent_endpoint_id_, msg_type, std::move(body));
}

/* ── round_trip ─────────────────────────────────────────────────────────── */

UspResult<proto::Record> UspController::round_trip(proto::Record record) {
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::shared_ptr<SessionState> state;
        try {
            state = ensure_session();
        } catch (const TransportError& te) {
            return UspError::from_transport(te);
        }

        if (record.to_id.empty())
            record.to_id = agent_endpoint_id_;

        /* Enqueue command with a promise. */
        std::promise<UspResult<proto::Record>> promise;
        auto future = promise.get_future();

        {
            std::unique_lock lk(state->cmd_mutex);
            if (state->dead) {
                promise.set_value(UspError::connection_failed("USP session closed"));
            } else {
                RequestCmd cmd;
                cmd.record = record;
                cmd.reply  = std::move(promise);
                state->commands.emplace(std::move(cmd));
            }
        }
        state->wake();

        /* Wait for reply. */
        auto result = future.get();

        if (auto* rec = std::get_if<proto::Record>(&result))
            return std::move(*rec);

        auto& err = std::get<UspError>(result);
        if (err.is_recoverable() && attempt == 0) {
            std::cerr << "USP: connection lost (" << err.to_string()
                      << "), reconnecting...\n";
            clear_session();
            continue;
        }
        return err;
    }
    return UspError::connection_failed("failed to establish shared USP session");
}

/* ── do_subscribe ───────────────────────────────────────────────────────── */

std::optional<UspError> UspController::do_subscribe(
    const std::vector<std::tuple<std::string,std::string,std::string>>& subs,
    std::function<void()> callback)
{
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::shared_ptr<SessionState> state;
        try {
            state = ensure_session();
        } catch (const TransportError& te) {
            return UspError::from_transport(te);
        }

        std::promise<std::optional<UspError>> promise;
        auto future = promise.get_future();

        {
            std::unique_lock lk(state->cmd_mutex);
            if (state->dead) {
                promise.set_value(UspError::connection_failed("USP session closed"));
            } else {
                SubscribeCmd cmd;
                cmd.subscriptions = subs;
                cmd.callback = callback;
                cmd.reply = std::move(promise);
                state->commands.emplace(std::move(cmd));
            }
        }
        state->wake();

        auto result = future.get();

        if (!result) return std::nullopt; /* success */

        if (result->is_recoverable() && attempt == 0) {
            clear_session();
            continue;
        }
        return result;
    }
    return UspError::connection_failed("failed to establish shared USP session");
}

/* ── notif_type_str ─────────────────────────────────────────────────────── */

std::string UspController::notif_type_str(SubscriptionNotificationType t) {
    switch (t) {
    case SubscriptionNotificationType::ValueChange:    return "ValueChange";
    case SubscriptionNotificationType::ObjectCreation: return "ObjectCreation";
    case SubscriptionNotificationType::ObjectDeletion: return "ObjectDeletion";
    }
    return "ValueChange";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Response parsing helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static UspResult<GetResponse> parse_get_response(const proto::Msg& msg) {
    if (!msg.body)
        return UspError::protocol("empty body in GET response");

    if (auto* resp = std::get_if<proto::Response>(&msg.body->msg_body)) {
        auto* gr = std::get_if<proto::GetResp>(&resp->resp_type);
        if (!gr) return UspError::protocol("unexpected response type for GET");

        GetResponse out;
        for (auto& path_result : gr->req_path_results) {
            if (path_result.err_code != 0) {
                out.errors.push_back({path_result.requested_path,
                                      path_result.err_code,
                                      path_result.err_msg});
            } else {
                for (auto& resolved : path_result.resolved_path_results) {
                    for (auto& [param, value] : resolved.result_params) {
                        /* resolved_path ends with '.' per TR-369. */
                        out.params[resolved.resolved_path + param] = value;
                    }
                }
            }
        }
        return out;
    }

    if (auto* eb = std::get_if<proto::ErrorBody>(&msg.body->msg_body))
        return UspError::agent_rejected(eb->err_code, eb->err_msg);

    return UspError::protocol("unexpected body for GET response");
}

static UspResult<SetResponse> parse_set_response(const proto::Msg& msg) {
    if (!msg.body)
        return UspError::protocol("empty body in SET response");

    if (auto* resp = std::get_if<proto::Response>(&msg.body->msg_body)) {
        auto* sr = std::get_if<proto::SetResp>(&resp->resp_type);
        if (!sr) return UspError::protocol("unexpected response type for SET");

        SetResponse out;
        for (auto& obj_result : sr->updated_obj_results) {
            if (obj_result.oper_status) {
                std::visit([&](auto&& v) {
                    using T = std::decay_t<decltype(v)>;
                    if constexpr (std::is_same_v<T, proto::OperationSuccess>) {
                        out.updated.push_back(obj_result.requested_path);
                    } else if constexpr (std::is_same_v<T, proto::OperationFailure>) {
                        out.errors.push_back({obj_result.requested_path,
                                              v.err_code, v.err_msg});
                    }
                }, obj_result.oper_status->oper_status);
            }
        }
        return out;
    }

    if (auto* eb = std::get_if<proto::ErrorBody>(&msg.body->msg_body))
        return UspError::agent_rejected(eb->err_code, eb->err_msg);

    return UspError::protocol("unexpected body for SET response");
}

static UspResult<OperateResponse> parse_operate_response(const proto::Msg& msg) {
    if (!msg.body)
        return UspError::protocol("empty body in OPERATE response");

    if (auto* resp = std::get_if<proto::Response>(&msg.body->msg_body)) {
        auto* or_ = std::get_if<proto::OperateResp>(&resp->resp_type);
        if (!or_) return UspError::protocol("unexpected response type for OPERATE");

        OperateResponse out;
        for (auto& op_result : or_->operation_results) {
            std::visit([&](auto&& v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, proto::OutputArgs>) {
                    for (auto& [k, val] : v.output_args)
                        out.output_args[k] = val;
                } else if constexpr (std::is_same_v<T, proto::CommandFailure>) {
                    /* Return error via early return isn't possible inside visit;
                     * mark error and break. A single failure is fatal. */
                    out.output_args.clear();
                    out.output_args["__error__"] =
                        std::to_string(v.err_code) + ": " + v.err_msg;
                }
            }, op_result.operation_resp);
        }
        return out;
    }

    if (auto* eb = std::get_if<proto::ErrorBody>(&msg.body->msg_body))
        return UspError::agent_rejected(eb->err_code, eb->err_msg);

    return UspError::protocol("unexpected body for OPERATE response");
}

/* Helper: group (full_param_path, value) pairs into UpdateObject entries. */
static std::vector<proto::UpdateObject>
group_params(const std::vector<std::pair<std::string,std::string>>& params) {
    std::vector<std::string> order;
    std::map<std::string, std::vector<proto::UpdateParamSetting>> by_obj;

    for (auto& [path, value] : params) {
        auto dot = path.rfind('.');
        std::string obj_path  = (dot != std::string::npos) ? path.substr(0, dot + 1) : path;
        std::string param_name= (dot != std::string::npos) ? path.substr(dot + 1)    : std::string{};

        if (by_obj.find(obj_path) == by_obj.end()) {
            order.push_back(obj_path);
        }
        proto::UpdateParamSetting s;
        s.param    = param_name;
        s.value    = value;
        s.required = true;
        by_obj[obj_path].push_back(std::move(s));
    }

    std::vector<proto::UpdateObject> result;
    for (auto& op : order) {
        proto::UpdateObject o;
        o.obj_path      = op;
        o.param_settings= std::move(by_obj[op]);
        result.push_back(std::move(o));
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API implementations
 * ═══════════════════════════════════════════════════════════════════════════ */

UspResult<GetResponse> UspController::get(const std::string& path) {
    return get_many({path});
}

UspResult<GetResponse> UspController::get_many(const std::vector<std::string>& paths,
                                               uint32_t max_depth) {
    proto::Get get_msg;
    get_msg.param_paths = paths;
    get_msg.max_depth   = max_depth;

    proto::Request req;
    req.req_type = std::move(get_msg);

    proto::Body body;
    body.msg_body = std::move(req);

    auto result = round_trip(build_record(proto::MsgType::Get, std::move(body)));
    if (auto* err = std::get_if<UspError>(&result)) return *err;

    auto msg_var = extract_msg(std::get<proto::Record>(result));
    if (auto* err = std::get_if<UspError>(&msg_var)) return *err;

    return parse_get_response(std::get<proto::Msg>(msg_var));
}

UspResult<SetResponse> UspController::set(const std::string& path, const std::string& value) {
    return set_many({{path, value}});
}

UspResult<SetResponse> UspController::set_many(
    const std::vector<std::pair<std::string,std::string>>& params)
{
    proto::Set set_msg;
    set_msg.allow_partial = false;
    set_msg.update_objs   = group_params(params);

    proto::Request req;
    req.req_type = std::move(set_msg);

    proto::Body body;
    body.msg_body = std::move(req);

    auto result = round_trip(build_record(proto::MsgType::Set, std::move(body)));
    if (auto* err = std::get_if<UspError>(&result)) return *err;

    auto msg_var = extract_msg(std::get<proto::Record>(result));
    if (auto* err = std::get_if<UspError>(&msg_var)) return *err;

    return parse_set_response(std::get<proto::Msg>(msg_var));
}

UspResult<OperateResponse> UspController::operate(
    const std::string& command,
    const std::vector<std::pair<std::string,std::string>>& args)
{
    proto::Operate op_msg;
    op_msg.command     = command;
    op_msg.command_key = "";
    op_msg.send_resp   = true;
    for (auto& [k, v] : args)
        op_msg.input_args[k] = v;

    proto::Request req;
    req.req_type = std::move(op_msg);

    proto::Body body;
    body.msg_body = std::move(req);

    auto result = round_trip(build_record(proto::MsgType::Operate, std::move(body)));
    if (auto* err = std::get_if<UspError>(&result)) return *err;

    auto msg_var = extract_msg(std::get<proto::Record>(result));
    if (auto* err = std::get_if<UspError>(&msg_var)) return *err;

    auto op_result = parse_operate_response(std::get<proto::Msg>(msg_var));
    if (auto* err = std::get_if<UspError>(&op_result)) return *err;

    /* Check for internal error marker. */
    auto& or_ = std::get<OperateResponse>(op_result);
    if (auto it = or_.output_args.find("__error__"); it != or_.output_args.end()) {
        std::string msg = it->second;
        or_.output_args.erase(it);
        /* Parse "code: msg" */
        auto colon = msg.find(':');
        uint32_t code = 0;
        std::string detail = msg;
        if (colon != std::string::npos) {
            try { code = static_cast<uint32_t>(std::stoul(msg)); } catch (...) {}
            detail = msg.substr(colon + 2);
        }
        return UspError::agent_rejected(code, detail);
    }
    return or_;
}

UspResult<GetResponse> UspController::subscribe_and_get(
    const std::string& path,
    SubscriptionNotificationType notif_type,
    std::function<void()> callback)
{
    return subscribe_many_and_get({{path, notif_type}}, std::move(callback));
}

UspResult<GetResponse> UspController::subscribe_many_and_get(
    const std::vector<std::pair<std::string, SubscriptionNotificationType>>& subs,
    std::function<void()> callback)
{
    if (subs.empty())
        return UspError::protocol("subscribe_many_and_get requires at least one subscription");

    /* Build subscription tuples: (sub_id, notif_type_str, path). */
    std::vector<std::tuple<std::string,std::string,std::string>> sub_tuples;
    for (auto& [path, notif_type] : subs) {
        sub_tuples.emplace_back("sub-" + next_msg_id(),
                                notif_type_str(notif_type),
                                path);
    }

    if (auto err = do_subscribe(sub_tuples, std::move(callback)))
        return *err;

    /* Deduplicate GET paths. */
    std::vector<std::string> get_paths;
    std::set<std::string> seen;
    for (auto& [path, _] : subs)
        if (seen.insert(path).second)
            get_paths.push_back(path);

    return get_many(get_paths);
}

/* ── Not-yet-implemented stubs ───────────────────────────────────────────── */

UspError UspController::register_obj(const std::string&) {
    return UspError::not_implemented("register");
}

UspError UspController::add(const std::string&,
                             const std::vector<std::pair<std::string,std::string>>&) {
    return UspError::not_implemented("add");
}

UspError UspController::delete_instance(const std::string&) {
    return UspError::not_implemented("delete");
}

UspError UspController::get_supported_dm(const std::string&) {
    return UspError::not_implemented("get_supported_dm");
}

UspError UspController::get_instances(const std::string&) {
    return UspError::not_implemented("get_instances");
}

UspError UspController::get_supported_protocol() {
    return UspError::not_implemented("get_supported_protocol");
}

} // namespace usp
