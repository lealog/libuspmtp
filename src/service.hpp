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
 * service.hpp
 *
 * USP Service: an application that publishes its own data model through the
 * USP Broker (TR-369 "USP Services", OB-USPA broker mode).
 *
 * The service connects to the broker's *controller* UDS socket, registers the
 * roots of its data model, and from then on answers the requests the broker
 * routes to it (GetSupportedDM, Get, GetInstances, Set, Add, Delete, Operate)
 * from a schema the application describes and callbacks that own the values.
 * It also keeps the subscriptions the broker creates in the service's
 * Device.LocalAgent.Subscription. table and sends Notify for them.
 */

#pragma once

#include "client.hpp"
#include "usp_proto.hpp"

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace usp {

/* ── Schema the service publishes ───────────────────────────────────────── */

/** One parameter of an object. */
struct ServiceParam {
    std::string           name;
    proto::ParamAccessType access{proto::ParamAccessType::ReadOnly};
    proto::ParamValueType  type{proto::ParamValueType::String};
};

/** One command of an object ("Reset()"). */
struct ServiceCommand {
    std::string              name;
    std::vector<std::string> input_args;
    std::vector<std::string> output_args;
    bool                     async{false};
};

/** One event of an object ("Changed!"). */
struct ServiceEvent {
    std::string              name;
    std::vector<std::string> args;
};

/**
 * One object of the schema, by schema path: "Device.TestApp." for a single
 * object, "Device.TestApp.Item.{i}." for a table.
 */
struct ServiceObject {
    std::string                 path;
    bool                        multi_instance{false};
    proto::ObjAccessType        access{proto::ObjAccessType::ReadOnly};
    std::vector<ServiceParam>   params;
    std::vector<ServiceCommand> commands;
    std::vector<ServiceEvent>   events;
    std::vector<std::string>    unique_keys;
};

/* ── Callbacks that own the values ──────────────────────────────────────── */

/** Result of a Set on one object: the parameters the agent did not apply. */
using ParamErrors = std::vector<proto::ParameterError>;

/**
 * The application owns the values; the library owns the protocol.  Every
 * callback receives instantiated paths ("Device.TestApp.Item.1."), is invoked
 * from the service's worker thread, and must not call back into the service.
 * A missing callback makes the corresponding request fail with 7001.
 */
struct ServiceHandlers {
    /** Parameter values of one object, or nullopt if the object does not exist. */
    std::function<std::optional<std::map<std::string, std::string>>(const std::string& obj_path)> get;

    /** The instances of one table ("Device.TestApp.Item."), with their unique keys. */
    std::function<std::vector<proto::CurrInstance>(const std::string& table_path)> instances;

    /** Apply parameters to one object; nullopt if the object does not exist. */
    std::function<std::optional<ParamErrors>(const std::string& obj_path,
                                             const std::map<std::string, std::string>& params)> set;

    /** Create an instance of a table. */
    std::function<UspResult<AddResponse>(const std::string& table_path,
                                         const std::map<std::string, std::string>& params)> add;

    /** Delete one instance; nullopt on success. */
    std::function<std::optional<UspError>(const std::string& obj_path)> del;

    /** Run a synchronous command; the output arguments on success. */
    std::function<UspResult<std::map<std::string, std::string>>(const std::string& obj_path,
                                                                const std::string& command,
                                                                const std::map<std::string, std::string>& input)> operate;
};

/** A subscription the broker created on this service. */
struct ServiceSubscription {
    std::string id;
    std::string notif_type;     /* ValueChange, ObjectCreation, ObjectDeletion, Event, OperationComplete */
    std::vector<std::string> reference_list;
    bool enable{true};
};

/** Per-path outcome of register()/deregister(). */
struct RegisterResult {
    std::string path;
    bool        ok{false};
    uint32_t    err_code{0};
    std::string err_msg;
};

/* ── UspService ─────────────────────────────────────────────────────────── */

class UspService {
public:
    /**
     * @param socket_path        The broker's controller UDS socket (e.g. "/var/run/usp/broker_controller_path").
     * @param endpoint_id        This service's endpoint ID (from_id).
     * @param broker_endpoint_id The broker's endpoint ID; empty means the one it reports in the UDS handshake.
     */
    UspService(std::string socket_path, std::string endpoint_id, std::string broker_endpoint_id = {});
    ~UspService();

    UspService(const UspService&) = delete;
    UspService& operator=(const UspService&) = delete;

    void set_timeout(std::chrono::seconds timeout);
    void set_password(std::string password);

    /** Describe the data model. Every object must be under one of the roots passed to start(). */
    void add_object(ServiceObject object);
    void set_handlers(ServiceHandlers handlers);

    /**
     * Connect, establish the UDS session and register `roots` (schema paths
     * ending in '.'). Returns one result per root, or an error when the
     * connection or the Register exchange itself failed.
     */
    UspResult<std::vector<RegisterResult>> start(const std::vector<std::string>& roots,
                                                 bool allow_partial = false);

    /** Deregister everything and disconnect. Safe to call when not started. */
    void stop();

    bool running() const;
    std::string broker_endpoint_id() const;

    /** Subscriptions the broker currently holds on this service. */
    std::vector<ServiceSubscription> subscriptions() const;

    /* ── Notifications: sent for every matching, enabled subscription ────── */

    void value_changed(const std::string& param_path, const std::string& value);
    void object_created(const std::string& obj_path, const std::map<std::string, std::string>& unique_keys);
    void object_deleted(const std::string& obj_path);
    void event(const std::string& obj_path, const std::string& event_name,
               const std::map<std::string, std::string>& params);

    /* ── Internals shared with the worker (public for free-function access) ── */

    struct State;

private:
    UspResult<std::vector<RegisterResult>> start_once(const std::vector<std::string>& roots, bool allow_partial);
    std::optional<UspError> send_request_and_wait(proto::MsgType type, proto::Body body, proto::Msg& reply);
    void send_notify(const std::string& notif_type, const std::string& path, proto::Notify notify);

    std::string          socket_path_;
    std::string          endpoint_id_;
    std::string          broker_endpoint_id_;
    std::string          password_;
    std::chrono::seconds timeout_{10};

    std::shared_ptr<State> state_;
};

} // namespace usp
