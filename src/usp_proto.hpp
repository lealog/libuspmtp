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
 * usp_proto.hpp
 *
 * Thin C++20 value wrappers for the USP TR-369 protobuf schemas vendored in
 * proto/. Encoding and decoding are delegated to the official protobuf C++
 * runtime and generated classes; this file intentionally contains no wire
 * format implementation.
 */

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace usp::proto {

struct NoSessionContextRecord {
    std::vector<uint8_t> payload;

    std::vector<uint8_t> encode() const;
    static std::optional<NoSessionContextRecord> decode(std::span<const uint8_t> data);
};

struct UdsConnectRecord {
    std::vector<uint8_t> encode() const;
};

struct DisconnectRecord {
    std::string reason;
    uint32_t reason_code{0};
};

struct Record {
    std::string version;
    std::string to_id;
    std::string from_id;
    std::string originator_id;
    std::string destination_id;
    int32_t payload_security{0};
    std::variant<std::monostate, NoSessionContextRecord, UdsConnectRecord, DisconnectRecord> record_type;

    std::vector<uint8_t> encode() const;
    static std::optional<Record> decode(std::span<const uint8_t> data);
};

enum class MsgType : int32_t {
    Error = 0,
    Get = 1,
    GetResp = 2,
    Notify = 3,
    Set = 4,
    SetResp = 5,
    Operate = 6,
    OperateResp = 7,
    Add = 8,
    AddResp = 9,
    Delete = 10,
    DeleteResp = 11,
    GetSupportedDm = 12,
    GetSupportedDmResp = 13,
    GetInstances = 14,
    GetInstancesResp = 15,
    NotifyResp = 16,
    GetSupportedProto = 17,
    GetSupportedProtoResp = 18,
    Register = 19,
    RegisterResp = 20,
    Deregister = 21,
    DeregisterResp = 22,
};

struct Header {
    std::string msg_id;
    MsgType msg_type{MsgType::Error};
};

struct ParamError {
    std::string param_path;
    uint32_t err_code{0};
    std::string err_msg;
};

struct ErrorBody {
    uint32_t err_code{0};
    std::string err_msg;
    std::vector<ParamError> param_errs;
};

struct Get {
    std::vector<std::string> param_paths;
    uint32_t max_depth{0};
};

struct ResolvedPathResult {
    std::string resolved_path;
    std::map<std::string, std::string> result_params;
};

struct RequestedPathResult {
    std::string requested_path;
    uint32_t err_code{0};
    std::string err_msg;
    std::vector<ResolvedPathResult> resolved_path_results;
};

struct GetResp {
    std::vector<RequestedPathResult> req_path_results;
};

struct GetSupportedDM {
    std::vector<std::string> obj_paths;
    bool first_level_only{false};
    bool return_commands{false};
    bool return_events{false};
    bool return_params{false};
    bool return_unique_key_sets{false};
};

enum class ParamAccessType : int32_t {
    ReadOnly = 0,
    ReadWrite = 1,
    WriteOnly = 2,
};

enum class ObjAccessType : int32_t {
    ReadOnly = 0,
    AddDelete = 1,
    AddOnly = 2,
    DeleteOnly = 3,
};

enum class ParamValueType : int32_t {
    Unknown = 0,
    Base64 = 1,
    Boolean = 2,
    DateTime = 3,
    Decimal = 4,
    HexBinary = 5,
    Int = 6,
    Long = 7,
    String = 8,
    UnsignedInt = 9,
    UnsignedLong = 10,
};

enum class ValueChangeType : int32_t {
    Unknown = 0,
    Allowed = 1,
    WillIgnore = 2,
};

enum class CmdType : int32_t {
    Unknown = 0,
    Sync = 1,
    Async = 2,
};

struct SupportedParamResult {
    std::string param_name;
    ParamAccessType access{ParamAccessType::ReadOnly};
    ParamValueType value_type{ParamValueType::Unknown};
    ValueChangeType value_change{ValueChangeType::Unknown};
};

struct SupportedCommandResult {
    std::string command_name;
    std::vector<std::string> input_arg_names;
    std::vector<std::string> output_arg_names;
    CmdType command_type{CmdType::Unknown};
};

struct SupportedEventResult {
    std::string event_name;
    std::vector<std::string> arg_names;
};

struct SupportedUniqueKeySet {
    std::vector<std::string> key_names;
};

struct SupportedObjectResult {
    std::string supported_obj_path;
    ObjAccessType access{ObjAccessType::ReadOnly};
    bool is_multi_instance{false};
    std::vector<SupportedCommandResult> supported_commands;
    std::vector<SupportedEventResult> supported_events;
    std::vector<SupportedParamResult> supported_params;
    std::vector<std::string> divergent_paths;
    std::vector<SupportedUniqueKeySet> unique_key_sets;
};

struct RequestedObjectResult {
    std::string req_obj_path;
    uint32_t err_code{0};
    std::string err_msg;
    std::string data_model_inst_uri;
    std::vector<SupportedObjectResult> supported_objs;
};

struct GetSupportedDMResp {
    std::vector<RequestedObjectResult> req_obj_results;
};

struct GetInstances {
    std::vector<std::string> obj_paths;
    bool first_level_only{false};
};

struct CurrInstance {
    std::string instantiated_obj_path;
    std::map<std::string, std::string> unique_keys;
};

struct InstancesPathResult {
    std::string requested_path;
    uint32_t err_code{0};
    std::string err_msg;
    std::vector<CurrInstance> curr_insts;
};

struct GetInstancesResp {
    std::vector<InstancesPathResult> req_path_results;
};

struct UpdateParamSetting {
    std::string param;
    std::string value;
    bool required{false};
};

struct UpdateObject {
    std::string obj_path;
    std::vector<UpdateParamSetting> param_settings;
};

struct Set {
    bool allow_partial{false};
    std::vector<UpdateObject> update_objs;
};

struct ParameterError {
    std::string param;
    uint32_t err_code{0};
    std::string err_msg;
};

struct UpdatedInstanceFailure {
    std::string affected_path;
    std::vector<ParameterError> param_errs;
};

struct UpdatedInstanceResult {
    std::string affected_path;
    std::vector<ParameterError> param_errs;
    std::map<std::string, std::string> updated_params;
};

struct OperationFailure {
    uint32_t err_code{0};
    std::string err_msg;
    std::vector<UpdatedInstanceFailure> updated_inst_failures;
};

struct OperationSuccess {
    std::vector<UpdatedInstanceResult> updated_inst_results;
};

struct OperationStatus {
    std::variant<std::monostate, OperationFailure, OperationSuccess> oper_status;
};

struct UpdatedObjectResult {
    std::string requested_path;
    std::optional<OperationStatus> oper_status;
};

struct SetResp {
    std::vector<UpdatedObjectResult> updated_obj_results;
};

struct Operate {
    std::string command;
    std::string command_key;
    bool send_resp{false};
    std::map<std::string, std::string> input_args;
};

struct OutputArgs {
    std::map<std::string, std::string> output_args;
};

struct CommandFailure {
    uint32_t err_code{0};
    std::string err_msg;
};

struct OperationResult {
    std::string executed_command;
    std::variant<std::monostate, std::string, OutputArgs, CommandFailure> operation_resp;
};

struct OperateResp {
    std::vector<OperationResult> operation_results;
};

struct CreateParamSetting {
    std::string param;
    std::string value;
    bool required{false};
};

struct CreateObject {
    std::string obj_path;
    std::vector<CreateParamSetting> param_settings;
};

struct Add {
    bool allow_partial{false};
    std::vector<CreateObject> create_objs;
};

struct AddOperationFailure {
    uint32_t err_code{0};
    std::string err_msg;
};

struct AddOperationSuccess {
    std::string instantiated_path;
    std::map<std::string, std::string> unique_keys;
    std::vector<ParameterError> param_errs;
};

struct AddOperationStatus {
    std::variant<std::monostate, AddOperationFailure, AddOperationSuccess> oper_status;
};

struct CreatedObjectResult {
    std::string requested_path;
    std::optional<AddOperationStatus> oper_status;
};

struct AddResp {
    std::vector<CreatedObjectResult> created_obj_results;
};

struct Delete {
    bool allow_partial{false};
    std::vector<std::string> obj_paths;
};

struct UnaffectedPathError {
    std::string unaffected_path;
    uint32_t err_code{0};
    std::string err_msg;
};

struct DeleteOperationFailure {
    uint32_t err_code{0};
    std::string err_msg;
};

struct DeleteOperationSuccess {
    std::vector<std::string> affected_paths;
    std::vector<UnaffectedPathError> unaffected_path_errs;
};

struct DeleteOperationStatus {
    std::variant<std::monostate, DeleteOperationFailure, DeleteOperationSuccess> oper_status;
};

struct DeletedObjectResult {
    std::string requested_path;
    std::optional<DeleteOperationStatus> oper_status;
};

struct DeleteResp {
    std::vector<DeletedObjectResult> deleted_obj_results;
};

struct GetSupportedProtocol {
    std::string controller_supported_protocol_versions;
};

struct GetSupportedProtocolResp {
    std::string agent_supported_protocol_versions;
};

struct Register {
    bool allow_partial{false};
    std::vector<std::string> reg_paths;
};

struct RegisterOperationFailure {
    uint32_t err_code{0};
    std::string err_msg;
};

struct RegisterOperationSuccess {
    std::string registered_path;
};

struct RegisterOperationStatus {
    std::variant<std::monostate, RegisterOperationFailure, RegisterOperationSuccess> oper_status;
};

struct RegisteredPathResult {
    std::string requested_path;
    std::optional<RegisterOperationStatus> oper_status;
};

struct RegisterResp {
    std::vector<RegisteredPathResult> registered_path_results;
};

struct Deregister {
    std::vector<std::string> paths;
};

struct DeregisterOperationFailure {
    uint32_t err_code{0};
    std::string err_msg;
};

struct DeregisterOperationSuccess {
    std::vector<std::string> deregistered_path;
};

struct DeregisterOperationStatus {
    std::variant<std::monostate, DeregisterOperationFailure, DeregisterOperationSuccess> oper_status;
};

struct DeregisteredPathResult {
    std::string requested_path;
    std::optional<DeregisterOperationStatus> oper_status;
};

struct DeregisterResp {
    std::vector<DeregisteredPathResult> deregistered_path_results;
};

struct Event {
    std::string obj_path;
    std::string event_name;
    std::map<std::string, std::string> params;
};

struct ValueChange {
    std::string param_path;
    std::string param_value;
};

struct ObjectCreation {
    std::string obj_path;
    std::map<std::string, std::string> unique_keys;
};

struct ObjectDeletion {
    std::string obj_path;
};

struct OperationComplete {
    std::string obj_path;
    std::string command_name;
    std::string command_key;
    std::variant<std::monostate, OutputArgs, CommandFailure> operation_resp;
};

struct Notify {
    std::string subscription_id;
    bool send_resp{false};
    std::variant<std::monostate, Event, ValueChange, ObjectCreation, ObjectDeletion, OperationComplete> notification;
};

struct NotifyResp {
    std::string subscription_id;
};

using RequestVariant = std::variant<std::monostate, Get, GetSupportedDM, GetInstances, Set, Add, Delete,
                                    Operate, Notify, GetSupportedProtocol, Register, Deregister>;

struct Request {
    RequestVariant req_type;
};

using ResponseVariant = std::variant<std::monostate, GetResp, GetSupportedDMResp, GetInstancesResp, SetResp,
                                     AddResp, DeleteResp, OperateResp, NotifyResp, GetSupportedProtocolResp,
                                     RegisterResp, DeregisterResp>;

struct Response {
    ResponseVariant resp_type;
};

using BodyVariant = std::variant<std::monostate, Request, Response, ErrorBody>;

struct Body {
    BodyVariant msg_body;
};

struct Msg {
    std::optional<Header> header;
    std::optional<Body> body;

    std::vector<uint8_t> encode() const;
    static std::optional<Msg> decode(std::span<const uint8_t> data);
};

/** The Header.msg_type that describes this body (Error when the body is empty or an error). */
MsgType msg_type_of(const Body& body);

/** The response message type that answers a request type (Error for types that have none). */
MsgType response_type_for(MsgType request_type);

} // namespace usp::proto
