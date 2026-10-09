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

#include "session.hpp"

#include <atomic>

namespace usp::detail {

static std::atomic<uint64_t> g_msg_counter{1};

std::string next_msg_id() {
    return std::to_string(g_msg_counter.fetch_add(1, std::memory_order_relaxed));
}

static proto::Record wrap(const std::string& from_id,
                          const std::string& to_id,
                          const std::string& msg_id,
                          proto::MsgType msg_type,
                          proto::Body body)
{
    proto::Msg msg;
    msg.header = proto::Header{msg_id, msg_type};
    msg.body   = std::move(body);

    proto::NoSessionContextRecord nsc;
    nsc.payload = msg.encode();

    proto::Record rec;
    rec.version          = "1.5";
    rec.to_id            = to_id;
    rec.from_id          = from_id;
    rec.payload_security = 0; /* Plaintext */
    rec.record_type      = std::move(nsc);
    return rec;
}

proto::Record build_record(const std::string& from_id,
                           const std::string& to_id,
                           proto::MsgType msg_type,
                           proto::Body body)
{
    return wrap(from_id, to_id, next_msg_id(), msg_type, std::move(body));
}

proto::Record build_reply_record(const std::string& from_id,
                                 const std::string& to_id,
                                 const std::string& msg_id,
                                 proto::Body body)
{
    proto::MsgType type = proto::msg_type_of(body);
    return wrap(from_id, to_id, msg_id, type, std::move(body));
}

std::variant<proto::Msg, UspError> extract_msg(const proto::Record& record) {
    const auto* nsc = std::get_if<proto::NoSessionContextRecord>(&record.record_type);
    if (!nsc)
        return UspError::protocol("expected NoSessionContextRecord in response");

    auto msg = proto::Msg::decode(nsc->payload);
    if (!msg)
        return UspError::protocol("failed to decode inner Msg");

    return std::move(*msg);
}

/* The agent expects a UDSConnectRecord to begin a session; it acknowledges
 * with its own UDSConnectRecord before it will process NoSessionContext
 * requests.  Without this handshake the agent only ever responds with a
 * UDSConnectRecord and the library would report "expected
 * NoSessionContextRecord in response". */
std::optional<TransportError> establish_uds_session(Transport& transport,
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

    /* Await the peer's UDSConnectRecord acknowledgement. */
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
        "no UDS Connect acknowledgement from peer (session not established)");
}

} // namespace usp::detail
