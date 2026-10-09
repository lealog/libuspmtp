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
 * session.hpp
 *
 * Record helpers and the UDS session establishment shared by the controller
 * (client.cpp) and the service (service.cpp) sides of the library.
 */

#pragma once

#include "client.hpp"
#include "transport.hpp"
#include "usp_proto.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <variant>

namespace usp::detail {

/** A process-wide unique message id for outgoing requests. */
std::string next_msg_id();

/** Build a USP Record wrapping a Msg (NoSessionContext, plaintext) with a fresh msg_id. */
proto::Record build_record(const std::string& from_id,
                           const std::string& to_id,
                           proto::MsgType msg_type,
                           proto::Body body);

/** Build a USP Record wrapping a Msg that answers `msg_id` (same id, response type of the body). */
proto::Record build_reply_record(const std::string& from_id,
                                 const std::string& to_id,
                                 const std::string& msg_id,
                                 proto::Body body);

/** Extract the inner Msg from a NoSessionContextRecord. */
std::variant<proto::Msg, UspError> extract_msg(const proto::Record& record);

/**
 * Complete the UDS session-establishment handshake: send our UDSConnectRecord
 * and, when `expect_ack` is set, wait for the peer's. Returns nullopt on
 * success.
 *
 * OB-USPA sends its own UDSConnectRecord only on its agent socket (to a
 * connecting controller); a service connecting on the broker's controller
 * socket sends one and gets nothing back, so a service passes false.
 */
std::optional<TransportError> establish_uds_session(Transport& transport,
                                                    const std::string& from_id,
                                                    const std::string& to_id,
                                                    std::chrono::seconds timeout,
                                                    bool expect_ack = true);

} // namespace usp::detail
