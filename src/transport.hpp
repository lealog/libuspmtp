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
 * transport.hpp
 *
 * UNIX domain socket transport implementing the OB-USPA UDS MTP framing
 * protocol for USP (TR-369) communication.
 *
 * Wire format (per OB-USPA UDS MTP):
 *
 *   [4 bytes: sync = 0x5F 0x55 0x53 0x50 = "_USP"]
 *   [4 bytes: outer_len, big-endian uint32]
 *   [outer_len bytes: TLV payload]
 *     TLV payload:
 *       [1 byte:  frame_type]
 *       [4 bytes: tlv_value_len, big-endian uint32]
 *       [tlv_value_len bytes: value]
 *
 * Frame types:
 *   1 = Handshake (value = UTF-8 endpoint ID)
 *   2 = Error     (value = UTF-8 error message)
 *   3 = USP Record (value = protobuf-encoded Record)
 */

#pragma once

#include "usp_proto.hpp"

#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace usp {

/* ── Wire-format constants ──────────────────────────────────────────────── */

/// Sync bytes identifying each UDS frame: "_USP" in ASCII.
inline constexpr std::array<uint8_t, 4> UDS_SYNC = {0x5Fu, 0x55u, 0x53u, 0x50u};

/// TLV header size: 1 byte type + 4 bytes length.
inline constexpr size_t TLV_HEADER_SIZE = 5;

/// Maximum outer-payload size accepted from the agent (16 MiB).
inline constexpr uint32_t MAX_PAYLOAD_BYTES = 16u * 1024u * 1024u;

/// Frame type constants.
inline constexpr uint8_t FRAME_TYPE_HANDSHAKE  = 1;
inline constexpr uint8_t FRAME_TYPE_ERROR      = 2;
inline constexpr uint8_t FRAME_TYPE_USP_RECORD = 3;
inline constexpr uint8_t FRAME_TYPE_PASSWORD   = 4;

/* ── Error type ─────────────────────────────────────────────────────────── */

/// Errors returned by the transport layer.
class TransportError {
public:
    enum class Kind {
        Timeout,           ///< recv() timed out (no data within SO_RCVTIMEO).
        ConnectionFailed,  ///< Could not connect the socket.
        Protocol,          ///< Framing or decoding violation.
        Io,                ///< Unexpected I/O error.
    };

    static TransportError timeout()
    { return TransportError(Kind::Timeout, "timeout"); }

    static TransportError connection_failed(std::string msg)
    { return TransportError(Kind::ConnectionFailed, std::move(msg)); }

    static TransportError protocol(std::string msg)
    { return TransportError(Kind::Protocol, std::move(msg)); }

    static TransportError io(std::string msg)
    { return TransportError(Kind::Io, std::move(msg)); }

    Kind        kind()    const noexcept { return kind_; }
    const std::string& message() const noexcept { return message_; }

    bool is_timeout()    const noexcept { return kind_ == Kind::Timeout; }
    bool is_recoverable() const noexcept {
        return kind_ == Kind::ConnectionFailed || kind_ == Kind::Io;
    }

    std::string to_string() const {
        switch (kind_) {
        case Kind::Timeout:          return "timeout";
        case Kind::ConnectionFailed: return "connection failed: " + message_;
        case Kind::Protocol:         return "protocol error: " + message_;
        case Kind::Io:               return "I/O error: " + message_;
        }
        return message_;
    }

private:
    TransportError(Kind k, std::string m)
        : kind_(k), message_(std::move(m)) {}

    Kind        kind_;
    std::string message_;
};

/* ── Transport class ────────────────────────────────────────────────────── */

/**
 * Wire transport over a UNIX domain stream socket using the OB-USPA UDS MTP
 * framing protocol.
 *
 * A Transport is move-only (the underlying file descriptor is an exclusive
 * resource).  After successful construction the handshake is complete and the
 * connection is ready to exchange USP Record frames.
 */
class Transport {
public:
    /**
     * Open a UNIX domain socket connection to `socket_path`, apply
     * `io_timeout` as both the send and receive timeout, and complete the
     * UDS MTP handshake identifying this side as `endpoint_id`. If
     * `peer_endpoint_id` is non-null it receives the agent's endpoint ID
     * from the handshake reply. A non-empty `password` is sent as a
     * Password TLV in the handshake frame, which the agent's authenticated
     * UDS sockets require (R-UDS of TR-369); it is ignored by the
     * unauthenticated ones.
     *
     * Returns a ready Transport or a TransportError on failure.
     */
    static std::variant<Transport, TransportError>
    connect(const std::string& socket_path,
            std::chrono::seconds io_timeout,
            const std::string& endpoint_id,
            std::string* peer_endpoint_id = nullptr,
            const std::string& password = {});

    /** The underlying socket, for poll(). Ownership stays with the Transport. */
    int native_handle() const noexcept { return fd_; }

    /* Non-copyable, movable. */
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;
    Transport(Transport&&) noexcept;
    Transport& operator=(Transport&&) noexcept;
    ~Transport();

    /**
     * Encode `record` and send it as a UDS USP Record frame (type 3).
     */
    std::optional<TransportError> send(const proto::Record& record);

    /**
     * Read one UDS frame and decode the USP Record contained in it.
     *
     * Returns TransportError::Timeout if the socket SO_RCVTIMEO fires
     * before a complete frame arrives.
     */
    std::variant<proto::Record, TransportError> recv();

private:
    explicit Transport(int fd) : fd_(fd) {}

    std::optional<TransportError> send_handshake(const std::string& endpoint_id,
                                                 const std::string& password);
    std::variant<std::vector<uint8_t>, TransportError> recv_handshake();
    std::variant<std::vector<uint8_t>, TransportError> read_frame();

    /* Write all bytes; returns error on failure. */
    std::optional<TransportError> write_all(const uint8_t* data, size_t len);

    /* Read exactly `len` bytes; returns error on failure (including timeout). */
    std::optional<TransportError> read_exact(uint8_t* buf, size_t len);

    int fd_ = -1;
};

} // namespace usp
