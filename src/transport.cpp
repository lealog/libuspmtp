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
 * transport.cpp
 *
 * UNIX domain socket transport implementation.
 */

#include "transport.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <span>
#include <string>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

namespace usp {

/* ── helpers ───────────────────────────────────────────────────────────── */

struct TlvView {
    uint8_t type{0};
    std::span<const uint8_t> value;
};

static TransportError make_io_error(const char* ctx) {
    char buf[256];
    std::snprintf(buf, sizeof(buf), "%s: %s", ctx, std::strerror(errno));
    return TransportError::io(buf);
}

static bool is_timeout_errno() {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT;
}

static std::variant<std::vector<TlvView>, TransportError>
parse_tlvs(std::span<const uint8_t> payload) {
    std::vector<TlvView> tlvs;
    size_t pos = 0;

    while (pos < payload.size()) {
        if (payload.size() - pos < TLV_HEADER_SIZE) {
            return TransportError::protocol("UDS frame contains a truncated TLV header");
        }

        const uint8_t type = payload[pos];
        const uint32_t value_len =
            (static_cast<uint32_t>(payload[pos + 1]) << 24) |
            (static_cast<uint32_t>(payload[pos + 2]) << 16) |
            (static_cast<uint32_t>(payload[pos + 3]) <<  8) |
             static_cast<uint32_t>(payload[pos + 4]);

        pos += TLV_HEADER_SIZE;
        if (value_len > payload.size() - pos) {
            return TransportError::protocol("TLV length exceeds remaining frame payload");
        }

        tlvs.push_back(TlvView{type, payload.subspan(pos, value_len)});
        pos += value_len;
    }

    if (tlvs.empty()) {
        return TransportError::protocol("UDS frame contains no TLVs");
    }
    return tlvs;
}

static std::string tlv_string(TlvView tlv) {
    return std::string(reinterpret_cast<const char*>(tlv.value.data()), tlv.value.size());
}

/* ── Transport::connect ─────────────────────────────────────────────────── */

std::variant<Transport, TransportError>
Transport::connect(const std::string& socket_path,
                   std::chrono::seconds io_timeout,
                   const std::string& endpoint_id,
                   std::string* peer_endpoint_id)
{
    /* Create socket. */
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return TransportError::connection_failed(
            std::string("socket(): ") + std::strerror(errno));

    /* Connect. */
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(addr.sun_path) - 1) {
        ::close(fd);
        return TransportError::connection_failed("socket path too long");
    }
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::string msg = std::string("connect '") + socket_path + "': " + std::strerror(errno);
        ::close(fd);
        return TransportError::connection_failed(std::move(msg));
    }

    /* Apply I/O timeout. */
    long secs = static_cast<long>(io_timeout.count());
    if (secs <= 0) secs = 1; /* minimum 1s */
    timeval tv{secs, 0};
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
    {
        ::close(fd);
        return TransportError::io("setsockopt SO_RCVTIMEO/SO_SNDTIMEO");
    }

#ifdef SO_NOSIGPIPE
    /* Suppress SIGPIPE on macOS when writing to a closed socket. */
    {
        int optval = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval));
    }
#endif

    Transport t(fd);

    /* Handshake: send client ID, receive agent ID. */
    if (auto err = t.send_handshake(endpoint_id))
        return *err;

    auto hs = t.recv_handshake();
    if (auto* err = std::get_if<TransportError>(&hs))
        return *err;

    if (peer_endpoint_id) {
        const auto& peer = std::get<std::vector<uint8_t>>(hs);
        peer_endpoint_id->assign(peer.begin(), peer.end());
    }

    return t;
}

/* ── Move semantics ────────────────────────────────────────────────────── */

Transport::Transport(Transport&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }

Transport& Transport::operator=(Transport&& o) noexcept {
    if (this != &o) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = o.fd_;
        o.fd_ = -1;
    }
    return *this;
}

Transport::~Transport() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

/* ── Public send / recv ─────────────────────────────────────────────────── */

std::optional<TransportError> Transport::send(const proto::Record& record) {
    std::vector<uint8_t> payload = record.encode();
    uint32_t tlv_value_len = static_cast<uint32_t>(payload.size());
    uint32_t outer_len     = static_cast<uint32_t>(TLV_HEADER_SIZE) + tlv_value_len;

    /* Sync word */
    if (auto e = write_all(UDS_SYNC.data(), UDS_SYNC.size())) return e;

    /* Outer length (big-endian) */
    const uint8_t olen_buf[4] = {
        static_cast<uint8_t>((outer_len >> 24) & 0xFFu),
        static_cast<uint8_t>((outer_len >> 16) & 0xFFu),
        static_cast<uint8_t>((outer_len >>  8) & 0xFFu),
        static_cast<uint8_t>( outer_len        & 0xFFu),
    };
    if (auto e = write_all(olen_buf, 4)) return e;

    /* TLV: type */
    uint8_t ftype = FRAME_TYPE_USP_RECORD;
    if (auto e = write_all(&ftype, 1)) return e;

    /* TLV: value length (big-endian) */
    const uint8_t vlen_buf[4] = {
        static_cast<uint8_t>((tlv_value_len >> 24) & 0xFFu),
        static_cast<uint8_t>((tlv_value_len >> 16) & 0xFFu),
        static_cast<uint8_t>((tlv_value_len >>  8) & 0xFFu),
        static_cast<uint8_t>( tlv_value_len         & 0xFFu),
    };
    if (auto e = write_all(vlen_buf, 4)) return e;

    /* TLV: value (protobuf payload) */
    if (!payload.empty())
        if (auto e = write_all(payload.data(), payload.size())) return e;

    return std::nullopt;
}

std::variant<proto::Record, TransportError> Transport::recv() {
    auto frame = read_frame();
    if (auto* err = std::get_if<TransportError>(&frame))
        return *err;

    auto& tlv_payload = std::get<std::vector<uint8_t>>(frame);
    auto parsed = parse_tlvs(std::span<const uint8_t>(tlv_payload.data(), tlv_payload.size()));
    if (auto* err = std::get_if<TransportError>(&parsed)) {
        return *err;
    }

    const auto& tlvs = std::get<std::vector<TlvView>>(parsed);

    const auto err_it = std::find_if(tlvs.begin(), tlvs.end(),
        [](const TlvView& tlv) { return tlv.type == FRAME_TYPE_ERROR; });
    if (err_it != tlvs.end()) {
        return TransportError::protocol("ob-uspa error frame: " + tlv_string(*err_it));
    }

    for (const auto& tlv : tlvs) {
        if (tlv.type != FRAME_TYPE_USP_RECORD) {
            continue;
        }

        auto rec = proto::Record::decode(tlv.value);
        if (!rec) {
            return TransportError::protocol("failed to decode USP Record");
        }
        return std::move(*rec);
    }

    return TransportError::protocol("UDS frame did not contain a USP Record TLV");
}

/* ── Private helpers ────────────────────────────────────────────────────── */

std::optional<TransportError> Transport::send_handshake(const std::string& endpoint_id) {
    const uint8_t* ep = reinterpret_cast<const uint8_t*>(endpoint_id.data());
    uint32_t tlv_value_len = static_cast<uint32_t>(endpoint_id.size());
    uint32_t outer_len     = static_cast<uint32_t>(TLV_HEADER_SIZE) + tlv_value_len;

    if (auto e = write_all(UDS_SYNC.data(), UDS_SYNC.size())) return e;

    const uint8_t olen_buf[4] = {
        static_cast<uint8_t>((outer_len >> 24) & 0xFFu),
        static_cast<uint8_t>((outer_len >> 16) & 0xFFu),
        static_cast<uint8_t>((outer_len >>  8) & 0xFFu),
        static_cast<uint8_t>( outer_len        & 0xFFu),
    };
    if (auto e = write_all(olen_buf, 4)) return e;

    uint8_t ftype = FRAME_TYPE_HANDSHAKE;
    if (auto e = write_all(&ftype, 1)) return e;

    const uint8_t vlen_buf[4] = {
        static_cast<uint8_t>((tlv_value_len >> 24) & 0xFFu),
        static_cast<uint8_t>((tlv_value_len >> 16) & 0xFFu),
        static_cast<uint8_t>((tlv_value_len >>  8) & 0xFFu),
        static_cast<uint8_t>( tlv_value_len         & 0xFFu),
    };
    if (auto e = write_all(vlen_buf, 4)) return e;

    if (!endpoint_id.empty())
        if (auto e = write_all(ep, endpoint_id.size())) return e;

    return std::nullopt;
}

std::variant<std::vector<uint8_t>, TransportError> Transport::recv_handshake() {
    auto frame = read_frame();
    if (auto* err = std::get_if<TransportError>(&frame))
        return *err;

    auto& tlv = std::get<std::vector<uint8_t>>(frame);
    auto parsed = parse_tlvs(std::span<const uint8_t>(tlv.data(), tlv.size()));
    if (auto* err = std::get_if<TransportError>(&parsed)) {
        return *err;
    }

    const auto& items = std::get<std::vector<TlvView>>(parsed);

    const auto err_it = std::find_if(items.begin(), items.end(),
        [](const TlvView& item) { return item.type == FRAME_TYPE_ERROR; });
    if (err_it != items.end()) {
        return TransportError::connection_failed("ob-uspa rejected handshake: " + tlv_string(*err_it));
    }

    const auto hs_it = std::find_if(items.begin(), items.end(),
        [](const TlvView& item) { return item.type == FRAME_TYPE_HANDSHAKE; });
    if (hs_it != items.end()) {
        return std::vector<uint8_t>(hs_it->value.begin(), hs_it->value.end());
    }

    return TransportError::protocol("handshake response did not contain a Handshake TLV");
}

std::variant<std::vector<uint8_t>, TransportError> Transport::read_frame() {
    /* 1. Sync word */
    uint8_t sync[4];
    if (auto e = read_exact(sync, 4)) return *e;
    if (sync[0] != UDS_SYNC[0] || sync[1] != UDS_SYNC[1] ||
        sync[2] != UDS_SYNC[2] || sync[3] != UDS_SYNC[3])
    {
        return TransportError::protocol("invalid UDS sync bytes");
    }

    /* 2. Outer length */
    uint8_t len_buf[4];
    if (auto e = read_exact(len_buf, 4)) return *e;
    uint32_t outer_len =
        (static_cast<uint32_t>(len_buf[0]) << 24) |
        (static_cast<uint32_t>(len_buf[1]) << 16) |
        (static_cast<uint32_t>(len_buf[2]) <<  8) |
         static_cast<uint32_t>(len_buf[3]);

    if (outer_len > MAX_PAYLOAD_BYTES)
        return TransportError::protocol(
            "frame payload length " + std::to_string(outer_len) +
            " exceeds maximum " + std::to_string(MAX_PAYLOAD_BYTES));

    if (outer_len < TLV_HEADER_SIZE)
        return TransportError::protocol(
            "frame payload length " + std::to_string(outer_len) +
            " too small for TLV header");

    /* 3. TLV payload */
    std::vector<uint8_t> tlv(outer_len);
    if (auto e = read_exact(tlv.data(), outer_len)) return *e;
    return tlv;
}

std::optional<TransportError> Transport::write_all(const uint8_t* data, size_t len) {
    size_t written = 0;
#ifdef MSG_NOSIGNAL
    constexpr int send_flags = MSG_NOSIGNAL;
#else
    constexpr int send_flags = 0;
#endif
    while (written < len) {
        ssize_t n = ::send(fd_, data + written, len - written, send_flags);
        if (n > 0) {
            written += static_cast<size_t>(n);
        } else if (n == 0) {
            return TransportError::io("send returned 0");
        } else {
            if (is_timeout_errno())
                return TransportError::timeout();
            return make_io_error("send");
        }
    }
    return std::nullopt;
}

std::optional<TransportError> Transport::read_exact(uint8_t* buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = ::read(fd_, buf + done, len - done);
        if (n > 0) {
            done += static_cast<size_t>(n);
        } else if (n == 0) {
            return TransportError::io("connection closed by peer");
        } else {
            if (is_timeout_errno())
                return TransportError::timeout();
            return make_io_error("read");
        }
    }
    return std::nullopt;
}

} // namespace usp
