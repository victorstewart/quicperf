#pragma once

#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF)
#include "quicperf_rust_packet_ffi.h"
#endif

#if defined(QUICZIGPERF)
#include "quicperf_zig_packet_ffi.h"
#endif

#include <algorithm>
#include <array>
#include <cassert>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

struct PacketStreamDebug {
  bool found = false;
  uint64_t sendWriteOffset = 0;
  uint64_t sendSendOffset = 0;
  uint64_t sendAckOffset = 0;
  uint64_t sendWindow = 0;
  uint64_t sendRetransmitCount = 0;
  bool sendFinQueued = false;
  bool sendFinSent = false;
  bool sendFinLost = false;
  bool sendHasData = false;
  bool sendHasUnacked = false;
  uint64_t recvReadPos = 0;
  uint64_t recvHighestBuffered = 0;
  uint64_t recvFinOffset = 0;
  bool recvFinKnown = false;
  bool recvFinished = false;
  uint64_t recvChunkCount = 0;
  uint64_t bytesInFlight = 0;
  uint64_t cwnd = 0;
  uint64_t connSendWindow = 0;
};

#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF)
struct RustPacketAbi {
  using engine_t = qpf_engine_t;
  using config_t = qpf_config_t;
  using addr_t = qpf_addr_t;

  constexpr static const char *label = "rust packet ffi";
  constexpr static bool is_zig = false;

  static const char *lastError(void)
  {
    return qpf_last_error();
  }
  static engine_t *engineNew(config_t *config)
  {
    return qpf_engine_new(config);
  }
  static void engineFree(engine_t *engine)
  {
    qpf_engine_free(engine);
  }
  static int connect(engine_t *engine, const addr_t *remote, uint64_t nowUs, uint64_t *conn)
  {
    return qpf_engine_connect(engine, remote, nowUs, conn);
  }
  static int acceptConnection(engine_t *engine, uint64_t *conn)
  {
    return qpf_engine_accept_connection(engine, conn);
  }
  static int isConnected(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qpf_engine_is_connected(engine, conn, nowUs);
  }
  static int receive(engine_t *engine, const addr_t *remote, uint8_t *data, size_t len, uint64_t nowUs)
  {
    return qpf_engine_receive(engine, remote, data, len, nowUs);
  }
  static int pollTransmit(engine_t *engine, addr_t *remote, uint8_t *data, size_t capacity, size_t *len, uint64_t nowUs)
  {
    return qpf_engine_poll_transmit(engine, remote, data, capacity, len, nowUs);
  }
  static int nextTimeoutUs(engine_t *engine, uint64_t nowUs, uint64_t *timeoutUs)
  {
    return qpf_engine_next_timeout_us(engine, nowUs, timeoutUs);
  }
  static int onTimeout(engine_t *engine, uint64_t nowUs)
  {
    return qpf_engine_on_timeout(engine, nowUs);
  }
  static int exportResumptionState(engine_t *engine, uint64_t conn, uint8_t *data, size_t capacity, size_t *len, uint64_t nowUs)
  {
    return qpf_engine_export_resumption_state(engine, conn, data, capacity, len, nowUs);
  }
  static int importResumptionState(engine_t *engine, const uint8_t *data, size_t len, bool useZeroRtt, uint64_t nowUs)
  {
    return qpf_engine_import_resumption_state(engine, data, len, useZeroRtt, nowUs);
  }
  static int connectionResumed(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qpf_connection_resumed(engine, conn, nowUs);
  }
  static int zeroRttAttempted(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qpf_connection_zero_rtt_attempted(engine, conn, nowUs);
  }
  static int zeroRttAccepted(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qpf_connection_zero_rtt_accepted(engine, conn, nowUs);
  }
  static int zeroRttRejected(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qpf_connection_zero_rtt_rejected(engine, conn, nowUs);
  }
  static bool hasPendingAppData(engine_t *)
  {
    return false;
  }
  static int openBidi(engine_t *engine, uint64_t conn, uint64_t *stream, uint64_t nowUs)
  {
    return qpf_connection_open_bidi(engine, conn, stream, nowUs);
  }
  static int acceptBidi(engine_t *engine, uint64_t conn, uint64_t *stream, uint64_t nowUs)
  {
    return qpf_connection_accept_bidi(engine, conn, stream, nowUs);
  }
  static int streamSend(engine_t *engine, uint64_t conn, uint64_t stream, const uint8_t *data, size_t len, size_t *written, uint64_t nowUs)
  {
    return qpf_stream_send(engine, conn, stream, data, len, written, nowUs);
  }
  static int streamRecv(engine_t *engine, uint64_t conn, uint64_t stream, uint8_t *data, size_t capacity, size_t *read, bool *fin, uint64_t nowUs)
  {
    return qpf_stream_recv(engine, conn, stream, data, capacity, read, fin, nowUs);
  }
  static int streamFinish(engine_t *engine, uint64_t conn, uint64_t stream, uint64_t nowUs)
  {
    return qpf_stream_finish(engine, conn, stream, nowUs);
  }
  static bool streamDebug(engine_t *, uint64_t, uint64_t, PacketStreamDebug *)
  {
    return false;
  }
  static int datagramSend(engine_t *engine, uint64_t conn, const uint8_t *data, size_t len, uint64_t nowUs)
  {
    return qpf_datagram_send(engine, conn, data, len, nowUs);
  }
  static int datagramRecv(engine_t *engine, uint64_t conn, uint8_t *data, size_t capacity, size_t *read, uint64_t nowUs)
  {
    return qpf_datagram_recv(engine, conn, data, capacity, read, nowUs);
  }
  static void setLibrary(config_t& config, uint32_t libraryKind)
  {
    config.library = libraryKind;
  }
};
#endif

#if defined(QUICZIGPERF)
struct ZigPacketAbi {
  using engine_t = qzf_engine_t;
  using config_t = qzf_config_t;
  using addr_t = qzf_addr_t;

  constexpr static const char *label = "zig packet ffi";
  constexpr static bool is_zig = true;

  static const char *lastError(void)
  {
    return qzf_last_error();
  }
  static engine_t *engineNew(config_t *config)
  {
    return qzf_engine_new(config);
  }
  static void engineFree(engine_t *engine)
  {
    qzf_engine_free(engine);
  }
  static int connect(engine_t *engine, const addr_t *remote, uint64_t nowUs, uint64_t *conn)
  {
    return qzf_engine_connect(engine, remote, nowUs, conn);
  }
  static int acceptConnection(engine_t *engine, uint64_t *conn)
  {
    return qzf_engine_accept_connection(engine, conn);
  }
  static int isConnected(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qzf_engine_is_connected(engine, conn, nowUs);
  }
  static int receive(engine_t *engine, const addr_t *remote, uint8_t *data, size_t len, uint64_t nowUs)
  {
    return qzf_engine_receive(engine, remote, data, len, nowUs);
  }
  static int pollTransmit(engine_t *engine, addr_t *remote, uint8_t *data, size_t capacity, size_t *len, uint64_t nowUs)
  {
    return qzf_engine_poll_transmit(engine, remote, data, capacity, len, nowUs);
  }
  static int nextTimeoutUs(engine_t *engine, uint64_t nowUs, uint64_t *timeoutUs)
  {
    return qzf_engine_next_timeout_us(engine, nowUs, timeoutUs);
  }
  static int onTimeout(engine_t *engine, uint64_t nowUs)
  {
    return qzf_engine_on_timeout(engine, nowUs);
  }
  static int exportResumptionState(engine_t *engine, uint64_t conn, uint8_t *data, size_t capacity, size_t *len, uint64_t nowUs)
  {
    return qzf_engine_export_resumption_state(engine, conn, data, capacity, len, nowUs);
  }
  static int importResumptionState(engine_t *engine, const uint8_t *data, size_t len, bool useZeroRtt, uint64_t nowUs)
  {
    return qzf_engine_import_resumption_state(engine, data, len, useZeroRtt, nowUs);
  }
  static int connectionResumed(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qzf_connection_resumed(engine, conn, nowUs);
  }
  static int zeroRttAttempted(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qzf_connection_zero_rtt_attempted(engine, conn, nowUs);
  }
  static int zeroRttAccepted(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qzf_connection_zero_rtt_accepted(engine, conn, nowUs);
  }
  static int zeroRttRejected(engine_t *engine, uint64_t conn, uint64_t nowUs)
  {
    return qzf_connection_zero_rtt_rejected(engine, conn, nowUs);
  }
  static bool hasPendingAppData(engine_t *engine)
  {
    return qzf_engine_has_pending_app_data(engine) == 1;
  }
  static int openBidi(engine_t *engine, uint64_t conn, uint64_t *stream, uint64_t nowUs)
  {
    return qzf_connection_open_bidi(engine, conn, stream, nowUs);
  }
  static int acceptBidi(engine_t *engine, uint64_t conn, uint64_t *stream, uint64_t nowUs)
  {
    return qzf_connection_accept_bidi(engine, conn, stream, nowUs);
  }
  static int streamSend(engine_t *engine, uint64_t conn, uint64_t stream, const uint8_t *data, size_t len, size_t *written, uint64_t nowUs)
  {
    return qzf_stream_send(engine, conn, stream, data, len, written, nowUs);
  }
  static int streamRecv(engine_t *engine, uint64_t conn, uint64_t stream, uint8_t *data, size_t capacity, size_t *read, bool *fin, uint64_t nowUs)
  {
    return qzf_stream_recv(engine, conn, stream, data, capacity, read, fin, nowUs);
  }
  static int streamFinish(engine_t *engine, uint64_t conn, uint64_t stream, uint64_t nowUs)
  {
    return qzf_stream_finish(engine, conn, stream, nowUs);
  }
  static bool streamDebug(engine_t *engine, uint64_t conn, uint64_t stream, PacketStreamDebug *debug)
  {
    qzf_stream_debug_t raw = {};
    if (qzf_stream_debug(engine, conn, stream, &raw) != 1 || !raw.found)
    {
      return false;
    }
    debug->found = true;
    debug->sendWriteOffset = raw.send_write_offset;
    debug->sendSendOffset = raw.send_send_offset;
    debug->sendAckOffset = raw.send_ack_offset;
    debug->sendWindow = raw.send_window;
    debug->sendRetransmitCount = raw.send_retransmit_count;
    debug->sendFinQueued = raw.send_fin_queued;
    debug->sendFinSent = raw.send_fin_sent;
    debug->sendFinLost = raw.send_fin_lost;
    debug->sendHasData = raw.send_has_data;
    debug->sendHasUnacked = raw.send_has_unacked;
    debug->recvReadPos = raw.recv_read_pos;
    debug->recvHighestBuffered = raw.recv_highest_buffered;
    debug->recvFinOffset = raw.recv_fin_offset;
    debug->recvFinKnown = raw.recv_fin_known;
    debug->recvFinished = raw.recv_finished;
    debug->recvChunkCount = raw.recv_chunk_count;
    debug->bytesInFlight = raw.bytes_in_flight;
    debug->cwnd = raw.cwnd;
    debug->connSendWindow = raw.conn_send_window;
    return true;
  }
  static int datagramSend(engine_t *engine, uint64_t conn, const uint8_t *data, size_t len, uint64_t nowUs)
  {
    return qzf_datagram_send(engine, conn, data, len, nowUs);
  }
  static int datagramRecv(engine_t *engine, uint64_t conn, uint8_t *data, size_t capacity, size_t *read, uint64_t nowUs)
  {
    return qzf_datagram_recv(engine, conn, data, capacity, read, nowUs);
  }
  static void setLibrary(config_t&, uint32_t) {}
};
#endif

template <Mode mode, typename Abi, uint32_t libraryKind = 0>
class PacketEngineLibrary : public QuicLibrary<mode> {
private:

  using QuicLibrary<mode>::networkHub;

  typename Abi::engine_t *engine = nullptr;
  uint64_t connection = UINT64_MAX;
  uint64_t stream = UINT64_MAX;
  alignas(64) std::array<uint8_t, benchmarkAppChunkSize> buffer = {};
  bool debugTrace = false;
  bool stallTrace = false;
  bool importedResumption = false;
  bool importedZeroRtt = false;
  uint64_t outgoingZeroRttPackets = 0;
  uint64_t durationCompletedUnits = 0;
  double durationMeasuredSeconds = 0.0;

  enum class ServerPhase : uint8_t {
    acceptStream,
    readRequest,
    transfer,
    readDone,
    sendAck,
    finish,
    complete
  };

  enum class GenericPhase : uint8_t {
    readRequest,
    transfer,
    sendResponse,
    readDone,
    sendAck,
    readAck,
    finish,
    complete
  };

  static const char *genericPhaseName(GenericPhase phase)
  {
    switch (phase)
    {
      case GenericPhase::readRequest:
        return "readRequest";
      case GenericPhase::transfer:
        return "transfer";
      case GenericPhase::sendResponse:
        return "sendResponse";
      case GenericPhase::readDone:
        return "readDone";
      case GenericPhase::sendAck:
        return "sendAck";
      case GenericPhase::readAck:
        return "readAck";
      case GenericPhase::finish:
        return "finish";
      case GenericPhase::complete:
        return "complete";
    }
    return "unknown";
  }

  struct ServerConn {
    uint64_t conn = UINT64_MAX;
    uint64_t stream = UINT64_MAX;
    ServerPhase phase = ServerPhase::acceptStream;
    std::array<uint8_t, sizeof(uint64_t)> request = {};
    size_t requestRead = 0;
    uint64_t bytesRemaining = 0;
    uint8_t done = 0;
    size_t doneRead = 0;
    uint8_t ack = 0;
    std::array<uint8_t, sizeof(uint64_t)> durationAck = {};
    size_t ackSent = 0;
    uint64_t durationDeadlineUs = 0;
    uint64_t durationReceived = 0;
    bool durationMode = false;
  };

  struct GenericServerStream {
    uint64_t conn = UINT64_MAX;
    uint64_t stream = UINT64_MAX;
    GenericPhase phase = GenericPhase::readRequest;
    uint64_t requestValue = 0;
    std::array<uint8_t, sizeof(uint64_t)> request = {};
    uint64_t requestBytesRead = 0;
    uint64_t requestBytesExpected = 0;
    uint64_t payloadRemaining = 0;
    uint64_t responseRemaining = 0;
    uint8_t done = 0;
    size_t doneRead = 0;
    uint8_t ack = 0;
    size_t ackSent = 0;
    size_t ackRead = 0;
    bool peerFinReceived = false;
    bool finSent = false;
    bool durationDoneSignal = false;
  };

  struct GenericClientStream {
    uint64_t stream = UINT64_MAX;
    GenericPhase phase = GenericPhase::readRequest;
    uint64_t requestValue = 0;
    uint64_t requestBytesSent = 0;
    uint64_t requestBytesExpected = 0;
    uint64_t payloadRemaining = 0;
    uint64_t responseRemaining = 0;
    uint8_t done = 0;
    size_t doneSent = 0;
    uint8_t ack = 0;
    size_t ackRead = 0;
    size_t ackSent = 0;
    bool finSent = false;
  };

  struct DatagramServerConn {
    uint64_t conn = UINT64_MAX;
    uint64_t doneStream = UINT64_MAX;
    uint64_t received = 0;
    uint64_t echoed = 0;
    std::deque<uint64_t> pendingEchoes;
    std::vector<uint8_t> seen;
    uint8_t done = 0;
    size_t doneRead = 0;
    bool clientDone = false;
  };

  void check(int result) const
  {
    if (result < 0)
    {
      const char *error = Abi::lastError();
      fprintf(stderr, "%s error: %s\n", Abi::label, error == nullptr ? "unknown" : error);
      assert(result >= 0);
      abort();
    }
  }

  bool lastErrorIsInvalidStream(void) const
  {
    const char *error = Abi::lastError();
    return error != nullptr && strstr(error, "InvalidStreamId") != nullptr;
  }

  bool lastErrorIsStreamLimit(void) const
  {
    const char *error = Abi::lastError();
    return error != nullptr && strstr(error, "StreamLimit") != nullptr;
  }

  static void encodeU64(uint64_t value, uint8_t out[8])
  {
    for (int i = 7; i >= 0; --i)
    {
      out[i] = static_cast<uint8_t>(value & 0xff);
      value >>= 8;
    }
  }

  static uint64_t decodeU64(const uint8_t in[8])
  {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i)
    {
      value = (value << 8) | in[i];
    }
    return value;
  }

  static typename Abi::addr_t packetAddrFromSockaddr(const struct sockaddr *address)
  {
    const auto *addr6 = reinterpret_cast<const struct sockaddr_in6 *>(address);
    typename Abi::addr_t out = {};
    memcpy(out.ip, addr6->sin6_addr.s6_addr, sizeof(out.ip));
    out.port = ntohs(addr6->sin6_port);
    return out;
  }

  static struct sockaddr_in6 sockaddrFromPacketAddr(const typename Abi::addr_t& address)
  {
    struct sockaddr_in6 out = {};
    out.sin6_family = AF_INET6;
    out.sin6_port = htons(address.port);
    memcpy(out.sin6_addr.s6_addr, address.ip, sizeof(out.sin6_addr.s6_addr));
    return out;
  }

  uint64_t nowUs(void) const
  {
    return timeNowUs();
  }

  constexpr static uint64_t durationTransferRequest(void)
  {
    return UINT64_MAX;
  }

  bool durationModeActive(void) const
  {
    return benchmarkDurationModeActive() &&
           benchmarkTargetDurationMs > 0 &&
           supportsDurationMode(benchmarkScenario);
  }

  uint64_t durationDeadlineUs(uint64_t startUs) const
  {
    return startUs + benchmarkTargetDurationMs * 1000ULL;
  }

  void recordDurationResult(uint64_t completedUnits, uint64_t startUs, uint64_t endUs)
  {
    durationCompletedUnits = completedUnits;
    durationMeasuredSeconds = std::max(0.000001, static_cast<double>(endUs - startUs) / 1'000'000.0);
  }

  uint64_t durationGenericTransferBytesPerStream(uint64_t bytes, uint64_t streamCount) const
  {
    const uint64_t finiteBytesPerStream = std::max<uint64_t>(1, bytes / std::max<uint64_t>(1, streamCount));
    constexpr uint64_t maxDurationStreamBytes = uint64_t {benchmarkAppChunkSize} * 4U;
    return std::max<uint64_t>(
        1,
        std::min<uint64_t>(finiteBytesPerStream, maxDurationStreamBytes));
  }

  static bool decodeQuicVarInt(const uint8_t *data, size_t length, size_t& offset, uint64_t& value)
  {
    if (offset >= length)
    {
      return false;
    }
    const uint8_t first = data[offset];
    const size_t varIntLength = size_t {1} << (first >> 6);
    if (varIntLength > sizeof(uint64_t) || offset + varIntLength > length)
    {
      return false;
    }
    value = first & 0x3f;
    for (size_t i = 1; i < varIntLength; ++i)
    {
      value = (value << 8) | data[offset + i];
    }
    offset += varIntLength;
    return true;
  }

  static bool datagramContainsQuicZeroRtt(const uint8_t *data, size_t length)
  {
    constexpr uint8_t quicLongHeader = 0x80;
    constexpr uint8_t quicFixedBit = 0x40;
    constexpr uint8_t quicLongPacketTypeMask = 0x30;
    constexpr uint8_t quicInitialPacketType = 0x00;
    constexpr uint8_t quicZeroRttPacketType = 0x10;
    constexpr uint8_t quicRetryPacketType = 0x30;

    size_t offset = 0;
    while (offset < length)
    {
      const uint8_t first = data[offset];
      if ((first & (quicLongHeader | quicFixedBit)) != (quicLongHeader | quicFixedBit))
      {
        return false;
      }
      const uint8_t packetType = first & quicLongPacketTypeMask;
      if (packetType == quicZeroRttPacketType)
      {
        return true;
      }

      ++offset;
      if (offset + 4 > length)
      {
        return false;
      }
      offset += 4;

      if (offset >= length)
      {
        return false;
      }
      const size_t destinationConnectionIdLength = data[offset++];
      if (offset + destinationConnectionIdLength > length)
      {
        return false;
      }
      offset += destinationConnectionIdLength;

      if (offset >= length)
      {
        return false;
      }
      const size_t sourceConnectionIdLength = data[offset++];
      if (offset + sourceConnectionIdLength > length)
      {
        return false;
      }
      offset += sourceConnectionIdLength;

      if (packetType == quicRetryPacketType)
      {
        return false;
      }

      if (packetType == quicInitialPacketType)
      {
        uint64_t tokenLength = 0;
        if (!decodeQuicVarInt(data, length, offset, tokenLength) || tokenLength > length - offset)
        {
          return false;
        }
        offset += static_cast<size_t>(tokenLength);
      }

      uint64_t packetLength = 0;
      if (!decodeQuicVarInt(data, length, offset, packetLength) || packetLength > length - offset)
      {
        return false;
      }
      offset += static_cast<size_t>(packetLength);
    }
    return false;
  }

  void flushOutgoingPackets(void)
  {
    networkHub->drainSendCompletions();
    MultiUDPContext *packets = nullptr;
    while (true)
    {
      if (packets == nullptr)
      {
        packets = networkHub->sendPool.get();
        if (packets == nullptr)
        {
          networkHub->drainSendCompletions();
          packets = networkHub->sendPool.get();
        }
        if (packets == nullptr)
        {
          networkHub->flush();
          return;
        }
      }

      UDPContext *packet = &packets->msgs[packets->count];
      typename Abi::addr_t destination = {};
      size_t len = 0;
      int result = Abi::pollTransmit(engine, &destination, packet->buffer(), MAX_IPV6_UDP_PACKET_SIZE, &len, nowUs());
      check(result);
      if (result == 0)
      {
        break;
      }

      struct sockaddr_in6 sockaddr = sockaddrFromPacketAddr(destination);
      packet->setLength(len);
      packet->copyInAddress(reinterpret_cast<const struct sockaddr *>(&sockaddr));
      if constexpr (mode & Mode::client)
      {
        if (datagramContainsQuicZeroRtt(packet->buffer(), len))
        {
          ++outgoingZeroRttPackets;
        }
      }
      ++packets->count;

      if (packets->isFull())
      {
        networkHub->sendBatch(packets);
        packets = nullptr;
      }
    }

    if (packets != nullptr)
    {
      if (packets->count > 0)
      {
        networkHub->sendBatch(packets);
      }
      else
      {
        packets->reset();
        networkHub->sendPool.relinquish(packets);
      }
    }
    networkHub->flush();
  }

  void flushPackets(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (importedZeroRtt && outgoingZeroRttPackets == 0)
      {
        flushOutgoingPackets();
        drainReadyIncomingPackets();
        return;
      }
    }
    drainReadyIncomingPackets();
    flushOutgoingPackets();
    drainReadyIncomingPackets();
  }

  void drainReadyIncomingPackets(void)
  {
    networkHub->recvmsgWithTimeout(0, [&](UDPContext *msg) -> void {
      typename Abi::addr_t remote = packetAddrFromSockaddr(msg->address());
      check(Abi::receive(engine, &remote, msg->buffer(), msg->msg_len, nowUs()));
    });
  }

  void pumpOnce(uint64_t maxWaitUs = 100'000)
  {
    flushPackets();
    uint64_t timeoutUs = maxWaitUs;
    check(Abi::nextTimeoutUs(engine, nowUs(), &timeoutUs));
    timeoutUs = std::min<uint64_t>(timeoutUs, maxWaitUs);

    bool timedout = networkHub->recvmsgWithTimeout(static_cast<int64_t>(timeoutUs), [&](UDPContext *msg) -> void {
      typename Abi::addr_t remote = packetAddrFromSockaddr(msg->address());
      check(Abi::receive(engine, &remote, msg->buffer(), msg->msg_len, nowUs()));
    });

    uint64_t afterIoUs = nowUs();
    uint64_t dueUs = maxWaitUs;
    check(Abi::nextTimeoutUs(engine, afterIoUs, &dueUs));
    if (timedout || dueUs == 0)
    {
      check(Abi::onTimeout(engine, afterIoUs));
    }
    flushPackets();
  }

  void drainTerminalPackets(uint64_t waitUs = 0, int iterations = 64)
  {
    for (int i = 0; i < iterations; ++i)
    {
      pumpOnce(waitUs);
    }
  }

  size_t sendSome(uint64_t activeStream, const uint8_t *data, size_t length)
  {
    size_t written = 0;
    check(Abi::streamSend(engine, connection, activeStream, data, length, &written, nowUs()));
    flushPackets();
    return written;
  }

  size_t sendSome(ServerConn& active, const uint8_t *data, size_t length)
  {
    size_t written = 0;
    check(Abi::streamSend(engine, active.conn, active.stream, data, length, &written, nowUs()));
    flushPackets();
    return written;
  }

  size_t sendSome(GenericServerStream& active, const uint8_t *data, size_t length)
  {
    size_t written = 0;
    check(Abi::streamSend(engine, active.conn, active.stream, data, length, &written, nowUs()));
    flushPackets();
    return written;
  }

  std::pair<size_t, bool> recvSome(uint64_t activeStream, uint8_t *data, size_t length)
  {
    size_t read = 0;
    bool fin = false;
    check(Abi::streamRecv(engine, connection, activeStream, data, length, &read, &fin, nowUs()));
    flushPackets();
    return {read, fin};
  }

  bool recvSomeAllowInvalidStream(uint64_t activeStream, uint8_t *data, size_t length, size_t& read, bool& fin)
  {
    read = 0;
    fin = false;
    int result = Abi::streamRecv(engine, connection, activeStream, data, length, &read, &fin, nowUs());
    if (result < 0)
    {
      if (lastErrorIsInvalidStream())
      {
        flushPackets();
        return false;
      }
      check(result);
    }
    flushPackets();
    return true;
  }

  std::pair<size_t, bool> recvSome(ServerConn& active, uint8_t *data, size_t length)
  {
    size_t read = 0;
    bool fin = false;
    check(Abi::streamRecv(engine, active.conn, active.stream, data, length, &read, &fin, nowUs()));
    flushPackets();
    return {read, fin};
  }

  std::pair<size_t, bool> recvSome(GenericServerStream& active, uint8_t *data, size_t length)
  {
    size_t read = 0;
    bool fin = false;
    check(Abi::streamRecv(engine, active.conn, active.stream, data, length, &read, &fin, nowUs()));
    flushPackets();
    return {read, fin};
  }

  bool sendDatagram(uint64_t activeConn, const uint8_t *data, size_t length)
  {
    int result = Abi::datagramSend(engine, activeConn, data, length, nowUs());
    check(result);
    flushPackets();
    return result == 1;
  }

  bool queueDatagram(uint64_t activeConn, const uint8_t *data, size_t length)
  {
    int result = Abi::datagramSend(engine, activeConn, data, length, nowUs());
    check(result);
    return result == 1;
  }

  bool recvDatagram(uint64_t activeConn, uint8_t *data, size_t capacity, size_t& read)
  {
    read = 0;
    int result = Abi::datagramRecv(engine, activeConn, data, capacity, &read, nowUs());
    check(result);
    flushPackets();
    return result == 1;
  }

  bool popDatagram(uint64_t activeConn, uint8_t *data, size_t capacity, size_t& read)
  {
    read = 0;
    int result = Abi::datagramRecv(engine, activeConn, data, capacity, &read, nowUs());
    check(result);
    return result == 1;
  }

  void sendAll(const uint8_t *data, size_t length)
  {
    size_t offset = 0;
    while (offset < length)
    {
      size_t written = sendSome(stream, data + offset, length - offset);
      if (written == 0)
      {
        pumpOnce();
      }
      else
      {
        offset += written;
      }
    }
  }

  uint64_t openClientBidiStream(void)
  {
    uint64_t opened = UINT64_MAX;
    uint64_t attempts = 0;
    while (true)
    {
      int result = Abi::openBidi(engine, connection, &opened, nowUs());
      check(result);
      if (result == 1)
      {
        return opened;
      }
      ++attempts;
      if (debugTrace && (attempts % 1000) == 0)
      {
        fprintf(stderr, "%s debug=open_client_bidi_wait attempts=%" PRIu64 "\n", Abi::label, attempts);
      }
      pumpOnce();
    }
  }

  bool tryOpenClientBidiStreamUntil(uint64_t deadlineUs, uint64_t& opened)
  {
    opened = UINT64_MAX;
    while (nowUs() < deadlineUs)
    {
      int result = Abi::openBidi(engine, connection, &opened, nowUs());
      if (result < 0)
      {
        if (!lastErrorIsStreamLimit())
        {
          check(result);
        }
      }
      if (result == 1)
      {
        return true;
      }
      const uint64_t currentUs = nowUs();
      if (currentUs >= deadlineUs)
      {
        break;
      }
      pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
    }
    return false;
  }

  bool tryOpenClientBidiStreamBestEffortUntil(uint64_t deadlineUs, uint64_t& opened)
  {
    opened = UINT64_MAX;
    while (nowUs() < deadlineUs)
    {
      int result = Abi::openBidi(engine, connection, &opened, nowUs());
      if (result == 1)
      {
        return true;
      }
      const uint64_t currentUs = nowUs();
      if (currentUs >= deadlineUs)
      {
        break;
      }
      pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
    }
    return false;
  }

  void finishStream(uint64_t activeStream)
  {
    check(Abi::streamFinish(engine, connection, activeStream, nowUs()));
    flushPackets();
  }

  void finishStream(ServerConn& active)
  {
    check(Abi::streamFinish(engine, active.conn, active.stream, nowUs()));
    flushPackets();
  }

  void finishStream(GenericServerStream& active)
  {
    if (active.finSent)
    {
      return;
    }
    check(Abi::streamFinish(engine, active.conn, active.stream, nowUs()));
    active.finSent = true;
    flushPackets();
  }

  void recvExact(uint8_t *data, size_t length)
  {
    size_t offset = 0;
    while (offset < length)
    {
      auto [read, fin] = recvSome(stream, data + offset, length - offset);
      if (read == 0)
      {
        if (fin)
        {
          fprintf(stderr, "%s stream ended before expected bytes\n", Abi::label);
          abort();
        }
        pumpOnce();
      }
      else
      {
        offset += read;
      }
    }
  }

  void recvTerminalUploadAck(uint8_t *data, size_t length)
  {
    size_t offset = 0;
    while (offset < length)
    {
      size_t read = 0;
      bool fin = false;
      bool streamValid = recvSomeAllowInvalidStream(stream, data + offset, length - offset, read, fin);
      if (!streamValid)
      {
        return;
      }
      if (read == 0)
      {
        if (fin)
        {
          return;
        }
        pumpOnce();
      }
      else
      {
        offset += read;
      }
    }
  }

  bool recvDurationUploadCount(uint64_t deadlineUs, uint64_t& delivered)
  {
    std::array<uint8_t, sizeof(uint64_t)> ack = {};
    size_t offset = 0;
    while (offset < ack.size())
    {
      const uint64_t currentUs = nowUs();
      if (currentUs >= deadlineUs)
      {
        return false;
      }
      size_t read = 0;
      bool fin = false;
      bool streamValid = recvSomeAllowInvalidStream(stream, ack.data() + offset, ack.size() - offset, read, fin);
      if (!streamValid)
      {
        pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
        continue;
      }
      if (read > 0)
      {
        offset += read;
        if (offset == ack.size())
        {
          break;
        }
        if (fin)
        {
          return false;
        }
        continue;
      }
      if (fin)
      {
        return false;
      }
      pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
    }
    delivered = decodeU64(ack.data());
    return true;
  }

  void sendBytes(uint64_t bytes)
  {
    while (bytes > 0)
    {
      size_t chunk = static_cast<size_t>(std::min<uint64_t>(bytes, buffer.size()));
      sendAll(buffer.data(), chunk);
      bytes -= chunk;
    }
  }

  void recvBytes(uint64_t bytes)
  {
    while (bytes > 0)
    {
      size_t chunk = static_cast<size_t>(std::min<uint64_t>(bytes, buffer.size()));
      recvExact(buffer.data(), chunk);
      bytes -= chunk;
    }
  }

  bool processServer(ServerConn& active)
  {
    switch (active.phase)
    {
      case ServerPhase::acceptStream:
        {
          int result = Abi::acceptBidi(engine, active.conn, &active.stream, nowUs());
          check(result);
          if (result == 1)
          {
            active.phase = ServerPhase::readRequest;
            return true;
          }
          return false;
        }
      case ServerPhase::readRequest:
        {
          auto [read, fin] = recvSome(active, active.request.data() + active.requestRead, active.request.size() - active.requestRead);
          (void)fin;
          active.requestRead += read;
          if (active.requestRead == active.request.size())
          {
            active.bytesRemaining = decodeU64(active.request.data());
            active.durationMode = benchmarkDurationModeActive() &&
                                  active.bytesRemaining == durationTransferRequest();
            if (active.durationMode)
            {
              active.durationDeadlineUs = durationDeadlineUs(nowUs());
            }
            active.phase = ServerPhase::transfer;
          }
          return read > 0;
        }
      case ServerPhase::transfer:
        {
          if (!active.durationMode && active.bytesRemaining == 0)
          {
            active.phase = ServerPhase::readDone;
            return true;
          }
          if (benchmarkIsUpload())
          {
            if (active.durationMode && active.durationDeadlineUs != 0 &&
                nowUs() >= active.durationDeadlineUs)
            {
              encodeU64(active.durationReceived, active.durationAck.data());
              active.phase = ServerPhase::sendAck;
              return true;
            }
            size_t chunk = active.durationMode
                               ? buffer.size()
                               : static_cast<size_t>(std::min<uint64_t>(active.bytesRemaining, buffer.size()));
            auto [read, fin] = recvSome(active, buffer.data(), chunk);
            if (active.durationMode)
            {
              active.durationReceived += read;
              if (fin)
              {
                encodeU64(active.durationReceived, active.durationAck.data());
                active.phase = ServerPhase::sendAck;
                return true;
              }
            }
            else
            {
              active.bytesRemaining -= read;
            }
            return read > 0;
          }
          if (active.durationMode && active.doneRead < sizeof(active.done))
          {
            auto [read, fin] = recvSome(active, &active.done + active.doneRead, sizeof(active.done) - active.doneRead);
            active.doneRead += read;
            if (active.doneRead == sizeof(active.done) || fin)
            {
              active.phase = ServerPhase::finish;
              return true;
            }
            if (active.durationDeadlineUs != 0 &&
                nowUs() >= active.durationDeadlineUs + benchmarkDurationCompletionDrainUs)
            {
              active.phase = ServerPhase::finish;
              return true;
            }
          }
          size_t chunk = active.durationMode
                             ? buffer.size()
                             : static_cast<size_t>(std::min<uint64_t>(active.bytesRemaining, buffer.size()));
          size_t written = sendSome(active, buffer.data(), chunk);
          if (!active.durationMode)
          {
            active.bytesRemaining -= written;
          }
          return written > 0;
        }
      case ServerPhase::readDone:
        {
          auto [read, fin] = recvSome(active, &active.done + active.doneRead, sizeof(active.done) - active.doneRead);
          (void)fin;
          active.doneRead += read;
          if (active.doneRead == sizeof(active.done))
          {
            active.phase = ServerPhase::sendAck;
          }
          return read > 0;
        }
      case ServerPhase::sendAck:
        {
          const uint8_t *ackData = active.durationMode ? active.durationAck.data() : &active.ack;
          const size_t ackSize = active.durationMode ? active.durationAck.size() : sizeof(active.ack);
          size_t written = sendSome(active, ackData + active.ackSent, ackSize - active.ackSent);
          active.ackSent += written;
          if (active.ackSent == ackSize)
          {
            active.phase = ServerPhase::finish;
          }
          return written > 0;
        }
      case ServerPhase::finish:
        {
          check(Abi::streamFinish(engine, active.conn, active.stream, nowUs()));
          flushPackets();
          active.phase = ServerPhase::complete;
          return true;
        }
      case ServerPhase::complete:
        return false;
    }
    return false;
  }

  void runServerConnections(void)
  {
    std::vector<ServerConn> conns;
    conns.reserve(benchmarkServerTargetConnections);
    uint32_t completed = 0;
    while (completed < benchmarkServerTargetConnections)
    {
      bool progressed = false;
      while (conns.size() < benchmarkServerTargetConnections)
      {
        uint64_t accepted = UINT64_MAX;
        int result = Abi::acceptConnection(engine, &accepted);
        check(result);
        if (result != 1)
        {
          break;
        }
        conns.push_back(ServerConn {.conn = accepted});
        progressed = true;
      }

      completed = 0;
      for (ServerConn& active : conns)
      {
        if (active.phase == ServerPhase::complete)
        {
          ++completed;
          continue;
        }
        progressed = processServer(active) || progressed;
        if (active.phase == ServerPhase::complete)
        {
          ++completed;
        }
      }

      if (!progressed)
      {
        pumpOnce();
      }
    }
    drainTerminalPackets(1000, 100);
  }

  void runClientDownload(uint64_t bytes)
  {
    uint8_t request[8];
    encodeU64(bytes, request);
    sendAll(request, sizeof(request));
    recvBytes(bytes);
    uint8_t done = 0;
    sendAll(&done, sizeof(done));
    uint8_t ack = 0;
    recvExact(&ack, sizeof(ack));
    check(Abi::streamFinish(engine, connection, stream, nowUs()));
    flushPackets();
  }

  void runClientDownloadDuration(void)
  {
    uint8_t request[8];
    encodeU64(durationTransferRequest(), request);
    sendAll(request, sizeof(request));

    uint64_t received = 0;
    const uint64_t startUs = nowUs();
    const uint64_t deadlineUs = durationDeadlineUs(startUs);
    while (nowUs() < deadlineUs)
    {
      auto [read, fin] = recvSome(stream, buffer.data(), buffer.size());
      if (read > 0)
      {
        received += read;
        continue;
      }
      if (fin)
      {
        break;
      }
      const uint64_t currentUs = nowUs();
      if (currentUs >= deadlineUs)
      {
        break;
      }
      pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
    }
    const uint64_t measuredEndUs = std::min<uint64_t>(nowUs(), deadlineUs);
    recordDurationResult(received, startUs, measuredEndUs);

    uint8_t done = 0;
    sendAll(&done, sizeof(done));
    finishStream(stream);
    drainTerminalPackets(1000, 50);
  }

  void runClientUpload(uint64_t bytes)
  {
    uint8_t request[8];
    encodeU64(bytes, request);
    sendAll(request, sizeof(request));
    sendBytes(bytes);
    uint8_t done = 0;
    sendAll(&done, sizeof(done));
    uint8_t ack = 0;
    recvExact(&ack, sizeof(ack));
    check(Abi::streamFinish(engine, connection, stream, nowUs()));
    flushPackets();
  }

  void runClientUploadDuration(void)
  {
    uint8_t request[8];
    encodeU64(durationTransferRequest(), request);
    sendAll(request, sizeof(request));

    uint64_t sent = 0;
    const uint64_t startUs = nowUs();
    const uint64_t deadlineUs = durationDeadlineUs(startUs);
    while (nowUs() < deadlineUs)
    {
      const uint64_t currentUs = nowUs();
      if (currentUs >= deadlineUs)
      {
        break;
      }
      const size_t chunk = buffer.size();
      const size_t written = sendSome(stream, buffer.data(), chunk);
      if (written > 0)
      {
        sent += written;
        continue;
      }
      pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
    }
    const uint64_t measuredEndUs = std::min<uint64_t>(nowUs(), deadlineUs);

    uint64_t delivered = 0;
    if (!recvDurationUploadCount(nowUs() + benchmarkDurationCompletionDrainUs, delivered))
    {
      delivered = 0;
    }
    recordDurationResult(delivered, startUs, measuredEndUs);
    (void)sent;
    drainTerminalPackets(1000, 50);
  }

  uint64_t reqRespRequestSize(void) const
  {
    if (benchmarkScenario == BenchmarkScenario::stream_churn)
    {
      return 1;
    }
    if (benchmarkScenario == BenchmarkScenario::close_reset_cleanup)
    {
      return 1;
    }
    if (benchmarkScenario == BenchmarkScenario::small_payload_pps)
    {
      return benchmarkScenarioMessageBytes;
    }
    return benchmarkScenarioRequestBytes;
  }

  uint64_t reqRespResponseSize(void) const
  {
    if (benchmarkScenario == BenchmarkScenario::stream_churn)
    {
      return 1;
    }
    if (benchmarkScenario == BenchmarkScenario::close_reset_cleanup)
    {
      return 1;
    }
    if (benchmarkScenario == BenchmarkScenario::small_payload_pps)
    {
      return benchmarkScenarioMessageBytes;
    }
    return benchmarkScenarioResponseBytes;
  }

  bool runClientReqRespStream(GenericClientStream& active)
  {
    switch (active.phase)
    {
      case GenericPhase::readRequest:
        {
          while (active.requestBytesSent < active.requestBytesExpected)
          {
            size_t chunk = static_cast<size_t>(
                std::min<uint64_t>(active.requestBytesExpected - active.requestBytesSent, buffer.size()));
            size_t written = sendSome(active.stream, buffer.data(), chunk);
            if (written == 0)
            {
              return false;
            }
            active.requestBytesSent += written;
          }
          active.phase = GenericPhase::sendResponse;
          return true;
        }
      case GenericPhase::sendResponse:
        {
          if (active.responseRemaining == 0)
          {
            active.phase = GenericPhase::transfer;
            return true;
          }
          size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
          auto [read, fin] = recvSome(active.stream, buffer.data(), chunk);
          (void)fin;
          active.responseRemaining -= read;
          return read > 0;
        }
      case GenericPhase::transfer:
        {
          size_t written = sendSome(active.stream, &active.done + active.doneSent, sizeof(active.done) - active.doneSent);
          active.doneSent += written;
          if (active.doneSent == sizeof(active.done))
          {
            finishStream(active.stream);
            active.phase = GenericPhase::complete;
            return true;
          }
          return written > 0;
        }
      case GenericPhase::complete:
        return false;
      default:
        return false;
    }
  }

  void addClientReqRespStream(std::vector<GenericClientStream>& active,
                              uint64_t streamId,
                              uint64_t requestBytes,
                              uint64_t responseBytes)
  {
    active.push_back(GenericClientStream {
        .stream = streamId,
        .phase = GenericPhase::readRequest,
        .requestBytesExpected = requestBytes,
        .responseRemaining = responseBytes,
    });
    if (benchmarkScenario == BenchmarkScenario::zero_rtt_reqresp)
    {
      (void)runClientReqRespStream(active.back());
    }
  }

  void runClientReqRespLike(uint64_t operations)
  {
    std::vector<GenericClientStream> active;
    active.reserve(benchmarkScenarioStreamsInFlight);
    uint64_t opened = 0;
    uint64_t completed = 0;
    const uint64_t requestBytes = reqRespRequestSize();
    const uint64_t responseBytes = reqRespResponseSize();

    while (completed < operations)
    {
      while (opened < operations && active.size() < benchmarkScenarioStreamsInFlight)
      {
        addClientReqRespStream(
            active,
            openClientBidiStream(),
            requestBytes,
            responseBytes);
        ++opened;
      }

      bool progressed = false;
      for (auto& streamState : active)
      {
        if (streamState.phase == GenericPhase::complete)
        {
          continue;
        }
        progressed = runClientReqRespStream(streamState) || progressed;
      }

      active.erase(std::remove_if(active.begin(), active.end(), [&](const GenericClientStream& streamState) {
                     if (streamState.phase == GenericPhase::complete)
                     {
                       ++completed;
                       return true;
                     }
                     return false;
                   }),
                   active.end());

      if (!progressed)
      {
        pumpOnce();
      }
    }
  }

  void runClientReqRespLikeDuration(void)
  {
    std::vector<GenericClientStream> active;
    active.reserve(benchmarkScenarioStreamsInFlight);
    uint64_t opened = 0;
    uint64_t measuredCompleted = 0;
    const uint64_t requestBytes = reqRespRequestSize();
    const uint64_t responseBytes = reqRespResponseSize();
    const uint64_t startUs = nowUs();
    const uint64_t deadlineUs = durationDeadlineUs(startUs);

    while (nowUs() < deadlineUs)
    {
      while (nowUs() < deadlineUs && opened < benchmarkScenarioOperations && active.size() < benchmarkScenarioStreamsInFlight)
      {
        uint64_t streamId = UINT64_MAX;
        if (!tryOpenClientBidiStreamUntil(deadlineUs, streamId))
        {
          break;
        }
        addClientReqRespStream(active, streamId, requestBytes, responseBytes);
        ++opened;
      }

      bool progressed = false;
      for (auto& streamState : active)
      {
        if (streamState.phase == GenericPhase::complete)
        {
          continue;
        }
        progressed = runClientReqRespStream(streamState) || progressed;
      }

      active.erase(std::remove_if(active.begin(), active.end(), [&](const GenericClientStream& streamState) {
                     if (streamState.phase == GenericPhase::complete)
                     {
                       if (nowUs() <= deadlineUs)
                       {
                         ++measuredCompleted;
                       }
                       return true;
                     }
                     return false;
                   }),
                   active.end());

      if (!progressed)
      {
        const uint64_t currentUs = nowUs();
        if (currentUs >= deadlineUs)
        {
          break;
        }
        pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
      }
    }

    const uint64_t measuredEndUs = std::min<uint64_t>(nowUs(), deadlineUs);
    const uint64_t drainDeadlineUs = nowUs() + benchmarkDurationCompletionDrainUs;
    while (!active.empty() && nowUs() < drainDeadlineUs)
    {
      bool progressed = false;
      for (auto& streamState : active)
      {
        if (streamState.phase == GenericPhase::complete)
        {
          continue;
        }
        progressed = runClientReqRespStream(streamState) || progressed;
      }

      active.erase(std::remove_if(active.begin(), active.end(), [](const GenericClientStream& streamState) {
                     return streamState.phase == GenericPhase::complete;
                   }),
                   active.end());

      if (!progressed)
      {
        pumpOnce(1000);
      }
    }

    uint64_t doneStream = UINT64_MAX;
    if (tryOpenClientBidiStreamBestEffortUntil(nowUs() + benchmarkDurationCompletionDrainUs, doneStream))
    {
      finishStream(doneStream);
    }
    drainTerminalPackets(1000, 50);
    (void)opened;
    recordDurationResult(measuredCompleted, startUs, measuredEndUs);
  }

  bool processClientTransferStream(GenericClientStream& active)
  {
    switch (active.phase)
    {
      case GenericPhase::readRequest:
        {
          uint8_t request[8];
          encodeU64(active.requestValue, request);
          while (active.requestBytesSent < sizeof(request))
          {
            size_t written = sendSome(active.stream, request + active.requestBytesSent, sizeof(request) - active.requestBytesSent);
            if (written == 0)
            {
              return false;
            }
            active.requestBytesSent += written;
          }
          if (benchmarkScenario == BenchmarkScenario::multistream_upload)
          {
            active.phase = GenericPhase::transfer;
          }
          else
          {
            active.phase = GenericPhase::sendResponse;
          }
          return true;
        }
      case GenericPhase::transfer:
        {
          if (benchmarkScenario == BenchmarkScenario::multistream_download)
          {
            size_t written = sendSome(active.stream, &active.done + active.doneSent, sizeof(active.done) - active.doneSent);
            active.doneSent += written;
            if (active.doneSent == sizeof(active.done))
            {
              active.phase = GenericPhase::readAck;
              return true;
            }
            return written > 0;
          }
          if (active.payloadRemaining == 0)
          {
            if (benchmarkScenario == BenchmarkScenario::multistream_upload && !active.finSent)
            {
              finishStream(active.stream);
              active.finSent = true;
            }
            active.phase = GenericPhase::sendResponse;
            return true;
          }
          size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
          size_t written = sendSome(active.stream, buffer.data(), chunk);
          active.payloadRemaining -= written;
          return written > 0;
        }
      case GenericPhase::sendResponse:
        {
          if (active.responseRemaining == 0)
          {
            active.phase = GenericPhase::complete;
            return true;
          }
          size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
          size_t read = 0;
          bool fin = false;
          bool streamValid = recvSomeAllowInvalidStream(active.stream, buffer.data(), chunk, read, fin);
          if (!streamValid && benchmarkScenario == BenchmarkScenario::multistream_upload)
          {
            active.responseRemaining = 0;
            active.phase = GenericPhase::complete;
            return true;
          }
          active.responseRemaining -= read;
          if (active.responseRemaining == 0 || (fin && benchmarkScenario == BenchmarkScenario::multistream_upload))
          {
            active.responseRemaining = 0;
            if (benchmarkScenario == BenchmarkScenario::multistream_download)
            {
              active.phase = GenericPhase::transfer;
            }
            else if (benchmarkScenario == BenchmarkScenario::multistream_upload)
            {
              active.phase = GenericPhase::complete;
            }
            else
            {
              active.phase = GenericPhase::complete;
            }
          }
          return read > 0;
        }
      case GenericPhase::readAck:
        {
          size_t read = 0;
          bool fin = false;
          bool streamValid = recvSomeAllowInvalidStream(active.stream, &active.ack + active.ackRead, sizeof(active.ack) - active.ackRead, read, fin);
          active.ackRead += read;
          if (!streamValid || active.ackRead == sizeof(active.ack) || fin)
          {
            if (!active.finSent && streamValid)
            {
              finishStream(active.stream);
              active.finSent = true;
            }
            active.phase = GenericPhase::complete;
            return true;
          }
          return read > 0;
        }
      case GenericPhase::finish:
        {
          size_t written = sendSome(active.stream, &active.done + active.doneSent, sizeof(active.done) - active.doneSent);
          active.doneSent += written;
          if (active.doneSent == sizeof(active.done))
          {
            finishStream(active.stream);
            active.phase = GenericPhase::complete;
            return true;
          }
          return written > 0;
        }
      case GenericPhase::complete:
        return false;
      default:
        return false;
    }
  }

  void runClientMultistream(uint64_t bytes)
  {
    const uint64_t streamCount = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    const uint64_t bytesPerStream = std::max<uint64_t>(1, bytes / streamCount);
    std::vector<GenericClientStream> active;
    active.reserve(streamCount);
    for (uint64_t i = 0; i < streamCount; ++i)
    {
      const uint64_t streamBytes = i + 1 == streamCount ? bytes - (bytesPerStream * (streamCount - 1)) : bytesPerStream;
      active.push_back(GenericClientStream {
          .stream = openClientBidiStream(),
          .phase = GenericPhase::readRequest,
          .requestValue = streamBytes,
          .payloadRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? streamBytes : 0,
          .responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : streamBytes,
      });
    }

    uint64_t completed = 0;
    uint64_t idleLoops = 0;
    uint64_t lastStallDumpUs = nowUs();
    while (completed < streamCount)
    {
      bool progressed = false;
      completed = 0;
      for (auto& streamState : active)
      {
        if (streamState.phase != GenericPhase::complete)
        {
          progressed = processClientTransferStream(streamState) || progressed;
        }
        if (streamState.phase == GenericPhase::complete)
        {
          ++completed;
        }
      }
      if (!progressed)
      {
        ++idleLoops;
        const uint64_t idleNowUs = nowUs();
        const bool dumpDebug = debugTrace && (idleLoops % 100'000) == 0;
        const bool dumpStall = stallTrace && idleNowUs - lastStallDumpUs >= 1'000'000;
        if (dumpDebug || dumpStall)
        {
          lastStallDumpUs = idleNowUs;
          fprintf(stderr, "%s debug=client_bidi_idle loops=%" PRIu64 " completed=%" PRIu64 "/%" PRIu64,
                  Abi::label, idleLoops, completed, streamCount);
          for (const auto& streamState : active)
          {
            fprintf(stderr, " stream=%" PRIu64 " phase=%s payload=%" PRIu64 " response=%" PRIu64 " doneSent=%zu",
                    streamState.stream, genericPhaseName(streamState.phase), streamState.payloadRemaining,
                    streamState.responseRemaining, streamState.doneSent);
            PacketStreamDebug streamDebug = {};
            if (Abi::streamDebug(engine, connection, streamState.stream, &streamDebug))
            {
              fprintf(stderr,
                      " send=%" PRIu64 "/%" PRIu64 "/%" PRIu64 " swin=%" PRIu64 " cwin=%" PRIu64 " rtx=%" PRIu64
                      " fin=%d/%d/%d hdata=%d hunacked=%d bif=%" PRIu64 " cwnd=%" PRIu64
                      " recv=%" PRIu64 "/%" PRIu64 " chunks=%" PRIu64 " rfin=%d/%" PRIu64 "/%d",
                      streamDebug.sendAckOffset, streamDebug.sendSendOffset, streamDebug.sendWriteOffset,
                      streamDebug.sendWindow, streamDebug.connSendWindow,
                      streamDebug.sendRetransmitCount,
                      streamDebug.sendFinQueued ? 1 : 0, streamDebug.sendFinSent ? 1 : 0, streamDebug.sendFinLost ? 1 : 0,
                      streamDebug.sendHasData ? 1 : 0, streamDebug.sendHasUnacked ? 1 : 0,
                      streamDebug.bytesInFlight, streamDebug.cwnd,
                      streamDebug.recvReadPos, streamDebug.recvHighestBuffered, streamDebug.recvChunkCount,
                      streamDebug.recvFinKnown ? 1 : 0, streamDebug.recvFinOffset, streamDebug.recvFinished ? 1 : 0);
            }
          }
          fprintf(stderr, "\n");
        }
        pumpOnce();
      }
      else
      {
        idleLoops = 0;
      }
    }
  }

  bool processClientMultistreamDurationStream(GenericClientStream& active, uint64_t deadlineUs)
  {
    switch (active.phase)
    {
      case GenericPhase::readRequest:
        {
          uint8_t request[8];
          encodeU64(active.requestValue, request);
          while (active.requestBytesSent < sizeof(request))
          {
            size_t written = sendSome(active.stream, request + active.requestBytesSent, sizeof(request) - active.requestBytesSent);
            if (written == 0)
            {
              return false;
            }
            active.requestBytesSent += written;
          }
          active.phase = benchmarkScenario == BenchmarkScenario::multistream_upload
                             ? GenericPhase::transfer
                             : GenericPhase::sendResponse;
          return true;
        }
      case GenericPhase::transfer:
        {
          if (active.payloadRemaining == 0)
          {
            if (!active.finSent)
            {
              finishStream(active.stream);
              active.finSent = true;
            }
            active.phase = GenericPhase::sendResponse;
            return true;
          }
          size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
          size_t written = sendSome(active.stream, buffer.data(), chunk);
          active.payloadRemaining -= written;
          if (written > 0 && nowUs() <= deadlineUs)
          {
            durationCompletedUnits += written;
          }
          return written > 0;
        }
      case GenericPhase::sendResponse:
        {
          if (active.responseRemaining == 0)
          {
            active.phase = GenericPhase::complete;
            return true;
          }
          size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
          size_t read = 0;
          bool fin = false;
          bool streamValid = recvSomeAllowInvalidStream(active.stream, buffer.data(), chunk, read, fin);
          if (!streamValid && benchmarkScenario == BenchmarkScenario::multistream_upload)
          {
            active.responseRemaining = 0;
            active.phase = GenericPhase::complete;
            return true;
          }
          active.responseRemaining -= read;
          if (read > 0 &&
              benchmarkScenario == BenchmarkScenario::multistream_download &&
              nowUs() <= deadlineUs)
          {
            durationCompletedUnits += read;
          }
          if (active.responseRemaining == 0 || (fin && benchmarkScenario == BenchmarkScenario::multistream_upload))
          {
            active.responseRemaining = 0;
            if (benchmarkScenario == BenchmarkScenario::multistream_download && !active.finSent)
            {
              finishStream(active.stream);
              active.finSent = true;
            }
            active.phase = GenericPhase::complete;
          }
          return read > 0 || fin;
        }
      case GenericPhase::complete:
        return false;
      default:
        return processClientTransferStream(active);
    }
  }

  void runClientMultistreamDuration(uint64_t bytes)
  {
    const uint64_t streamCount = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    const uint64_t streamBytes = durationGenericTransferBytesPerStream(bytes, streamCount);
    std::vector<GenericClientStream> active;
    active.reserve(streamCount);
    uint64_t doneStream = openClientBidiStream();
    durationCompletedUnits = 0;
    durationMeasuredSeconds = 0.0;
    const uint64_t startUs = nowUs();
    const uint64_t deadlineUs = durationDeadlineUs(startUs);

    while (nowUs() < deadlineUs)
    {
      while (active.size() < streamCount && nowUs() < deadlineUs)
      {
        uint64_t openedStream = UINT64_MAX;
        if (!tryOpenClientBidiStreamUntil(deadlineUs, openedStream))
        {
          break;
        }
        active.push_back(GenericClientStream {
            .stream = openedStream,
            .phase = GenericPhase::readRequest,
            .requestValue = streamBytes,
            .payloadRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? streamBytes : 0,
            .responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : streamBytes,
        });
      }

      bool progressed = false;
      for (auto& streamState : active)
      {
        if (streamState.phase != GenericPhase::complete)
        {
          progressed = processClientMultistreamDurationStream(streamState, deadlineUs) || progressed;
        }
      }
      active.erase(std::remove_if(active.begin(), active.end(), [](const GenericClientStream& streamState) {
                     return streamState.phase == GenericPhase::complete;
                   }),
                   active.end());

      if (!progressed)
      {
        const uint64_t currentUs = nowUs();
        if (currentUs >= deadlineUs)
        {
          break;
        }
        pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
      }
    }

    const uint64_t measuredEndUs = std::min<uint64_t>(nowUs(), deadlineUs);
    recordDurationResult(durationCompletedUnits, startUs, measuredEndUs);
    for (auto& streamState : active)
    {
      if (!streamState.finSent)
      {
        finishStream(streamState.stream);
        streamState.finSent = true;
      }
    }
    finishStream(doneStream);
    drainTerminalPackets(1000, 100);
  }

  bool processClientBidiStream(GenericClientStream& active)
  {
    if (active.phase == GenericPhase::readDone)
    {
      if (active.doneSent < sizeof(active.done))
      {
        size_t written = sendSome(active.stream, &active.done + active.doneSent, sizeof(active.done) - active.doneSent);
        active.doneSent += written;
        if (written == 0)
        {
          return false;
        }
      }
      active.phase = GenericPhase::readAck;
      return true;
    }
    if (active.phase == GenericPhase::readAck)
    {
      size_t read = 0;
      bool fin = false;
      bool streamValid = recvSomeAllowInvalidStream(active.stream, &active.ack + active.ackRead, sizeof(active.ack) - active.ackRead, read, fin);
      active.ackRead += read;
      if (!streamValid || active.ackRead == sizeof(active.ack) || fin)
      {
        if (!streamValid || (fin && active.ackRead == 0))
        {
          active.phase = GenericPhase::complete;
        }
        else
        {
          active.phase = GenericPhase::sendAck;
        }
        return true;
      }
      return read > 0;
    }
    if (active.phase == GenericPhase::sendAck)
    {
      size_t written = sendSome(active.stream, &active.ack + active.ackSent, sizeof(active.ack) - active.ackSent);
      active.ackSent += written;
      if (active.ackSent == sizeof(active.ack))
      {
        if (!active.finSent)
        {
          finishStream(active.stream);
          active.finSent = true;
        }
        active.phase = GenericPhase::complete;
        return true;
      }
      return written > 0;
    }

    bool progressed = false;
    if (active.requestBytesSent < sizeof(uint64_t))
    {
      uint8_t request[8];
      encodeU64(active.requestValue, request);
      size_t written = sendSome(active.stream, request + active.requestBytesSent, sizeof(request) - active.requestBytesSent);
      active.requestBytesSent += written;
      progressed = written > 0 || progressed;
      if (active.requestBytesSent < sizeof(request))
      {
        return progressed;
      }
    }
    if (active.payloadRemaining > 0)
    {
      size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
      size_t written = sendSome(active.stream, buffer.data(), chunk);
      active.payloadRemaining -= written;
      progressed = written > 0 || progressed;
    }
    if (active.responseRemaining > 0)
    {
      size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
      auto [read, fin] = recvSome(active.stream, buffer.data(), chunk);
      (void)fin;
      active.responseRemaining -= read;
      progressed = read > 0 || progressed;
    }
    if (active.payloadRemaining == 0 && active.responseRemaining == 0)
    {
      active.phase = GenericPhase::readDone;
      progressed = true;
    }
    return progressed;
  }

  void runClientBidi(uint64_t bytes)
  {
    const uint64_t streamCount = 1;
    const uint64_t bytesPerStream = std::max<uint64_t>(1, bytes / streamCount);
    std::vector<GenericClientStream> active;
    active.reserve(streamCount);
    for (uint64_t i = 0; i < streamCount; ++i)
    {
      const uint64_t streamBytes = i + 1 == streamCount ? bytes - (bytesPerStream * (streamCount - 1)) : bytesPerStream;
      active.push_back(GenericClientStream {
          .stream = openClientBidiStream(),
          .requestValue = streamBytes,
          .payloadRemaining = streamBytes,
          .responseRemaining = streamBytes,
      });
    }
    uint64_t completed = 0;
    uint64_t idleLoops = 0;
    uint64_t lastStallDumpUs = nowUs();
    while (completed < streamCount)
    {
      bool progressed = false;
      completed = 0;
      for (auto& streamState : active)
      {
        if (streamState.phase != GenericPhase::complete)
        {
          progressed = processClientBidiStream(streamState) || progressed;
        }
        if (streamState.phase == GenericPhase::complete)
        {
          ++completed;
        }
      }
      const uint64_t loopNowUs = nowUs();
      if (stallTrace && loopNowUs - lastStallDumpUs >= 1'000'000)
      {
        lastStallDumpUs = loopNowUs;
        fprintf(stderr, "%s debug=client_bidi_loop completed=%" PRIu64 "/%" PRIu64 " progressed=%d",
                Abi::label, completed, streamCount, progressed ? 1 : 0);
        for (const auto& streamState : active)
        {
          fprintf(stderr, " stream=%" PRIu64 " phase=%s requestSent=%" PRIu64 " payload=%" PRIu64 " response=%" PRIu64 " doneSent=%zu finSent=%d",
                  streamState.stream, genericPhaseName(streamState.phase), streamState.requestBytesSent,
                  streamState.payloadRemaining, streamState.responseRemaining, streamState.doneSent,
                  streamState.finSent ? 1 : 0);
          PacketStreamDebug streamDebug = {};
          if (Abi::streamDebug(engine, connection, streamState.stream, &streamDebug))
          {
            fprintf(stderr,
                    " send=%" PRIu64 "/%" PRIu64 "/%" PRIu64 " swin=%" PRIu64 " cwin=%" PRIu64 " rtx=%" PRIu64
                    " fin=%d/%d/%d hdata=%d hunacked=%d bif=%" PRIu64 " cwnd=%" PRIu64
                    " recv=%" PRIu64 "/%" PRIu64 " chunks=%" PRIu64 " rfin=%d/%" PRIu64 "/%d",
                    streamDebug.sendAckOffset, streamDebug.sendSendOffset, streamDebug.sendWriteOffset,
                    streamDebug.sendWindow, streamDebug.connSendWindow,
                    streamDebug.sendRetransmitCount,
                    streamDebug.sendFinQueued ? 1 : 0, streamDebug.sendFinSent ? 1 : 0, streamDebug.sendFinLost ? 1 : 0,
                    streamDebug.sendHasData ? 1 : 0, streamDebug.sendHasUnacked ? 1 : 0,
                    streamDebug.bytesInFlight, streamDebug.cwnd,
                    streamDebug.recvReadPos, streamDebug.recvHighestBuffered, streamDebug.recvChunkCount,
                    streamDebug.recvFinKnown ? 1 : 0, streamDebug.recvFinOffset, streamDebug.recvFinished ? 1 : 0);
          }
        }
        fprintf(stderr, "\n");
      }
      if (!progressed)
      {
        ++idleLoops;
        if (debugTrace && (idleLoops % 100'000) == 0)
        {
          fprintf(stderr, "%s debug=client_bidi_idle loops=%" PRIu64 " completed=%" PRIu64 "/%" PRIu64,
                  Abi::label, idleLoops, completed, streamCount);
          for (const auto& streamState : active)
          {
            fprintf(stderr, " stream=%" PRIu64 " phase=%s requestSent=%" PRIu64 " payload=%" PRIu64 " response=%" PRIu64 " doneSent=%zu finSent=%d",
                    streamState.stream, genericPhaseName(streamState.phase), streamState.requestBytesSent,
                    streamState.payloadRemaining, streamState.responseRemaining, streamState.doneSent,
                    streamState.finSent ? 1 : 0);
          }
          fprintf(stderr, "\n");
        }
        pumpOnce();
      }
      else
      {
        idleLoops = 0;
      }
    }
  }

  bool processClientBidiDurationStream(GenericClientStream& active, uint64_t deadlineUs)
  {
    bool progressed = false;
    if (active.requestBytesSent < sizeof(uint64_t))
    {
      uint8_t request[8];
      encodeU64(active.requestValue, request);
      size_t written = sendSome(active.stream, request + active.requestBytesSent, sizeof(request) - active.requestBytesSent);
      active.requestBytesSent += written;
      progressed = written > 0 || progressed;
      if (active.requestBytesSent < sizeof(request))
      {
        return progressed;
      }
    }
    if (active.payloadRemaining > 0)
    {
      size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
      size_t written = sendSome(active.stream, buffer.data(), chunk);
      active.payloadRemaining -= written;
      if (written > 0 && nowUs() <= deadlineUs)
      {
        durationCompletedUnits += written;
      }
      progressed = written > 0 || progressed;
    }
    if (active.responseRemaining > 0)
    {
      size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
      auto [read, fin] = recvSome(active.stream, buffer.data(), chunk);
      (void)fin;
      active.responseRemaining -= read;
      if (read > 0 && nowUs() <= deadlineUs)
      {
        durationCompletedUnits += read;
      }
      progressed = read > 0 || progressed;
    }
    if (active.payloadRemaining == 0 && active.responseRemaining == 0)
    {
      if (!active.finSent)
      {
        finishStream(active.stream);
        active.finSent = true;
      }
      active.phase = GenericPhase::complete;
      progressed = true;
    }
    return progressed;
  }

  void runClientBidiDuration(uint64_t bytes)
  {
    constexpr uint64_t streamCount = 1;
    const uint64_t streamBytes = durationGenericTransferBytesPerStream(bytes, streamCount);
    std::vector<GenericClientStream> active;
    active.reserve(streamCount);
    uint64_t doneStream = openClientBidiStream();
    durationCompletedUnits = 0;
    durationMeasuredSeconds = 0.0;
    const uint64_t startUs = nowUs();
    const uint64_t deadlineUs = durationDeadlineUs(startUs);

    while (nowUs() < deadlineUs)
    {
      while (active.size() < streamCount && nowUs() < deadlineUs)
      {
        uint64_t openedStream = UINT64_MAX;
        if (!tryOpenClientBidiStreamUntil(deadlineUs, openedStream))
        {
          break;
        }
        active.push_back(GenericClientStream {
            .stream = openedStream,
            .requestValue = streamBytes,
            .payloadRemaining = streamBytes,
            .responseRemaining = streamBytes,
        });
      }

      bool progressed = false;
      for (auto& streamState : active)
      {
        if (streamState.phase != GenericPhase::complete)
        {
          progressed = processClientBidiDurationStream(streamState, deadlineUs) || progressed;
        }
      }
      active.erase(std::remove_if(active.begin(), active.end(), [](const GenericClientStream& streamState) {
                     return streamState.phase == GenericPhase::complete;
                   }),
                   active.end());
      if (!progressed)
      {
        const uint64_t currentUs = nowUs();
        if (currentUs >= deadlineUs)
        {
          break;
        }
        pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
      }
    }

    const uint64_t measuredEndUs = std::min<uint64_t>(nowUs(), deadlineUs);
    recordDurationResult(durationCompletedUnits, startUs, measuredEndUs);
    for (auto& streamState : active)
    {
      if (!streamState.finSent)
      {
        finishStream(streamState.stream);
        streamState.finSent = true;
      }
    }
    finishStream(doneStream);
    drainTerminalPackets(1000, 100);
  }

  void runClientDatagrams(uint64_t operations)
  {
    const size_t payloadSize = benchmarkDatagramPayloadBytesForNoMssApiLimit(
        buffer.size(),
        benchmarkUdpPayloadSize);
    if (payloadSize == 0 || payloadSize > buffer.size())
    {
      fprintf(stderr, "%s invalid DATAGRAM payload size %zu\n", Abi::label, payloadSize);
      abort();
    }

    uint64_t sent = 0;
    uint64_t received = 0;
    const uint64_t burstLimit = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    bool doneStreamSent = false;
    uint64_t drainDeadlineUs = 0;
    std::vector<uint8_t> seen(benchmarkDatagramSeenBytes(operations), 0);
    while (sent < operations || !doneStreamSent || drainDeadlineUs == 0 || nowUs() < drainDeadlineUs)
    {
      bool progressed = false;
      uint64_t sentThisLoop = 0;
      while (sent < operations && sentThisLoop < burstLimit)
      {
        benchmarkFillDatagramPayload(buffer.data(), payloadSize, networkHub->junk, sent);
        if (!queueDatagram(connection, buffer.data(), payloadSize))
        {
          break;
        }
        ++sent;
        ++sentThisLoop;
        progressed = true;
      }
      flushOutgoingPackets();

      size_t read = 0;
      drainReadyIncomingPackets();
      while (popDatagram(connection, buffer.data(), buffer.size(), read))
      {
        const uint64_t sequence = benchmarkDecodeDatagramSequence(buffer.data(), read);
        if (benchmarkMarkDatagramSeen(seen, sequence, operations))
        {
          ++received;
          progressed = true;
        }
      }
      if (sent >= operations && !doneStreamSent)
      {
        uint64_t doneStream = openClientBidiStream();
        uint8_t done = 0;
        size_t doneWritten = 0;
        while (doneWritten < sizeof(done))
        {
          size_t written = sendSome(doneStream, &done + doneWritten, sizeof(done) - doneWritten);
          if (written == 0)
          {
            pumpOnce();
          }
          else
          {
            doneWritten += written;
          }
        }
        finishStream(doneStream);
        doneStreamSent = true;
        progressed = true;
      }
      if (doneStreamSent && drainDeadlineUs == 0)
      {
        drainDeadlineUs = received >= sent ? nowUs() : nowUs() + benchmarkDatagramDrainUs;
      }
      else if (doneStreamSent && received >= sent)
      {
        drainDeadlineUs = nowUs();
      }

      if (!progressed)
      {
        pumpOnce();
      }
    }
    benchmarkRecordDatagramClientCounters(sent, received);
  }

  void runClientDatagramsDuration(void)
  {
    const size_t payloadSize = benchmarkDatagramPayloadBytesForNoMssApiLimit(
        buffer.size(),
        benchmarkUdpPayloadSize);
    if (payloadSize == 0 || payloadSize > buffer.size())
    {
      fprintf(stderr, "%s invalid DATAGRAM payload size %zu\n", Abi::label, payloadSize);
      abort();
    }

    uint64_t sent = 0;
    uint64_t received = 0;
    const uint64_t burstLimit = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    const bool finiteOperationCap = benchmarkScenarioOperations > 0;
    const uint64_t operationCap = finiteOperationCap
                                      ? benchmarkScenarioOperations
                                      : std::numeric_limits<uint64_t>::max();
    std::vector<uint8_t> seen(finiteOperationCap ? benchmarkDatagramSeenBytes(operationCap) : 0, 0);
    const uint64_t startUs = nowUs();
    const uint64_t deadlineUs = durationDeadlineUs(startUs);
    while (nowUs() < deadlineUs && sent < operationCap)
    {
      bool progressed = false;
      uint64_t sentThisLoop = 0;
      while (nowUs() < deadlineUs &&
             sent < operationCap &&
             sentThisLoop < burstLimit &&
             sent - received < burstLimit)
      {
        benchmarkFillDatagramPayload(buffer.data(), payloadSize, networkHub->junk, sent);
        if (!queueDatagram(connection, buffer.data(), payloadSize))
        {
          break;
        }
        ++sent;
        ++sentThisLoop;
        progressed = true;
      }
      flushOutgoingPackets();

      size_t read = 0;
      drainReadyIncomingPackets();
      while (popDatagram(connection, buffer.data(), buffer.size(), read))
      {
        const uint64_t sequence = benchmarkDecodeDatagramSequence(buffer.data(), read);
        if (benchmarkMarkDatagramSeen(seen, sequence, finiteOperationCap ? operationCap : 0))
        {
          ++received;
          progressed = true;
        }
      }

      if (!progressed)
      {
        const uint64_t currentUs = nowUs();
        if (currentUs >= deadlineUs)
        {
          break;
        }
        pumpOnce(std::min<uint64_t>(1000, deadlineUs - currentUs));
      }
    }
    const uint64_t measuredEndUs = std::min<uint64_t>(nowUs(), deadlineUs);

    uint64_t doneStream = openClientBidiStream();
    uint8_t done = 0;
    size_t doneWritten = 0;
    while (doneWritten < sizeof(done))
    {
      size_t written = sendSome(doneStream, &done + doneWritten, sizeof(done) - doneWritten);
      if (written == 0)
      {
        pumpOnce();
      }
      else
      {
        doneWritten += written;
      }
    }
    finishStream(doneStream);

    uint64_t drainDeadlineUs = received >= sent ? nowUs() : nowUs() + benchmarkDatagramDrainUs;
    while (nowUs() < drainDeadlineUs)
    {
      bool progressed = false;
      size_t read = 0;
      drainReadyIncomingPackets();
      while (popDatagram(connection, buffer.data(), buffer.size(), read))
      {
        const uint64_t sequence = benchmarkDecodeDatagramSequence(buffer.data(), read);
        if (benchmarkMarkDatagramSeen(seen, sequence, finiteOperationCap ? operationCap : 0))
        {
          ++received;
          progressed = true;
        }
      }
      if (received >= sent)
      {
        drainDeadlineUs = nowUs();
      }
      else if (!progressed)
      {
        pumpOnce(1000);
      }
    }

    benchmarkRecordDatagramClientCounters(sent, received);
    recordDurationResult(received, startUs, measuredEndUs);
  }

  bool processGenericServerStream(GenericServerStream& active)
  {
    switch (active.phase)
    {
      case GenericPhase::readRequest:
        {
          if (benchmarkDurationModeActive())
          {
            auto [read, fin] = recvSome(active, buffer.data(), 1);
            if (read == 0 && fin)
            {
              active.durationDoneSignal = true;
              active.phase = GenericPhase::complete;
              return true;
            }
            if (read > 0)
            {
              active.request[active.requestBytesRead++] = buffer[0];
            }
          }
          if (benchmarkScenario == BenchmarkScenario::reqresp ||
              benchmarkScenario == BenchmarkScenario::zero_rtt_reqresp ||
              benchmarkScenario == BenchmarkScenario::stream_churn ||
              benchmarkScenario == BenchmarkScenario::small_payload_pps ||
              benchmarkScenario == BenchmarkScenario::close_reset_cleanup)
          {
            if (active.requestBytesExpected == 0)
            {
              active.requestBytesExpected = reqRespRequestSize();
            }
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(
                active.requestBytesExpected - active.requestBytesRead, buffer.size()));
            auto [read, fin] = recvSome(active, buffer.data(), chunk);
            if (benchmarkDurationModeActive() &&
                read == 0 && fin && active.requestBytesRead == 0)
            {
              active.durationDoneSignal = true;
              active.phase = GenericPhase::complete;
              return true;
            }
            (void)fin;
            active.requestBytesRead += read;
            if (active.requestBytesRead == active.requestBytesExpected)
            {
              active.responseRemaining = reqRespResponseSize();
              active.phase = GenericPhase::sendResponse;
            }
            return read > 0;
          }
          auto [read, fin] = recvSome(active, active.request.data() + active.requestBytesRead, active.request.size() - active.requestBytesRead);
          (void)fin;
          active.requestBytesRead += read;
          if (active.requestBytesRead == active.request.size())
          {
            active.requestValue = decodeU64(active.request.data());
            active.payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                                       benchmarkScenario == BenchmarkScenario::bidi)
                                          ? active.requestValue
                                          : 0;
            active.responseRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload) ? 1 : active.requestValue;
            active.phase = benchmarkScenario == BenchmarkScenario::multistream_upload ? GenericPhase::transfer : GenericPhase::sendResponse;
          }
          return read > 0;
        }
      case GenericPhase::transfer:
        {
          if (active.payloadRemaining == 0)
          {
            active.phase = GenericPhase::sendResponse;
            return true;
          }
          size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
          auto [read, fin] = recvSome(active, buffer.data(), chunk);
          active.payloadRemaining -= read;
          if (benchmarkScenario == BenchmarkScenario::multistream_upload && fin)
          {
            active.payloadRemaining = 0;
            active.phase = GenericPhase::sendResponse;
          }
          return read > 0;
        }
      case GenericPhase::sendResponse:
        {
          bool progressed = false;
          if (benchmarkScenario == BenchmarkScenario::bidi && active.payloadRemaining > 0)
          {
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
            auto [read, fin] = recvSome(active, buffer.data(), chunk);
            active.payloadRemaining -= read;
            if (fin)
            {
              active.peerFinReceived = true;
            }
            progressed = read > 0 || progressed;
          }
          if (active.responseRemaining > 0)
          {
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
            size_t written = sendSome(active, buffer.data(), chunk);
            active.responseRemaining -= written;
            progressed = written > 0 || progressed;
          }
          if (active.responseRemaining == 0 && active.payloadRemaining == 0)
          {
            if (benchmarkScenario == BenchmarkScenario::bidi)
            {
              active.phase = GenericPhase::readDone;
            }
            else
            {
              active.phase = benchmarkScenario == BenchmarkScenario::multistream_upload
                                 ? GenericPhase::finish
                                 : GenericPhase::readDone;
            }
          }
          return progressed;
        }
      case GenericPhase::readDone:
        {
          if (active.peerFinReceived)
          {
            active.phase = (benchmarkScenario == BenchmarkScenario::bidi ||
                            benchmarkScenario == BenchmarkScenario::multistream_download)
                               ? GenericPhase::sendAck
                               : GenericPhase::finish;
            return true;
          }
          auto [read, fin] = recvSome(active, &active.done + active.doneRead, sizeof(active.done) - active.doneRead);
          active.doneRead += read;
          if (active.doneRead == sizeof(active.done) || fin)
          {
            active.phase = (benchmarkScenario == BenchmarkScenario::bidi ||
                            benchmarkScenario == BenchmarkScenario::multistream_download)
                               ? GenericPhase::sendAck
                               : GenericPhase::finish;
          }
          return read > 0 || fin;
        }
      case GenericPhase::sendAck:
        {
          size_t written = sendSome(active, &active.ack + active.ackSent, sizeof(active.ack) - active.ackSent);
          active.ackSent += written;
          if (active.ackSent == sizeof(active.ack))
          {
            if (benchmarkScenario == BenchmarkScenario::bidi)
            {
              if constexpr (Abi::is_zig)
              {
                active.phase = GenericPhase::finish;
              }
              else
              {
                active.phase = GenericPhase::readAck;
              }
            }
            else
            {
              active.phase = GenericPhase::finish;
            }
          }
          return written > 0;
        }
      case GenericPhase::readAck:
        {
          if (benchmarkScenario != BenchmarkScenario::bidi)
          {
            return false;
          }
          auto [read, fin] = recvSome(active, &active.ack + active.ackRead, sizeof(active.ack) - active.ackRead);
          active.ackRead += read;
          if (active.ackRead == sizeof(active.ack) || fin)
          {
            active.phase = GenericPhase::finish;
          }
          return read > 0 || fin;
        }
      case GenericPhase::finish:
        finishStream(active);
        active.phase = GenericPhase::complete;
        return true;
      case GenericPhase::complete:
        return false;
    }
    return false;
  }

  void runServerGenericStreams(void)
  {
    std::vector<uint64_t> conns;
    std::vector<GenericServerStream> streams;
    conns.reserve(benchmarkServerTargetConnections);
    const bool durationMode = benchmarkDurationModeActive() &&
                              supportsDurationMode(benchmarkScenario);
    const uint64_t targetStreams = durationMode
                                       ? UINT64_MAX
                                       : benchmarkGenericServerTargetStreams();
    uint64_t idleLoops = 0;
    uint64_t lastStallDumpUs = nowUs();
    uint64_t durationDoneSignalsSeen = 0;
    uint64_t durationDrainDeadlineUs = 0;
    uint64_t durationServerDeadlineUs = 0;

    while (true)
    {
      bool progressed = false;
      while (conns.size() < benchmarkServerTargetConnections)
      {
        uint64_t accepted = UINT64_MAX;
        int result = Abi::acceptConnection(engine, &accepted);
        check(result);
        if (result != 1)
        {
          break;
        }
        conns.push_back(accepted);
        progressed = true;
      }
      for (uint64_t connId : conns)
      {
        while (streams.size() < targetStreams)
        {
          uint64_t acceptedStream = UINT64_MAX;
          int result = Abi::acceptBidi(engine, connId, &acceptedStream, nowUs());
          check(result);
          if (result != 1)
          {
            break;
          }
          streams.push_back(GenericServerStream {.conn = connId, .stream = acceptedStream});
          progressed = true;
        }
      }

      uint64_t completed = 0;
      uint64_t durationDoneSignals = 0;
      uint64_t durationActiveStreams = 0;
      for (auto& streamState : streams)
      {
        if (streamState.phase != GenericPhase::complete)
        {
          progressed = processGenericServerStream(streamState) || progressed;
        }
        if (streamState.durationDoneSignal)
        {
          ++durationDoneSignals;
        }
        else if (streamState.phase == GenericPhase::complete)
        {
          ++completed;
        }
        else
        {
          ++durationActiveStreams;
        }
      }
      if (durationMode)
      {
        if (conns.size() >= benchmarkServerTargetConnections && durationServerDeadlineUs == 0)
        {
          durationServerDeadlineUs =
              nowUs() + benchmarkTargetDurationMs * 1000ULL + benchmarkDatagramDrainUs;
        }
        durationDoneSignalsSeen += durationDoneSignals;
        streams.erase(std::remove_if(streams.begin(), streams.end(), [](const GenericServerStream& streamState) {
                        return streamState.phase == GenericPhase::complete;
                      }),
                      streams.end());
      }
      const bool durationServerDeadlineElapsed =
          durationServerDeadlineUs != 0 && nowUs() >= durationServerDeadlineUs;
      if (durationMode &&
          conns.size() >= benchmarkServerTargetConnections &&
          (durationDoneSignalsSeen >= benchmarkServerTargetConnections ||
           durationServerDeadlineElapsed))
      {
        if (durationServerDeadlineElapsed)
        {
          drainTerminalPackets(1000, 100);
          break;
        }
        if (streams.empty() && durationActiveStreams == 0)
        {
          if (Abi::hasPendingAppData(engine))
          {
            pumpOnce(1000);
            continue;
          }
          drainTerminalPackets(1000, 100);
          break;
        }
        if (durationDrainDeadlineUs == 0 || progressed)
        {
          durationDrainDeadlineUs = nowUs() + benchmarkDatagramDrainUs;
        }
        if (nowUs() >= durationDrainDeadlineUs)
        {
          drainTerminalPackets(1000, 100);
          break;
        }
      }
      if (completed >= targetStreams)
      {
        if constexpr (Abi::is_zig)
        {
          if (benchmarkScenario == BenchmarkScenario::bidi ||
              benchmarkScenario == BenchmarkScenario::multistream_download)
          {
            // quic-zig can retain app-send state until terminal ACKs arrive. Once the
            // workload has exchanged its app-level terminal ack, do a bounded drain
            // instead of making server completion depend on late transport cleanup.
            drainTerminalPackets(1000, 2000);
            break;
          }
        }
        if (Abi::hasPendingAppData(engine))
        {
          pumpOnce(1000);
          continue;
        }
        drainTerminalPackets(1000, 100);
        break;
      }
      if (!progressed)
      {
        ++idleLoops;
        const uint64_t idleNowUs = nowUs();
        const bool dumpDebug = debugTrace && (idleLoops % 100'000) == 0;
        const bool dumpStall = stallTrace && idleNowUs - lastStallDumpUs >= 1'000'000;
        if (dumpDebug || dumpStall)
        {
          lastStallDumpUs = idleNowUs;
          fprintf(stderr, "%s debug=server_generic_idle loops=%" PRIu64 " conns=%zu streams=%zu completed=%" PRIu64 "/%" PRIu64,
                  Abi::label, idleLoops, conns.size(), streams.size(), completed, targetStreams);
          for (const auto& streamState : streams)
          {
            fprintf(stderr, " stream=%" PRIu64 " phase=%s payload=%" PRIu64 " response=%" PRIu64 " doneRead=%zu",
                    streamState.stream, genericPhaseName(streamState.phase), streamState.payloadRemaining,
                    streamState.responseRemaining, streamState.doneRead);
            PacketStreamDebug streamDebug = {};
            if (Abi::streamDebug(engine, streamState.conn, streamState.stream, &streamDebug))
            {
              fprintf(stderr,
                      " send=%" PRIu64 "/%" PRIu64 "/%" PRIu64 " swin=%" PRIu64 " cwin=%" PRIu64 " rtx=%" PRIu64
                      " fin=%d/%d/%d hdata=%d hunacked=%d bif=%" PRIu64 " cwnd=%" PRIu64
                      " recv=%" PRIu64 "/%" PRIu64 " chunks=%" PRIu64 " rfin=%d/%" PRIu64 "/%d",
                      streamDebug.sendAckOffset, streamDebug.sendSendOffset, streamDebug.sendWriteOffset,
                      streamDebug.sendWindow, streamDebug.connSendWindow,
                      streamDebug.sendRetransmitCount,
                      streamDebug.sendFinQueued ? 1 : 0, streamDebug.sendFinSent ? 1 : 0, streamDebug.sendFinLost ? 1 : 0,
                      streamDebug.sendHasData ? 1 : 0, streamDebug.sendHasUnacked ? 1 : 0,
                      streamDebug.bytesInFlight, streamDebug.cwnd,
                      streamDebug.recvReadPos, streamDebug.recvHighestBuffered, streamDebug.recvChunkCount,
                      streamDebug.recvFinKnown ? 1 : 0, streamDebug.recvFinOffset, streamDebug.recvFinished ? 1 : 0);
            }
          }
          fprintf(stderr, "\n");
        }
        pumpOnce();
      }
      else
      {
        idleLoops = 0;
      }
    }
  }

  void runServerDatagrams(void)
  {
    const size_t payloadSize = benchmarkDatagramPayloadBytesForNoMssApiLimit(
        buffer.size(),
        benchmarkUdpPayloadSize);
    if (payloadSize == 0 || payloadSize > buffer.size())
    {
      fprintf(stderr, "%s invalid DATAGRAM payload size %zu\n", Abi::label, payloadSize);
      abort();
    }

    std::vector<DatagramServerConn> conns;
    conns.reserve(benchmarkServerTargetConnections);
    uint64_t drainDeadlineUs = 0;

    while (drainDeadlineUs == 0 || nowUs() < drainDeadlineUs)
    {
      bool progressed = false;
      drainReadyIncomingPackets();
      while (conns.size() < benchmarkServerTargetConnections)
      {
        uint64_t accepted = UINT64_MAX;
        int result = Abi::acceptConnection(engine, &accepted);
        check(result);
        if (result != 1)
        {
          break;
        }
        DatagramServerConn active = {};
        active.conn = accepted;
        conns.push_back(std::move(active));
        progressed = true;
      }

      bool allConnectionsComplete = conns.size() >= benchmarkServerTargetConnections;
      for (DatagramServerConn& active : conns)
      {
        if (active.doneStream == UINT64_MAX)
        {
          uint64_t acceptedStream = UINT64_MAX;
          int result = Abi::acceptBidi(engine, active.conn, &acceptedStream, nowUs());
          check(result);
          if (result == 1)
          {
            active.doneStream = acceptedStream;
            progressed = true;
          }
        }
        if (active.doneStream != UINT64_MAX && !active.clientDone)
        {
          size_t read = 0;
          bool fin = false;
          check(Abi::streamRecv(engine, active.conn, active.doneStream,
                                &active.done + active.doneRead,
                                sizeof(active.done) - active.doneRead,
                                &read, &fin, nowUs()));
          active.doneRead += read;
          if (read > 0 || fin)
          {
            active.clientDone = true;
            progressed = true;
          }
        }
        size_t read = 0;
        while (popDatagram(active.conn, buffer.data(), buffer.size(), read))
        {
          const uint64_t sequence = benchmarkDecodeDatagramSequence(buffer.data(), read);
          if (benchmarkMarkDatagramSeen(active.seen, sequence))
          {
            ++active.received;
            active.pendingEchoes.push_back(sequence);
            progressed = true;
          }
        }

        while (!active.pendingEchoes.empty())
        {
          benchmarkFillDatagramPayload(buffer.data(), payloadSize, networkHub->junk, active.pendingEchoes.front());
          if (!queueDatagram(active.conn, buffer.data(), payloadSize))
          {
            break;
          }
          active.pendingEchoes.pop_front();
          ++active.echoed;
          progressed = true;
        }

        allConnectionsComplete = allConnectionsComplete &&
                                 active.clientDone &&
                                 active.pendingEchoes.empty();
      }

      if (allConnectionsComplete && (drainDeadlineUs == 0 || progressed))
      {
        drainDeadlineUs = nowUs() + benchmarkDatagramDrainUs;
      }
      flushOutgoingPackets();

      if (!progressed)
      {
        pumpOnce();
      }
    }
  }

  void runClientGenericScenario(uint64_t bytes)
  {
    switch (benchmarkScenario)
    {
      case BenchmarkScenario::reqresp:
      case BenchmarkScenario::zero_rtt_reqresp:
      case BenchmarkScenario::stream_churn:
      case BenchmarkScenario::small_payload_pps:
      case BenchmarkScenario::close_reset_cleanup:
        if (durationModeActive())
        {
          runClientReqRespLikeDuration();
          return;
        }
        runClientReqRespLike(benchmarkScenarioOperationsForCurrentMode());
        return;
      case BenchmarkScenario::multistream_download:
      case BenchmarkScenario::multistream_upload:
        if (durationModeActive())
        {
          runClientMultistreamDuration(bytes);
          return;
        }
        runClientMultistream(bytes);
        return;
      case BenchmarkScenario::bidi:
        if (durationModeActive())
        {
          runClientBidiDuration(bytes);
          return;
        }
        runClientBidi(bytes);
        return;
      default:
        return;
    }
  }

public:

  constexpr static bool packetEngineSupportsResumption(void)
  {
#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF)
    if constexpr (!Abi::is_zig)
    {
      return libraryKind == QPF_LIBRARY_QUINN ||
             libraryKind == QPF_LIBRARY_NOQ ||
             libraryKind == QPF_LIBRARY_NEQO ||
             libraryKind == QPF_LIBRARY_S2N;
    }
#endif
#if defined(QUICZIGPERF)
    if constexpr (Abi::is_zig)
    {
      return true;
    }
#endif
    return false;
  }

  constexpr static bool packetEngineSupportsZeroRtt(void)
  {
#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF)
    if constexpr (!Abi::is_zig)
    {
      return libraryKind == QPF_LIBRARY_QUINN ||
             libraryKind == QPF_LIBRARY_NOQ ||
             libraryKind == QPF_LIBRARY_NEQO ||
             libraryKind == QPF_LIBRARY_S2N;
    }
#endif
#if defined(QUICZIGPERF)
    if constexpr (Abi::is_zig)
    {
      return true;
    }
#endif
    return false;
  }

  ~PacketEngineLibrary()
  {
    if (engine != nullptr)
    {
      Abi::engineFree(engine);
      engine = nullptr;
    }
    delete networkHub;
  }

  void instanceSetup(uint16_t localPort, int argc, char *argv[])
  {
    (void)argc;
    (void)argv;
    std::fill(buffer.begin(), buffer.end(), 0x7);
    networkHub = new NetworkHub<mode>(localPort);
    debugTrace = std::getenv("QUICPERF_PACKET_DEBUG") != nullptr;
    stallTrace = std::getenv("QUICPERF_PACKET_STALL_DEBUG") != nullptr;

    typename Abi::config_t config = {};
    Abi::setLibrary(config, libraryKind);
    config.is_server = (mode & Mode::server) != 0;
    config.local_addr = packetAddrFromSockaddr(networkHub->socket.address());
    config.cert_path = tls_cert;
    config.key_path = tls_key;
    config.chain_path = tls_chain;
    if constexpr (!Abi::is_zig)
    {
      config.tls_hostname = benchmarkTlsHostname;
    }
    config.calendar_unix_seconds = benchmarkTlsCalendarUnixSeconds;
    config.tls_verify_peer = benchmarkTlsVerifyPeer();
    config.use_bbr = !benchmarkCongestionProfileUsesCubic();
    if constexpr (!Abi::is_zig)
    {
      config.initial_congestion_window_bytes = 13'500;
      config.max_ack_delay_ns = 25'000'000;
      config.ack_delay_exponent = 3;
      config.ack_frequency = false;
      config.active_migration = false;
      config.active_connection_id_limit = 2;
      config.connection_id_bytes = 8;
      config.stream_credit_replenish_below = 32;
      config.ticket_lifetime_ns = 300'000'000'000;
      config.maximum_early_data_bytes = 4'096;
      config.one_use_tickets = true;
    }
    config.connection_window = benchmarkConnectionWindow;
    config.stream_window = benchmarkStreamWindow;
    config.max_bidi_streams = benchmarkMaxBidiStreams;
    config.max_uni_streams = benchmarkMaxUniStreams;
    config.idle_timeout_ms = benchmarkIdleTimeoutMs;
    config.udp_payload_size = 1'350;
    config.datagram_max_frame_size = 1'200;
    if constexpr (Abi::is_zig)
    {
      config.send_backlog_limit = config.stream_window;
    }
    config.now_us = nowUs();
    engine = Abi::engineNew(&config);
    if (engine == nullptr)
    {
      const char *error = Abi::lastError();
      fprintf(stderr, "%s error: %s\n", Abi::label, error == nullptr ? "unknown" : error);
      abort();
    }
  }

  void connectToServer(struct sockaddr *address)
  {
    if constexpr (mode & Mode::client)
    {
      typename Abi::addr_t remote = packetAddrFromSockaddr(address);
      check(Abi::connect(engine, &remote, nowUs(), &connection));
      while (Abi::isConnected(engine, connection, nowUs()) != 1)
      {
        pumpOnce();
      }
    }
  }

  void connectToServerForZeroRtt(struct sockaddr *address) override
  {
    if constexpr (mode & Mode::client)
    {
      typename Abi::addr_t remote = packetAddrFromSockaddr(address);
      check(Abi::connect(engine, &remote, nowUs(), &connection));
    }
  }

  void openStream(void)
  {
    if constexpr (mode & Mode::client)
    {
      while (true)
      {
        int result = Abi::openBidi(engine, connection, &stream, nowUs());
        check(result);
        if (result == 1)
        {
          break;
        }
        pumpOnce();
      }
    }
  }

  bool supportsSessionResumption(void) const override
  {
    return packetEngineSupportsResumption();
  }

  bool supportsZeroRtt(void) const override
  {
    return packetEngineSupportsZeroRtt();
  }

  bool supportsDurationMode(BenchmarkScenario scenario) const override
  {
    switch (scenario)
    {
      case BenchmarkScenario::download:
      case BenchmarkScenario::upload:
      case BenchmarkScenario::loss_recovery:
      case BenchmarkScenario::flow_control:
      case BenchmarkScenario::datagram:
      case BenchmarkScenario::reqresp:
      case BenchmarkScenario::stream_churn:
      case BenchmarkScenario::small_payload_pps:
      case BenchmarkScenario::close_reset_cleanup:
      case BenchmarkScenario::zero_rtt_reqresp:
      case BenchmarkScenario::multistream_download:
      case BenchmarkScenario::multistream_upload:
      case BenchmarkScenario::bidi:
        return benchmarkTargetDurationMs > 0;
      default:
        return false;
    }
  }

  uint64_t completedUnitsForReport(uint64_t fallback) const override
  {
    return durationModeActive() ? durationCompletedUnits : fallback;
  }

  double measuredSecondsForReport(double fallback) const override
  {
    return durationModeActive() ? durationMeasuredSeconds : fallback;
  }

  bool exportResumptionState(BenchmarkResumptionState& state) override
  {
    if constexpr (mode & Mode::client)
    {
      drainTerminalPackets(1000, 1000);
      std::array<uint8_t, 64 * 1024> serialized = {};
      size_t len = 0;
      int result = Abi::exportResumptionState(
          engine, connection, serialized.data(), serialized.size(), &len, nowUs());
      check(result);
      if (result != 1)
      {
        return false;
      }
      state.session.assign(serialized.data(), serialized.data() + len);
      state.transportParams.clear();
      state.proofLabel = resumptionProofLabel();
      return true;
    }
    return false;
  }

  bool importResumptionState(const BenchmarkResumptionState& state, bool enableZeroRtt) override
  {
    if constexpr (mode & Mode::client)
    {
      int result = Abi::importResumptionState(
          engine, state.session.data(), state.session.size(), enableZeroRtt, nowUs());
      check(result);
      if (result != 1)
      {
        return false;
      }
      importedResumption = true;
      importedZeroRtt = enableZeroRtt;
      return true;
    }
    return false;
  }

  bool connectionWasResumed(void) const override
  {
    if constexpr (mode & Mode::client)
    {
      if (!importedResumption)
      {
        return false;
      }
      int result = Abi::connectionResumed(engine, connection, nowUs());
      check(result);
      return result == 1;
    }
    return false;
  }

  bool zeroRttWasAttempted(void) const override
  {
    if constexpr (mode & Mode::client)
    {
      if (!importedZeroRtt)
      {
        return false;
      }
      int result = Abi::zeroRttAttempted(engine, connection, nowUs());
      check(result);
#if defined(S2NPERF)
      if constexpr (!Abi::is_zig)
      {
        if (libraryKind == QPF_LIBRARY_S2N)
        {
          if (result != 1 || outgoingZeroRttPackets == 0)
          {
            fprintf(stderr,
                    "%s zero_rtt_attempted_debug abi_attempted=%d outgoing_zero_rtt_packets=%" PRIu64 "\n",
                    Abi::label,
                    result == 1 ? 1 : 0,
                    outgoingZeroRttPackets);
          }
          return result == 1 && outgoingZeroRttPackets > 0;
        }
      }
#endif
      return result == 1;
    }
    return false;
  }

  bool zeroRttWasAccepted(void) const override
  {
    if constexpr (mode & Mode::client)
    {
      if (!importedZeroRtt)
      {
        return false;
      }
      int result = Abi::zeroRttAccepted(engine, connection, nowUs());
      check(result);
      return result == 1;
    }
    return false;
  }

  bool zeroRttWasRejected(void) const override
  {
    if constexpr (mode & Mode::client)
    {
      if (!importedZeroRtt)
      {
        return false;
      }
      int result = Abi::zeroRttRejected(engine, connection, nowUs());
      check(result);
      return result == 1;
    }
    return false;
  }

  const char *resumptionProofLabel(void) const override
  {
#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF)
    if constexpr (!Abi::is_zig)
    {
      switch (libraryKind)
      {
        case QPF_LIBRARY_QUINN:
          return "quinn_proto_rustls_shared_client_config_ticket_0rtt_state";
        case QPF_LIBRARY_NOQ:
          return "noq_proto_rustls_shared_client_config_ticket_0rtt_state";
        case QPF_LIBRARY_NEQO:
          return "neqo_resumption_token_tls_info_zero_rtt_state";
        default:
          break;
      }
    }
#endif
    if constexpr (Abi::is_zig)
    {
      return "quic_zig_session_ticket_psk_0rtt_state";
    }
    return "packet_engine_resumption_api";
  }

  void startPerfTest(uint64_t nBytes = 0)
  {
    if constexpr (mode & Mode::server)
    {
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        runServerDatagrams();
      }
      else if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        runServerGenericStreams();
      }
      else
      {
        runServerConnections();
      }
    }
    else
    {
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        if (durationModeActive())
        {
          runClientDatagramsDuration();
        }
        else
        {
          runClientDatagrams(benchmarkScenarioOperations);
        }
      }
      else if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        runClientGenericScenario(nBytes);
      }
      else if (benchmarkIsUpload())
      {
        if (durationModeActive())
        {
          runClientUploadDuration();
        }
        else
        {
          runClientUpload(nBytes);
        }
      }
      else
      {
        if (durationModeActive())
        {
          runClientDownloadDuration();
        }
        else
        {
          runClientDownload(nBytes);
        }
      }
    }
  }

  void postPerfTest() override
  {
    if constexpr (mode & Mode::client)
    {
      if (benchmarkIsResumptionScenario() ||
          benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        drainTerminalPackets(1000, 1000);
      }
    }
  }
};

#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF)
template <Mode mode>
using Quinn = PacketEngineLibrary<mode, RustPacketAbi, QPF_LIBRARY_QUINN>;

template <Mode mode>
using Noq = PacketEngineLibrary<mode, RustPacketAbi, QPF_LIBRARY_NOQ>;

template <Mode mode>
using Neqo = PacketEngineLibrary<mode, RustPacketAbi, QPF_LIBRARY_NEQO>;

template <Mode mode>
using S2n = PacketEngineLibrary<mode, RustPacketAbi, QPF_LIBRARY_S2N>;
#endif

#if defined(QUICZIGPERF)
template <Mode mode>
using QuicZig = PacketEngineLibrary<mode, ZigPacketAbi>;
#endif
