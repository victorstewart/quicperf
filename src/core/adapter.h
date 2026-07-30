#pragma once

#include "capability.h"
#include "negotiated_settings.h"
#include "packet_io.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace quicperf {

struct AdapterError {
  uint64_t code = 0;
  std::string message;
};

enum class PrimitiveStatus : uint8_t { ready, wouldBlock, fatal };

struct TransportCounters {
  uint64_t packetsReceived = 0;
  uint64_t packetsSent = 0;
  uint64_t packetsLost = 0;
  uint64_t packetsRetransmitted = 0;
  uint64_t timerExpirations = 0;
  uint64_t recoveryWakeups = 0;
  uint64_t flowControlBlockedEvents = 0;
  uint64_t streamCreditBlockedEvents = 0;
};

struct PeerTerminalFacts {
  bool available = false;
  bool fin = false;
  bool resetStream = false;
  bool stopSending = false;
  bool connectionClose = false;
  uint64_t resetStreamError = 0;
  uint64_t stopSendingError = 0;
  uint64_t connectionCloseError = 0;
  uint64_t connectionCloseReasonLength = 0;
};

class Adapter {
public:
  virtual ~Adapter() = default;
  virtual const Capabilities& capabilities() const noexcept = 0;
  virtual bool configure(std::string_view canonicalConfig, AdapterError& error) = 0;
  virtual bool setLocalAddress(const sockaddr_in& local, AdapterError& error) = 0;
  virtual bool receiveBatch(std::span<const ReceivedPacket> packets, uint64_t nowRawNs, AdapterError& error) = 0;
  virtual size_t pollTransmitBatch(std::span<TransmitPacket> packets, uint64_t nowRawNs, AdapterError& error) = 0;
  virtual uint64_t nextTimeoutRawNs() const noexcept = 0;
  virtual bool onTimeout(uint64_t nowRawNs, AdapterError& error) = 0;

  // Application-facing transport primitives. The common workload engine is
  // their only production caller; adapters never own workload semantics.
  virtual bool connect(const sockaddr_in& peer, uint64_t nowRawNs, uint64_t& connectionId,
                       AdapterError& error) = 0;
  virtual PrimitiveStatus acceptConnection(uint64_t nowRawNs, uint64_t& connectionId,
                                           AdapterError& error) = 0;
  virtual bool isConnected(uint64_t connectionId, uint64_t nowRawNs, bool& connected,
                           AdapterError& error) = 0;
  virtual bool connectionIsClosed(uint64_t, uint64_t, bool& closed, AdapterError&)
  {
    closed = false;
    return true;
  }
  virtual bool releaseConnectionWhenClosed(uint64_t, uint64_t, AdapterError& error)
  {
    error = {};
    return true;
  }
  virtual bool peerTerminalFacts(uint64_t, uint64_t, uint64_t,
                                 PeerTerminalFacts& facts, AdapterError&)
  {
    facts = {};
    return true;
  }
  virtual PrimitiveStatus openBidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                                  uint64_t& streamId, AdapterError& error) = 0;
  virtual PrimitiveStatus acceptBidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                                    uint64_t& streamId, AdapterError& error) = 0;
  virtual PrimitiveStatus openUnidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                                   uint64_t& streamId, AdapterError& error) = 0;
  virtual PrimitiveStatus acceptUnidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                                     uint64_t& streamId, AdapterError& error) = 0;
  virtual bool writeStream(uint64_t connectionId, uint64_t streamId,
                           std::span<const std::byte> bytes, uint64_t nowRawNs,
                           size_t& written, AdapterError& error) = 0;
  virtual bool consumeStreamData(uint64_t connectionId, uint64_t streamId,
                                 std::span<std::byte> bytes, uint64_t nowRawNs,
                                 size_t& read, bool& finished, AdapterError& error) = 0;
  virtual bool finishStream(uint64_t connectionId, uint64_t streamId, uint64_t nowRawNs,
                            AdapterError& error) = 0;
  virtual bool resetStream(uint64_t connectionId, uint64_t streamId, uint64_t applicationError,
                           uint64_t nowRawNs, AdapterError& error) = 0;
  virtual bool stopSending(uint64_t connectionId, uint64_t streamId, uint64_t applicationError,
                           uint64_t nowRawNs, AdapterError& error) = 0;
  virtual PrimitiveStatus sendDatagram(uint64_t connectionId, std::span<const std::byte> bytes,
                                       uint64_t nowRawNs, AdapterError& error) = 0;
  virtual PrimitiveStatus consumeDatagram(uint64_t connectionId, std::span<std::byte> bytes,
                                          uint64_t nowRawNs, size_t& read,
                                          AdapterError& error) = 0;
  virtual PrimitiveStatus exportResumptionState(uint64_t connectionId, uint64_t nowRawNs,
                                                std::span<std::byte> bytes, size_t& written,
                                                AdapterError& error) = 0;
  virtual PrimitiveStatus importResumptionState(std::span<const std::byte> bytes,
                                                bool useZeroRtt, uint64_t nowRawNs,
                                                AdapterError& error) = 0;
  virtual bool connectionResumed(uint64_t connectionId, uint64_t nowRawNs, bool& resumed,
                                 AdapterError& error) = 0;
  virtual bool zeroRttAttempted(uint64_t connectionId, uint64_t nowRawNs, bool& attempted,
                               AdapterError& error) = 0;
  virtual bool zeroRttAccepted(uint64_t connectionId, uint64_t nowRawNs, bool& accepted,
                              AdapterError& error) = 0;
  virtual bool zeroRttRejected(uint64_t connectionId, uint64_t nowRawNs, bool& rejected,
                              AdapterError& error) = 0;
  virtual bool closeConnection(uint64_t connectionId, uint64_t applicationError,
                               uint64_t nowRawNs, AdapterError& error) = 0;
  virtual TransportCounters snapshotTransportCounters() const noexcept = 0;
  virtual NegotiatedSettings snapshotNegotiatedSettings() const noexcept
  {
    NegotiatedSettings result;
    result.unavailableFields = {"adapter_did_not_report_post_handshake_treatment"};
    return result;
  }
  virtual bool reset(AdapterError& error) = 0;
  virtual bool stop(AdapterError& error) = 0;
};

} // namespace quicperf
