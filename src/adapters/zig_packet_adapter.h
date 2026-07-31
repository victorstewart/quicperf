#pragma once

#include "adapter_factory.h"
#include "core/strict_config.h"
#include "quicperf_zig_packet_ffi.h"

#include <array>
#include <unordered_map>

namespace quicperf {

class ZigPacketAdapter final : public Adapter {
public:
  ZigPacketAdapter();
  ~ZigPacketAdapter() override;
  const Capabilities& capabilities() const noexcept override { return capabilities_; }
  bool configure(std::string_view canonicalConfig, AdapterError& error) override;
  bool setLocalAddress(const sockaddr_in& local, AdapterError& error) override;
  bool receiveBatch(std::span<const ReceivedPacket> packets, uint64_t nowRawNs, AdapterError& error) override;
  size_t pollTransmitBatch(std::span<TransmitPacket> packets, uint64_t nowRawNs, AdapterError& error) override;
  uint64_t nextTimeoutRawNs() const noexcept override { return nextTimeoutRawNs_; }
  bool onTimeout(uint64_t nowRawNs, AdapterError& error) override;
  bool connect(const sockaddr_in& peer, uint64_t nowRawNs, uint64_t& connectionId, AdapterError& error) override;
  PrimitiveStatus acceptConnection(uint64_t nowRawNs, uint64_t& connectionId, AdapterError& error) override;
  bool isConnected(uint64_t connectionId, uint64_t nowRawNs, bool& connected, AdapterError& error) override;
  bool connectionIsClosed(uint64_t connectionId, uint64_t nowRawNs, bool& closed,
                          AdapterError& error) override;
  bool peerTerminalFacts(uint64_t connectionId, uint64_t streamId, uint64_t nowRawNs,
                         PeerTerminalFacts& facts, AdapterError& error) override;
  PrimitiveStatus openBidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                          uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus acceptBidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                            uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus openUnidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                           uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus acceptUnidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                             uint64_t& streamId, AdapterError& error) override;
  bool writeStream(uint64_t connectionId, uint64_t streamId, std::span<const std::byte> bytes,
                   uint64_t nowRawNs, size_t& written, AdapterError& error) override;
  bool consumeStreamData(uint64_t connectionId, uint64_t streamId, std::span<std::byte> bytes,
                         uint64_t nowRawNs, size_t& read, bool& finished, AdapterError& error) override;
  bool finishStream(uint64_t connectionId, uint64_t streamId, uint64_t nowRawNs, AdapterError& error) override;
  bool resetStream(uint64_t connectionId, uint64_t streamId, uint64_t applicationError,
                   uint64_t nowRawNs, AdapterError& error) override;
  bool stopSending(uint64_t connectionId, uint64_t streamId, uint64_t applicationError,
                   uint64_t nowRawNs, AdapterError& error) override;
  PrimitiveStatus sendDatagram(uint64_t connectionId, std::span<const std::byte> bytes,
                               uint64_t nowRawNs, AdapterError& error) override;
  PrimitiveStatus consumeDatagram(uint64_t connectionId, std::span<std::byte> bytes,
                                  uint64_t nowRawNs, size_t& read, AdapterError& error) override;
  PrimitiveStatus exportResumptionState(uint64_t connectionId, uint64_t nowRawNs,
                                        std::span<std::byte> bytes, size_t& written,
                                        AdapterError& error) override;
  PrimitiveStatus importResumptionState(std::span<const std::byte> bytes, bool useZeroRtt,
                                        uint64_t nowRawNs, AdapterError& error) override;
  bool connectionResumed(uint64_t connectionId, uint64_t nowRawNs, bool& resumed, AdapterError& error) override;
  bool zeroRttAttempted(uint64_t connectionId, uint64_t nowRawNs, bool& attempted, AdapterError& error) override;
  bool zeroRttAccepted(uint64_t connectionId, uint64_t nowRawNs, bool& accepted, AdapterError& error) override;
  bool zeroRttRejected(uint64_t connectionId, uint64_t nowRawNs, bool& rejected, AdapterError& error) override;
  bool closeConnection(uint64_t connectionId, uint64_t applicationError,
                       uint64_t nowRawNs, AdapterError& error) override;
  TransportCounters snapshotTransportCounters() const noexcept override;
  NegotiatedSettings snapshotNegotiatedSettings() const noexcept override;
  bool reset(AdapterError& error) override;
  bool stop(AdapterError& error) override;

private:
  bool createEngine(const sockaddr_in& local, AdapterError& error);
  bool updateTimeout(uint64_t nowRawNs, AdapterError& error);
  static qzf_addr_t toFfi(const sockaddr_in& address);
  static sockaddr_in fromFfi(const qzf_addr_t& address);
  static void assignError(const qzf_adapter_status_v2_t& status, AdapterError& error);
  static bool assignScalarError(int status, AdapterError& error);
  static uint64_t toMicroseconds(uint64_t nowRawNs) noexcept { return nowRawNs / 1'000; }

  Capabilities capabilities_;
  EndpointConfig config_ {};
  bool configured_ = false;
  qzf_engine_t* engine_ = nullptr;
  uint64_t nextTimeoutRawNs_ = 0;
  std::array<std::array<uint8_t, maxUdpPayloadSize>, packetBatchSize> output_ {};
  std::array<qzf_transmit_descriptor_v2_t, packetBatchSize> transmit_ {};
  std::array<qzf_receive_descriptor_v2_t, packetBatchSize> receive_ {};
  TransportCounters counters_ {};
  std::unordered_map<uint64_t, qzf_negotiated_t> negotiated_;
  uint64_t lastCallerRawNs_ = 0;
};

} // namespace quicperf
