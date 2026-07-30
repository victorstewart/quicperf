#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>
#include <netinet/in.h>

#include "path_loss.h"

namespace quicperf {

constexpr size_t packetBatchSize = 64;
constexpr size_t packetPoolSize = 4'096;
constexpr size_t maxUdpPayloadSize = 1'350;
constexpr size_t maximumUdpDatagramSize = 65'535;
constexpr int requestedSocketBufferBytes = 16 * 1024 * 1024;

enum class PacketBackend { syscall, iouring };

struct PacketIoConfig {
  bool pmtud = false;
  bool udpGso = true;
  bool udpGro = true;
  bool ecn = false;
  bool receiveTimestamps = false;
  bool busyPolling = false;
  bool commonPacing = true;
  bool requireMultishotReceive = false;
};

struct ReceivedPacket {
  std::span<const std::byte> bytes;
  sockaddr_in peer {};
  uint8_t ecn = 0;
  uint16_t groSegmentSize = 0;
  uint64_t receivedRawNs = 0;
};

struct TransmitPacket {
  std::span<const std::byte> bytes;
  sockaddr_in peer {};
  uint8_t ecn = 0;
  uint16_t gsoSegmentSize = 0;
  uint64_t desiredSendRawNs = 0;
  uint64_t desiredSendMonotonicNs = 0;
};

struct PacketIoCounters {
  uint64_t packetsReceived = 0;
  uint64_t packetsSent = 0;
  uint64_t udpDatagramsReceived = 0;
  uint64_t udpDatagramsSent = 0;
  uint64_t groSegmentsReceived = 0;
  uint64_t gsoSegmentsSent = 0;
  uint64_t receiveCalls = 0;
  uint64_t sendCalls = 0;
  uint64_t receiveErrors = 0;
  uint64_t sendErrors = 0;
  uint64_t backpressureEvents = 0;
  uint64_t lossPacketsConsidered = 0;
  uint64_t lossPacketsDropped = 0;
  uint64_t lossWarmupPacketsConsidered = 0;
  uint64_t lossWarmupPacketsDropped = 0;
  uint64_t lossMeasurementPacketsConsidered = 0;
  uint64_t lossMeasurementPacketsDropped = 0;
};

class PacketIoDriver {
public:
  virtual ~PacketIoDriver() = default;
  virtual uint16_t bind(uint32_t addressNetworkOrder, uint16_t portHostOrder) = 0;
  virtual std::span<const ReceivedPacket> receive(uint64_t nowRawNs) = 0;
  virtual size_t send(std::span<const TransmitPacket> packets, uint64_t nowRawNs) = 0;
  virtual void armLossRecovery(std::span<const uint8_t, 32> traceSeed,
                               uint64_t measurementStartRawNs,
                               uint64_t measurementEndRawNs,
                               uint8_t direction) = 0;
  virtual void resetLossRecovery() = 0;
  virtual void shareLossRecovery(
      std::shared_ptr<LossRecoveryStream> stream) = 0;
  virtual bool hasPendingTransmit() const noexcept = 0;
  virtual int wait(uint64_t timeoutNs) = 0;
  virtual int socketFd() const noexcept = 0;
  virtual std::vector<int> ownedFileDescriptors() const = 0;
  virtual const PacketIoCounters& counters() const noexcept = 0;
  virtual PacketBackend backend() const noexcept = 0;
};

std::unique_ptr<PacketIoDriver> makePacketIoDriver(PacketBackend backend, const PacketIoConfig& config);

} // namespace quicperf
