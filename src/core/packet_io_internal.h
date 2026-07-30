#pragma once

#include "packet_io.h"

#include <array>
#include <cerrno>
#include <memory>

namespace quicperf {

inline bool restartableMultishotReceiveError(int result, bool hasMore) noexcept
{
  return result == -ENOBUFS || (result == -ECANCELED && !hasMore);
}

class PacketIoBase : public PacketIoDriver {
public:
  explicit PacketIoBase(PacketIoConfig config);
  ~PacketIoBase() override;
  uint16_t bind(uint32_t addressNetworkOrder, uint16_t portHostOrder) override;
  void armLossRecovery(std::span<const uint8_t, 32> traceSeed,
                       uint64_t measurementStartRawNs,
                       uint64_t measurementEndRawNs,
                       uint8_t direction) override;
  void resetLossRecovery() override;
  void shareLossRecovery(std::shared_ptr<LossRecoveryStream> stream) override;
  bool hasPendingTransmit() const noexcept override
  {
    return lossPendingOffset_ != lossPendingCount_;
  }
  int socketFd() const noexcept override { return socketFd_; }
  std::vector<int> ownedFileDescriptors() const override { return {socketFd_}; }
  const PacketIoCounters& counters() const noexcept override { return counters_; }

protected:
  static constexpr size_t providedBufferHeadroom = 512;
  using Buffer = std::array<std::byte, maximumUdpDatagramSize + providedBufferHeadroom>;
  size_t prepareLossTransmit(std::span<const TransmitPacket> packets,
                             uint64_t nowRawNs);
  std::span<const TransmitPacket> pendingLossTransmit() const noexcept;
  void retireLossTransmit(size_t sentPackets);
  PacketIoConfig config_;
  int socketFd_ = -1;
  PacketIoCounters counters_;
  std::vector<Buffer> packetPool_;
  std::array<ReceivedPacket, packetBatchSize> received_ {};
  std::shared_ptr<LossRecoveryStream> lossStream_;
  std::array<Buffer, packetBatchSize> lossTransmitBuffers_ {};
  std::array<TransmitPacket, packetBatchSize> lossPending_ {};
  size_t lossPendingOffset_ = 0;
  size_t lossPendingCount_ = 0;
};

std::unique_ptr<PacketIoDriver> makeSyscallPacketIoDriver(const PacketIoConfig& config);
std::unique_ptr<PacketIoDriver> makeIouringPacketIoDriver(const PacketIoConfig& config);

} // namespace quicperf
