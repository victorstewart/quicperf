#include "packet_io_internal.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <fcntl.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace quicperf {
namespace {

void requireSocketOption(int fd, int level, int option, const void* value, socklen_t length, const char* name)
{
  if (setsockopt(fd, level, option, value, length) != 0)
  {
    throw std::runtime_error(std::string("failed socket option ") + name + ": " + std::strerror(errno));
  }
}

} // namespace

PacketIoBase::PacketIoBase(PacketIoConfig config)
    : config_(config), packetPool_(packetPoolSize),
      lossStream_(std::make_shared<LossRecoveryStream>())
{
}

PacketIoBase::~PacketIoBase()
{
  if (socketFd_ >= 0) close(socketFd_);
}

void PacketIoBase::armLossRecovery(std::span<const uint8_t, 32> traceSeed,
                                   uint64_t measurementStartRawNs,
                                   uint64_t measurementEndRawNs,
                                   uint8_t direction)
{
  if (hasPendingTransmit())
    throw std::logic_error("cannot arm loss recovery with queued transmit packets");
  lossStream_->arm(traceSeed, measurementStartRawNs, measurementEndRawNs, direction);
}

void PacketIoBase::resetLossRecovery()
{
  if (hasPendingTransmit())
    throw std::logic_error("cannot reset loss recovery with queued transmit packets");
  lossStream_->reset();
}

void PacketIoBase::shareLossRecovery(std::shared_ptr<LossRecoveryStream> stream)
{
  if (!stream || hasPendingTransmit() || lossStream_->armed())
    throw std::logic_error("cannot replace an active loss-recovery stream");
  lossStream_ = std::move(stream);
}

size_t PacketIoBase::prepareLossTransmit(
    std::span<const TransmitPacket> packets, uint64_t nowRawNs)
{
  if (hasPendingTransmit())
    throw std::logic_error("cannot replace queued loss-recovery transmit packets");
  lossPendingOffset_ = 0;
  lossPendingCount_ = 0;
  const size_t count = std::min(packets.size(), packetBatchSize);
  size_t consumed = 0;
  for (; consumed < count; ++consumed)
  {
    const auto& packet = packets[consumed];
    if (packet.desiredSendRawNs > nowRawNs) break;
    if (packet.bytes.empty() || packet.bytes.size() > maximumUdpDatagramSize)
      throw std::invalid_argument("invalid UDP transmit packet length");
    if (packet.gsoSegmentSize != 0 && !config_.udpGso)
      throw std::invalid_argument("UDP GSO packet supplied while UDP GSO is disabled");
    if (packet.gsoSegmentSize > maxUdpPayloadSize)
      throw std::invalid_argument("UDP GSO segment exceeds the frozen payload size");
    const size_t segmentSize = packet.gsoSegmentSize == 0 ?
        packet.bytes.size() : packet.gsoSegmentSize;
    auto& output = lossTransmitBuffers_[lossPendingCount_];
    size_t outputBytes = 0;
    size_t retainedSegments = 0;
    for (size_t offset = 0; offset < packet.bytes.size(); offset += segmentSize)
    {
      const size_t length = std::min(segmentSize, packet.bytes.size() - offset);
      const LossDecision decision = lossStream_->next(nowRawNs);
      if (decision.active)
      {
        ++counters_.lossPacketsConsidered;
        auto& considered = decision.measurement ?
            counters_.lossMeasurementPacketsConsidered :
            counters_.lossWarmupPacketsConsidered;
        ++considered;
        if (decision.drop)
        {
          ++counters_.lossPacketsDropped;
          auto& dropped = decision.measurement ?
              counters_.lossMeasurementPacketsDropped :
              counters_.lossWarmupPacketsDropped;
          ++dropped;
          continue;
        }
      }
      std::memcpy(output.data() + outputBytes,
                  packet.bytes.data() + offset, length);
      outputBytes += length;
      ++retainedSegments;
    }
    if (retainedSegments == 0) continue;
    lossPending_[lossPendingCount_++] = {
        {output.data(), outputBytes}, packet.peer, packet.ecn,
        retainedSegments > 1 ? packet.gsoSegmentSize : uint16_t {0},
        packet.desiredSendRawNs, packet.desiredSendMonotonicNs};
  }
  return consumed;
}

std::span<const TransmitPacket> PacketIoBase::pendingLossTransmit() const noexcept
{
  return {lossPending_.data() + lossPendingOffset_,
          lossPendingCount_ - lossPendingOffset_};
}

void PacketIoBase::retireLossTransmit(size_t sentPackets)
{
  if (sentPackets > lossPendingCount_ - lossPendingOffset_)
    throw std::logic_error("loss-recovery transmit completion exceeds queue");
  lossPendingOffset_ += sentPackets;
  if (lossPendingOffset_ == lossPendingCount_)
  {
    lossPendingOffset_ = 0;
    lossPendingCount_ = 0;
  }
}

uint16_t PacketIoBase::bind(uint32_t addressNetworkOrder, uint16_t portHostOrder)
{
  if (socketFd_ >= 0) throw std::logic_error("packet socket is already bound");
  socketFd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
  if (socketFd_ < 0) throw std::runtime_error(std::string("UDP socket failed: ") + std::strerror(errno));
  requireSocketOption(socketFd_, SOL_SOCKET, SO_SNDBUF, &requestedSocketBufferBytes, sizeof(requestedSocketBufferBytes), "SO_SNDBUF");
  requireSocketOption(socketFd_, SOL_SOCKET, SO_RCVBUF, &requestedSocketBufferBytes, sizeof(requestedSocketBufferBytes), "SO_RCVBUF");
  const int pmtud = config_.pmtud ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
  requireSocketOption(socketFd_, IPPROTO_IP, IP_MTU_DISCOVER, &pmtud, sizeof(pmtud), "IP_MTU_DISCOVER");
  const int receiveTos = config_.ecn ? 1 : 0;
  requireSocketOption(socketFd_, IPPROTO_IP, IP_RECVTOS, &receiveTos, sizeof(receiveTos), "IP_RECVTOS");
  if (config_.udpGro)
  {
    const int enabled = 1;
    requireSocketOption(socketFd_, IPPROTO_UDP, UDP_GRO, &enabled, sizeof(enabled), "UDP_GRO");
  }
  if (config_.receiveTimestamps)
  {
    const int enabled = 1;
    requireSocketOption(socketFd_, SOL_SOCKET, SO_TIMESTAMPNS, &enabled, sizeof(enabled), "SO_TIMESTAMPNS");
  }
  if (config_.busyPolling)
  {
    throw std::invalid_argument("publication packet driver forbids busy polling");
  }
  sockaddr_in local {};
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = addressNetworkOrder;
  local.sin_port = htons(portHostOrder);
  if (::bind(socketFd_, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0)
  {
    throw std::runtime_error(std::string("UDP bind failed: ") + std::strerror(errno));
  }
  socklen_t length = sizeof(local);
  if (getsockname(socketFd_, reinterpret_cast<sockaddr*>(&local), &length) != 0)
  {
    throw std::runtime_error(std::string("getsockname failed: ") + std::strerror(errno));
  }
  return ntohs(local.sin_port);
}

std::unique_ptr<PacketIoDriver> makePacketIoDriver(PacketBackend backend, const PacketIoConfig& config)
{
  if (config.requireMultishotReceive && backend != PacketBackend::iouring)
  {
    throw std::invalid_argument("multishot receive requires iouring backend");
  }
  return backend == PacketBackend::syscall ? makeSyscallPacketIoDriver(config) : makeIouringPacketIoDriver(config);
}

} // namespace quicperf
