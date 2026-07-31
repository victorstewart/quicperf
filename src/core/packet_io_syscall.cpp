#include "packet_io_internal.h"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <linux/udp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace quicperf {
namespace {

class SyscallPacketIo final : public PacketIoBase {
public:
  explicit SyscallPacketIo(PacketIoConfig config) : PacketIoBase(config)
  {
    epollFd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epollFd_ < 0) throw std::runtime_error("epoll_create1 failed");
  }

  ~SyscallPacketIo() override
  {
    if (epollFd_ >= 0) close(epollFd_);
  }

  uint16_t bind(uint32_t address, uint16_t port) override
  {
    const uint16_t selected = PacketIoBase::bind(address, port);
    epoll_event event {};
    event.events = EPOLLIN;
    event.data.fd = socketFd_;
    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, socketFd_, &event) != 0) throw std::runtime_error("epoll_ctl failed");
    return selected;
  }

  std::span<const ReceivedPacket> receive(uint64_t nowRawNs) override
  {
    std::array<mmsghdr, packetBatchSize> messages {};
    std::array<iovec, packetBatchSize> vectors {};
    std::array<sockaddr_in, packetBatchSize> peers {};
    std::array<std::array<std::byte, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t))>, packetBatchSize> controls {};
    for (size_t index = 0; index < packetBatchSize; ++index)
    {
      vectors[index] = {packetPool_[index].data(), maximumUdpDatagramSize};
      messages[index].msg_hdr.msg_iov = &vectors[index];
      messages[index].msg_hdr.msg_iovlen = 1;
      messages[index].msg_hdr.msg_name = &peers[index];
      messages[index].msg_hdr.msg_namelen = sizeof(peers[index]);
      messages[index].msg_hdr.msg_control = controls[index].data();
      messages[index].msg_hdr.msg_controllen = controls[index].size();
    }
    ++counters_.receiveCalls;
    const unsigned receiveSlots = config_.udpGro ? 1U : static_cast<unsigned>(messages.size());
    const int count = recvmmsg(socketFd_, messages.data(), receiveSlots, MSG_DONTWAIT, nullptr);
    if (count < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return {};
      ++counters_.receiveErrors;
      throw std::runtime_error(std::string("recvmmsg failed: ") + std::strerror(errno));
    }
    size_t delivered = 0;
    for (int index = 0; index < count; ++index)
    {
      uint8_t ecn = 0;
      uint16_t gro = 0;
      for (cmsghdr* cmsg = CMSG_FIRSTHDR(&messages[index].msg_hdr); cmsg; cmsg = CMSG_NXTHDR(&messages[index].msg_hdr, cmsg))
      {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) ecn = *reinterpret_cast<uint8_t*>(CMSG_DATA(cmsg)) & 0x03;
        if (cmsg->cmsg_level == IPPROTO_UDP && cmsg->cmsg_type == UDP_GRO) std::memcpy(&gro, CMSG_DATA(cmsg), sizeof(gro));
      }
      const size_t segmentSize = gro == 0 ? messages[index].msg_len : gro;
      for (size_t offset = 0; offset < messages[index].msg_len; offset += segmentSize)
      {
        assert(delivered < received_.size());
        const size_t length = std::min(segmentSize, static_cast<size_t>(messages[index].msg_len) - offset);
        received_[delivered++] = {{packetPool_[index].data() + offset, length}, peers[index], ecn, gro, nowRawNs};
      }
    }
    counters_.udpDatagramsReceived += count;
    counters_.packetsReceived += delivered;
    counters_.groSegmentsReceived += delivered;
    return {received_.data(), delivered};
  }

  size_t send(std::span<const TransmitPacket> packets, uint64_t nowRawNs) override
  {
    if (!lossStream_->armed()) return transmit(packets, nowRawNs);
    if (hasPendingTransmit())
    {
      const size_t sent = transmit(pendingLossTransmit(), nowRawNs);
      retireLossTransmit(sent);
      return 0;
    }
    const size_t consumed = prepareLossTransmit(packets, nowRawNs);
    if (hasPendingTransmit())
    {
      const size_t sent = transmit(pendingLossTransmit(), nowRawNs);
      retireLossTransmit(sent);
    }
    return consumed;
  }

  size_t transmit(std::span<const TransmitPacket> packets, uint64_t nowRawNs)
  {
    const size_t count = std::min(packets.size(), packetBatchSize);
    std::array<mmsghdr, packetBatchSize> messages {};
    std::array<iovec, packetBatchSize> vectors {};
    std::array<std::array<std::byte, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t))>, packetBatchSize> controls {};
    size_t ready = 0;
    for (; ready < count; ++ready)
    {
      if (packets[ready].desiredSendRawNs > nowRawNs) break;
      if (packets[ready].gsoSegmentSize != 0 && !config_.udpGso)
        throw std::invalid_argument("UDP GSO packet supplied while UDP GSO is disabled");
      vectors[ready] = {const_cast<std::byte*>(packets[ready].bytes.data()), packets[ready].bytes.size()};
      messages[ready].msg_hdr.msg_iov = &vectors[ready];
      messages[ready].msg_hdr.msg_iovlen = 1;
      messages[ready].msg_hdr.msg_name = const_cast<sockaddr_in*>(&packets[ready].peer);
      messages[ready].msg_hdr.msg_namelen = sizeof(sockaddr_in);
      size_t controlLength = 0;
      if (config_.ecn)
      {
        auto* cmsg = reinterpret_cast<cmsghdr*>(controls[ready].data() + controlLength);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_TOS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        const int tos = packets[ready].ecn & 0x03;
        std::memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
        controlLength += CMSG_SPACE(sizeof(int));
      }
      if (packets[ready].gsoSegmentSize != 0)
      {
        auto* cmsg = reinterpret_cast<cmsghdr*>(controls[ready].data() + controlLength);
        cmsg->cmsg_level = IPPROTO_UDP;
        cmsg->cmsg_type = UDP_SEGMENT;
        cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
        std::memcpy(CMSG_DATA(cmsg), &packets[ready].gsoSegmentSize, sizeof(uint16_t));
        controlLength += CMSG_SPACE(sizeof(uint16_t));
      }
      if (controlLength != 0)
      {
        messages[ready].msg_hdr.msg_control = controls[ready].data();
        messages[ready].msg_hdr.msg_controllen = controlLength;
      }
    }
    if (ready == 0) return 0;
    ++counters_.sendCalls;
    const int sent = sendmmsg(socketFd_, messages.data(), ready, MSG_DONTWAIT);
    if (sent < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        ++counters_.backpressureEvents;
        return 0;
      }
      ++counters_.sendErrors;
      throw std::runtime_error(std::string("sendmmsg failed: ") + std::strerror(errno));
    }
    counters_.packetsSent += sent;
    counters_.udpDatagramsSent += sent;
    for (int index = 0; index < sent; ++index)
      counters_.gsoSegmentsSent += packets[index].gsoSegmentSize == 0 ? 1 :
          (packets[index].bytes.size() + packets[index].gsoSegmentSize - 1) / packets[index].gsoSegmentSize;
    return static_cast<size_t>(sent);
  }

  int wait(uint64_t timeoutNs) override
  {
    epoll_event event {};
    timespec timeout {
        static_cast<time_t>(timeoutNs / 1'000'000'000),
        static_cast<long>(timeoutNs % 1'000'000'000)};
    return epoll_pwait2(epollFd_, &event, 1, &timeout, nullptr);
  }

  std::vector<int> ownedFileDescriptors() const override
  {
    auto descriptors = PacketIoBase::ownedFileDescriptors();
    descriptors.push_back(epollFd_);
    return descriptors;
  }

  PacketBackend backend() const noexcept override { return PacketBackend::syscall; }

private:
  int epollFd_ = -1;
};

} // namespace

std::unique_ptr<PacketIoDriver> makeSyscallPacketIoDriver(const PacketIoConfig& config)
{
  return std::make_unique<SyscallPacketIo>(config);
}

} // namespace quicperf
