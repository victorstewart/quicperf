#include "packet_io_internal.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <liburing.h>
#include <linux/udp.h>
#include <poll.h>

namespace quicperf {
namespace {

class IouringPacketIo final : public PacketIoBase {
public:
  explicit IouringPacketIo(PacketIoConfig config) : PacketIoBase(config)
  {
    io_uring_params params {};
    if (io_uring_queue_init_params(256, &ring_, &params) < 0) throw std::runtime_error("io_uring initialization failed");
    initialized_ = true;
    if (config.requireMultishotReceive)
    {
      io_uring_params receiveParams {};
      if (io_uring_queue_init_params(256, &receiveRing_, &receiveParams) < 0)
      {
        io_uring_queue_exit(&ring_);
        initialized_ = false;
        throw std::runtime_error("io_uring multishot receive ring initialization failed");
      }
      receiveInitialized_ = true;
      int error = 0;
      bufferRing_ = io_uring_setup_buf_ring(
          &receiveRing_, packetPoolSize, receiveBufferGroup, 0, &error);
      if (!bufferRing_)
      {
        io_uring_queue_exit(&receiveRing_);
        receiveInitialized_ = false;
        io_uring_queue_exit(&ring_);
        initialized_ = false;
        throw std::runtime_error(std::string("io_uring provided buffer ring failed: ") + std::strerror(-error));
      }
      for (size_t index = 0; index < packetPool_.size(); ++index)
      {
        io_uring_buf_ring_add(
            bufferRing_, packetPool_[index].data(), packetPool_[index].size(),
            static_cast<unsigned short>(index), io_uring_buf_ring_mask(packetPoolSize), index);
      }
      io_uring_buf_ring_advance(bufferRing_, packetPoolSize);
      multishotMessage_.msg_namelen = sizeof(sockaddr_in);
      multishotMessage_.msg_controllen = CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t));
    }
  }

  ~IouringPacketIo() override
  {
    if (receiveInitialized_)
    {
      if (multishotArmed_)
      {
        if (auto* sqe = io_uring_get_sqe(&receiveRing_))
        {
          io_uring_prep_cancel64(sqe, receiveToken, 0);
          io_uring_sqe_set_data64(sqe, cancelToken);
          io_uring_submit_and_wait(&receiveRing_, 1);
          io_uring_cqe* cqe = nullptr;
          unsigned head = 0;
          unsigned count = 0;
          io_uring_for_each_cqe(&receiveRing_, head, cqe) { ++count; }
          if (count) io_uring_cq_advance(&receiveRing_, count);
        }
      }
      if (bufferRing_) io_uring_free_buf_ring(
          &receiveRing_, bufferRing_, packetPoolSize, receiveBufferGroup);
      io_uring_queue_exit(&receiveRing_);
    }
    if (initialized_) io_uring_queue_exit(&ring_);
  }

  uint16_t bind(uint32_t address, uint16_t port) override
  {
    const uint16_t selected = PacketIoBase::bind(address, port);
    if (config_.requireMultishotReceive) armMultishot();
    return selected;
  }

  std::span<const ReceivedPacket> receive(uint64_t nowRawNs) override
  {
    if (config_.requireMultishotReceive) return receiveMultishot(nowRawNs);
    std::array<msghdr, packetBatchSize> messages {};
    std::array<iovec, packetBatchSize> vectors {};
    std::array<sockaddr_in, packetBatchSize> peers {};
    std::array<std::array<std::byte, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t))>, packetBatchSize> controls {};
    size_t prepared = 0;
    const size_t receiveSlots = config_.udpGro ? 1 : packetBatchSize;
    for (size_t index = 0; index < receiveSlots; ++index)
    {
      vectors[index] = {packetPool_[index].data(), maximumUdpDatagramSize};
      messages[index].msg_iov = &vectors[index];
      messages[index].msg_iovlen = 1;
      messages[index].msg_name = &peers[index];
      messages[index].msg_namelen = sizeof(peers[index]);
      messages[index].msg_control = controls[index].data();
      messages[index].msg_controllen = controls[index].size();
      auto* sqe = io_uring_get_sqe(&ring_);
      if (!sqe) break;
      io_uring_prep_recvmsg(sqe, socketFd_, &messages[index], MSG_DONTWAIT);
      io_uring_sqe_set_data64(sqe, index);
      ++prepared;
    }
    ++counters_.receiveCalls;
    const int submitted = io_uring_submit_and_wait(&ring_, prepared);
    if (submitted < 0 || static_cast<size_t>(submitted) != prepared) throw std::runtime_error("io_uring receive submit failed");
    size_t count = 0;
    size_t datagrams = 0;
    for (size_t completion = 0; completion < prepared; ++completion)
    {
      io_uring_cqe* cqe = nullptr;
      if (io_uring_wait_cqe(&ring_, &cqe) < 0) throw std::runtime_error("io_uring receive completion failed");
      const size_t index = io_uring_cqe_get_data64(cqe);
      if (cqe->res >= 0 && index < packetBatchSize)
      {
        ++datagrams;
        uint8_t ecn = 0;
        uint16_t gro = 0;
        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&messages[index]); cmsg; cmsg = CMSG_NXTHDR(&messages[index], cmsg))
        {
          if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) ecn = *reinterpret_cast<uint8_t*>(CMSG_DATA(cmsg)) & 0x03;
          if (cmsg->cmsg_level == IPPROTO_UDP && cmsg->cmsg_type == UDP_GRO) std::memcpy(&gro, CMSG_DATA(cmsg), sizeof(gro));
        }
        const size_t datagramLength = static_cast<size_t>(cqe->res);
        const size_t segmentSize = gro == 0 ? datagramLength : gro;
        for (size_t offset = 0; offset < datagramLength; offset += segmentSize)
        {
          if (count >= received_.size()) throw std::runtime_error("io_uring GRO batch exceeds 64 packets");
          const size_t length = std::min(segmentSize, datagramLength - offset);
          received_[count++] = {{packetPool_[index].data() + offset, length}, peers[index], ecn, gro, nowRawNs};
        }
      }
      else if (cqe->res != -EAGAIN && cqe->res != -EWOULDBLOCK)
      {
        ++counters_.receiveErrors;
      }
      io_uring_cqe_seen(&ring_, cqe);
    }
    counters_.udpDatagramsReceived += datagrams;
    counters_.packetsReceived += count;
    counters_.groSegmentsReceived += count;
    return {received_.data(), count};
  }

  std::vector<int> ownedFileDescriptors() const override
  {
    auto descriptors = PacketIoBase::ownedFileDescriptors();
    if (initialized_) descriptors.push_back(ring_.ring_fd);
    if (receiveInitialized_) descriptors.push_back(receiveRing_.ring_fd);
    return descriptors;
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
    std::array<msghdr, packetBatchSize> messages {};
    std::array<iovec, packetBatchSize> vectors {};
    std::array<std::array<std::byte, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t))>, packetBatchSize> controls {};
    size_t submitted = 0;
    io_uring_sqe* lastSqe = nullptr;
    for (; submitted < std::min(packets.size(), packetBatchSize); ++submitted)
    {
      if (packets[submitted].desiredSendRawNs > nowRawNs) break;
      if (packets[submitted].gsoSegmentSize != 0 && !config_.udpGso)
        throw std::invalid_argument("UDP GSO packet supplied while UDP GSO is disabled");
      vectors[submitted] = {const_cast<std::byte*>(packets[submitted].bytes.data()), packets[submitted].bytes.size()};
      messages[submitted].msg_iov = &vectors[submitted];
      messages[submitted].msg_iovlen = 1;
      messages[submitted].msg_name = const_cast<sockaddr_in*>(&packets[submitted].peer);
      messages[submitted].msg_namelen = sizeof(sockaddr_in);
      size_t controlLength = 0;
      if (config_.ecn)
      {
        auto* cmsg = reinterpret_cast<cmsghdr*>(controls[submitted].data() + controlLength);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_TOS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        const int tos = packets[submitted].ecn & 0x03;
        std::memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
        controlLength += CMSG_SPACE(sizeof(int));
      }
      if (packets[submitted].gsoSegmentSize != 0)
      {
        auto* cmsg = reinterpret_cast<cmsghdr*>(controls[submitted].data() + controlLength);
        cmsg->cmsg_level = IPPROTO_UDP;
        cmsg->cmsg_type = UDP_SEGMENT;
        cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
        std::memcpy(CMSG_DATA(cmsg), &packets[submitted].gsoSegmentSize, sizeof(uint16_t));
        controlLength += CMSG_SPACE(sizeof(uint16_t));
      }
      if (controlLength != 0)
      {
        messages[submitted].msg_control = controls[submitted].data();
        messages[submitted].msg_controllen = controlLength;
      }
      auto* sqe = io_uring_get_sqe(&ring_);
      if (!sqe) break;
      io_uring_prep_sendmsg(sqe, socketFd_, &messages[submitted], MSG_DONTWAIT);
      sqe->flags |= IOSQE_IO_LINK;
      io_uring_sqe_set_data64(sqe, submitted);
      lastSqe = sqe;
    }
    if (submitted == 0) return 0;
    lastSqe->flags &= ~IOSQE_IO_LINK;
    ++counters_.sendCalls;
    if (io_uring_submit_and_wait(&ring_, submitted) < 0) throw std::runtime_error("io_uring send submit failed");
    std::array<int, packetBatchSize> results {};
    results.fill(std::numeric_limits<int>::min());
    for (size_t completion = 0; completion < submitted; ++completion)
    {
      io_uring_cqe* cqe = nullptr;
      if (io_uring_wait_cqe(&ring_, &cqe) < 0) break;
      const size_t index = io_uring_cqe_get_data64(cqe);
      if (index >= submitted) throw std::runtime_error("io_uring send completion identity mismatch");
      results[index] = cqe->res;
      io_uring_cqe_seen(&ring_, cqe);
    }
    size_t sent = 0;
    for (size_t index = 0; index < submitted; ++index)
    {
      if (results[index] >= 0)
      {
        ++sent;
        continue;
      }
      if (results[index] == -EAGAIN || results[index] == -EWOULDBLOCK)
      {
        ++counters_.backpressureEvents;
        break;
      }
      if (results[index] == -ECANCELED) break;
      ++counters_.sendErrors;
      throw std::runtime_error(std::string("io_uring send failed: ") + std::strerror(-results[index]));
    }
    counters_.packetsSent += sent;
    counters_.udpDatagramsSent += sent;
    for (size_t index = 0; index < sent; ++index)
      counters_.gsoSegmentsSent += packets[index].gsoSegmentSize == 0 ? 1 :
          (packets[index].bytes.size() + packets[index].gsoSegmentSize - 1) / packets[index].gsoSegmentSize;
    return sent;
  }

  int wait(uint64_t timeoutNs) override
  {
    if (config_.requireMultishotReceive)
    {
      __kernel_timespec timeout {
          static_cast<__kernel_time64_t>(timeoutNs / 1'000'000'000),
          static_cast<long long>(timeoutNs % 1'000'000'000)};
      io_uring_cqe* cqe = nullptr;
      const int result = io_uring_wait_cqe_timeout(&receiveRing_, &cqe, &timeout);
      return result == 0 ? 1 : result == -ETIME ? 0 : result;
    }
    constexpr uint64_t pollToken = std::numeric_limits<uint64_t>::max();
    constexpr uint64_t cancelToken = pollToken - 1;
    auto* pollSqe = io_uring_get_sqe(&ring_);
    if (!pollSqe) throw std::runtime_error("io_uring poll SQE unavailable");
    io_uring_prep_poll_add(pollSqe, socketFd_, POLLIN);
    io_uring_sqe_set_data64(pollSqe, pollToken);
    if (io_uring_submit(&ring_) != 1) throw std::runtime_error("io_uring poll submit failed");
    __kernel_timespec timeout {
        static_cast<__kernel_time64_t>(timeoutNs / 1'000'000'000),
        static_cast<long long>(timeoutNs % 1'000'000'000)};
    io_uring_cqe* cqe = nullptr;
    const int result = io_uring_wait_cqe_timeout(&ring_, &cqe, &timeout);
    if (result == 0)
    {
      const bool matched = io_uring_cqe_get_data64(cqe) == pollToken;
      const int readiness = cqe->res;
      io_uring_cqe_seen(&ring_, cqe);
      if (!matched) throw std::runtime_error("io_uring poll completion identity mismatch");
      return readiness < 0 ? readiness : 1;
    }
    if (result != -ETIME) return result;

    auto* cancelSqe = io_uring_get_sqe(&ring_);
    if (!cancelSqe) throw std::runtime_error("io_uring cancel SQE unavailable");
    io_uring_prep_cancel64(cancelSqe, pollToken, 0);
    io_uring_sqe_set_data64(cancelSqe, cancelToken);
    if (io_uring_submit_and_wait(&ring_, 2) < 0) throw std::runtime_error("io_uring poll cancel failed");
    bool sawPoll = false;
    bool sawCancel = false;
    while (!sawPoll || !sawCancel)
    {
      if (io_uring_wait_cqe(&ring_, &cqe) < 0) throw std::runtime_error("io_uring poll cancel completion failed");
      const uint64_t token = io_uring_cqe_get_data64(cqe);
      sawPoll |= token == pollToken;
      sawCancel |= token == cancelToken;
      io_uring_cqe_seen(&ring_, cqe);
      if (token != pollToken && token != cancelToken) throw std::runtime_error("io_uring poll cancel identity mismatch");
    }
    return 0;
  }

  PacketBackend backend() const noexcept override { return PacketBackend::iouring; }

private:
  void armMultishot()
  {
    if (multishotArmed_) return;
    auto* sqe = io_uring_get_sqe(&receiveRing_);
    if (!sqe) throw std::runtime_error("io_uring multishot receive SQE unavailable");
    io_uring_prep_recvmsg_multishot(sqe, socketFd_, &multishotMessage_, MSG_TRUNC);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = receiveBufferGroup;
    io_uring_sqe_set_data64(sqe, receiveToken);
    if (io_uring_submit(&receiveRing_) != 1)
      throw std::runtime_error("io_uring multishot receive submit failed");
    multishotArmed_ = true;
  }

  void recycleBuffer(uint16_t id)
  {
    io_uring_buf_ring_add(
        bufferRing_, packetPool_[id].data(), packetPool_[id].size(), id,
        io_uring_buf_ring_mask(packetPoolSize), 0);
    io_uring_buf_ring_advance(bufferRing_, 1);
  }

  std::span<const ReceivedPacket> receiveMultishot(uint64_t nowRawNs)
  {
    for (size_t index = 0; index < heldBufferCount_; ++index)
      recycleBuffer(heldBufferIds_[index]);
    heldBufferCount_ = 0;
    ++counters_.receiveCalls;
    size_t delivered = 0;
    size_t datagrams = 0;
    const size_t receiveSlots = config_.udpGro ? 1 : packetBatchSize;
    while (datagrams < receiveSlots && delivered < received_.size())
    {
      io_uring_cqe* cqe = nullptr;
      const int peeked = io_uring_peek_cqe(&receiveRing_, &cqe);
      if (peeked == -EAGAIN) break;
      if (peeked < 0 || !cqe)
        throw std::runtime_error("io_uring multishot receive completion failed");
      const int result = cqe->res;
      const unsigned flags = cqe->flags;
      const uint64_t token = io_uring_cqe_get_data64(cqe);
      io_uring_cqe_seen(&receiveRing_, cqe);
      if (token != receiveToken)
        throw std::runtime_error("io_uring multishot receive identity mismatch");
      if (!(flags & IORING_CQE_F_MORE))
      {
        multishotArmed_ = false;
        armMultishot();
      }
      if (restartableMultishotReceiveError(
              result, flags & IORING_CQE_F_MORE)) continue;
      if (result < 0)
      {
        ++counters_.receiveErrors;
        throw std::runtime_error(
            std::string("io_uring multishot receive failed: ") + std::strerror(-result));
      }
      if (!(flags & IORING_CQE_F_BUFFER))
        throw std::runtime_error("io_uring multishot receive omitted buffer identity");
      const unsigned bufferId = flags >> IORING_CQE_BUFFER_SHIFT;
      if (bufferId >= packetPool_.size())
        throw std::runtime_error("io_uring multishot receive buffer identity is invalid");
      auto* output = io_uring_recvmsg_validate(
          packetPool_[bufferId].data(), result, &multishotMessage_);
      if (!output)
      {
        recycleBuffer(static_cast<uint16_t>(bufferId));
        ++counters_.receiveErrors;
        throw std::runtime_error("io_uring multishot recvmsg metadata is invalid");
      }
      const size_t payloadLength = io_uring_recvmsg_payload_length(
          output, result, &multishotMessage_);
      if ((output->flags & MSG_TRUNC) || output->payloadlen != payloadLength ||
          output->namelen != sizeof(sockaddr_in))
      {
        recycleBuffer(static_cast<uint16_t>(bufferId));
        ++counters_.receiveErrors;
        throw std::runtime_error("io_uring multishot datagram or peer address was truncated");
      }
      uint8_t ecn = 0;
      uint16_t gro = 0;
      for (cmsghdr* cmsg = io_uring_recvmsg_cmsg_firsthdr(output, &multishotMessage_);
           cmsg;
           cmsg = io_uring_recvmsg_cmsg_nexthdr(output, &multishotMessage_, cmsg))
      {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS)
          ecn = *reinterpret_cast<uint8_t*>(CMSG_DATA(cmsg)) & 0x03;
        if (cmsg->cmsg_level == IPPROTO_UDP && cmsg->cmsg_type == UDP_GRO)
          std::memcpy(&gro, CMSG_DATA(cmsg), sizeof(gro));
      }
      if (gro > payloadLength)
      {
        recycleBuffer(static_cast<uint16_t>(bufferId));
        throw std::runtime_error("io_uring multishot GRO segment exceeds its datagram");
      }
      const size_t segmentSize = gro == 0 ? payloadLength : gro;
      const size_t segments = segmentSize == 0 ? 0 :
          (payloadLength + segmentSize - 1) / segmentSize;
      if (segments == 0 || delivered + segments > received_.size())
      {
        recycleBuffer(static_cast<uint16_t>(bufferId));
        throw std::runtime_error("io_uring multishot receive batch exceeds 64 packets");
      }
      const auto peer = *static_cast<sockaddr_in*>(io_uring_recvmsg_name(output));
      if (peer.sin_family != AF_INET)
      {
        recycleBuffer(static_cast<uint16_t>(bufferId));
        ++counters_.receiveErrors;
        throw std::runtime_error("io_uring multishot received a non-IPv4 peer");
      }
      const auto* payload = static_cast<const std::byte*>(
          io_uring_recvmsg_payload(output, &multishotMessage_));
      for (size_t offset = 0; offset < payloadLength; offset += segmentSize)
      {
        const size_t length = std::min(segmentSize, payloadLength - offset);
        received_[delivered++] = {
            {payload + offset, length}, peer, ecn, gro, nowRawNs};
      }
      heldBufferIds_[heldBufferCount_++] = static_cast<uint16_t>(bufferId);
      ++datagrams;
      ++counters_.udpDatagramsReceived;
      counters_.packetsReceived += segments;
      counters_.groSegmentsReceived += segments;
    }
    return {received_.data(), delivered};
  }

  static constexpr uint16_t receiveBufferGroup = 7;
  static constexpr uint64_t receiveToken = std::numeric_limits<uint64_t>::max() - 8;
  static constexpr uint64_t cancelToken = receiveToken - 1;
  io_uring ring_ {};
  io_uring receiveRing_ {};
  io_uring_buf_ring* bufferRing_ = nullptr;
  msghdr multishotMessage_ {};
  std::array<uint16_t, packetBatchSize> heldBufferIds_ {};
  size_t heldBufferCount_ = 0;
  bool initialized_ = false;
  bool receiveInitialized_ = false;
  bool multishotArmed_ = false;
};

} // namespace

std::unique_ptr<PacketIoDriver> makeIouringPacketIoDriver(const PacketIoConfig& config)
{
  return std::make_unique<IouringPacketIo>(config);
}

} // namespace quicperf
