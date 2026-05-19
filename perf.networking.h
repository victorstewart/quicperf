#include "liburing.h"
#include <openssl/rand.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <ctime>
#include <fcntl.h>
#include <memory>
#include <netinet/udp.h>
#include <poll.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <stdlib.h>
#include <cstdlib>

#pragma once

#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

uint64_t timeNowUs(void)
{
  return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

struct MultiUDPContext;

template <typename T>
class Pool {
private:

  uint32_t capacity;
  uint32_t watermark;

  T *base;
  std::vector<T *> available;

public:

  Pool(uint32_t count)
  {
    capacity = count;
    watermark = 0;
    base = new T[count];
    available.reserve(count);
  }

  uint32_t howManyLeft(void)
  {
    return (capacity - watermark) + available.size();
  }

  T *get(void)
  {
    T *item = NULL;

    if (watermark == capacity)
    {
      if (available.size())
      {
        item = available.back();
        available.pop_back();
      }
    }
    else
    {
      item = &base[watermark++];
    }

    return item;
  }

  void relinquish(T *item)
  {
    available.emplace_back(item);
  }
};

class UDPSocket {
public:

  struct sockaddr_in6 *address6;
  socklen_t addressLen;
  int fd;

  template <typename T = struct sockaddr>
  T *address(void)
  {
    return (T *)address6;
  }

  UDPSocket(uint16_t port)
  {
    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
    {
      fprintf(stderr, "quicperf_socket_error action=socket errno=%d message=%s\n", errno, strerror(errno));
      abort();
    }

    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const uint32_t[]) {static_cast<uint32_t>(benchmarkConnectionWindow)}, sizeof(uint32_t));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const uint32_t[]) {static_cast<uint32_t>(benchmarkConnectionWindow)}, sizeof(uint32_t));
#ifdef UDP_GRO
    if (benchmarkUdpGroEnabled())
    {
      int enabled = 1;
      setsockopt(fd, IPPROTO_UDP, UDP_GRO, &enabled, sizeof(enabled));
    }
#endif
    benchmarkRecordSocketBuffers(fd);

    addressLen = sizeof(struct sockaddr_in6);

    address6 = (struct sockaddr_in6 *)calloc(1, addressLen);
    address6->sin6_family = AF_INET6;
    address6->sin6_flowinfo = 0;
    address6->sin6_port = htons(port);
    address6->sin6_addr = localAddress;

    if (bind(fd, (struct sockaddr *)address6, addressLen) != 0)
    {
      fprintf(stderr, "quicperf_socket_error action=bind port=%u errno=%d message=%s\n",
              static_cast<unsigned>(port), errno, strerror(errno));
      abort();
    }
  }
};

constexpr static size_t MAX_IPV6_UDP_PACKET_SIZE = benchmarkUdpPayloadSize;
constexpr static uint16_t MAX_IPV6_UDP_GSO_SEGMENTS = 64;
constexpr static size_t MAX_IPV6_UDP_GSO_PAYLOAD_SIZE = 65'507;
constexpr static size_t MAX_IPV6_UDP_GSO_BUFFER_SIZE = benchmarkUdpPayloadSize * MAX_IPV6_UDP_GSO_SEGMENTS;
constexpr static size_t MAX_IPV6_UDP_GSO_SEND_BUFFER_SIZE = std::min(MAX_IPV6_UDP_GSO_BUFFER_SIZE, MAX_IPV6_UDP_GSO_PAYLOAD_SIZE);

struct UDPContext {

  struct msghdr msg_hdr;
  unsigned int msg_len;
  size_t iov_capacity;
  uint16_t udp_segment_size;
  alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(uint16_t))];

  UDPContext()
  {
    memset(&msg_hdr, 0, sizeof(struct msghdr));
    msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
    msg_hdr.msg_name = malloc(msg_hdr.msg_namelen);

    msg_hdr.msg_iov = (struct iovec *)malloc(sizeof(struct iovec));
    msg_hdr.msg_iov[0].iov_len = MAX_IPV6_UDP_PACKET_SIZE;
    msg_hdr.msg_iov[0].iov_base = malloc(MAX_IPV6_UDP_PACKET_SIZE);
    msg_hdr.msg_iovlen = 1;
    iov_capacity = MAX_IPV6_UDP_PACKET_SIZE;
    udp_segment_size = 0;

    // add the interface to every message

    // else if (cmsg->cmsg_level == IPPROTO_IPV6) {
    // if (cmsg->cmsg_type == IPV6_PKTINFO) {
    //     if (addr_dest != NULL) {
    //         struct in6_pktinfo* pPktInfo6 = (struct in6_pktinfo*)CMSG_DATA(cmsg);

    // ((struct sockaddr_in6*)addr_dest)->sin6_family = AF_INET6;
    // ((struct sockaddr_in6*)addr_dest)->sin6_port = 0;
    // memcpy(&((struct sockaddr_in6*)addr_dest)->sin6_addr, &pPktInfo6->ipi6_addr, sizeof(struct in6_addr));

    // if (dest_if != NULL) {
    //     *dest_if = (int)pPktInfo6->ipi6_ifindex;
    // }
    // }
    // }
  }

  template <typename T = struct sockaddr>
  T *address(void)
  {
    return (T *)msg_hdr.msg_name;
  }

  template <typename T = struct sockaddr>
  const T *address(void) const
  {
    return (const T *)msg_hdr.msg_name;
  }

  uint8_t *buffer(void)
  {
    return (uint8_t *)msg_hdr.msg_iov[0].iov_base;
  }

  size_t length(void) const
  {
    return msg_hdr.msg_iov[0].iov_len;
  }

  void ensureCapacity(size_t capacity)
  {
    if (capacity > iov_capacity)
    {
      void *resized = realloc(msg_hdr.msg_iov[0].iov_base, capacity);
      if (resized == nullptr)
      {
        fprintf(stderr, "quicperf_udp_buffer_realloc_failed requested=%zu\n", capacity);
        abort();
      }
      msg_hdr.msg_iov[0].iov_base = resized;
      iov_capacity = capacity;
    }
  }

  void setLength(size_t length)
  {
    msg_hdr.msg_iov[0].iov_len = length;
    msg_len = length;
  }

  void clearUdpSegmentSize(void)
  {
    udp_segment_size = 0;
    msg_hdr.msg_control = nullptr;
    msg_hdr.msg_controllen = 0;
  }

  void reset(void)
  {
    msg_len = 0;
    msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
    clearUdpSegmentSize();
    setLength(MAX_IPV6_UDP_PACKET_SIZE);
  }

  void enableRecvControl(void)
  {
    memset(control, 0, sizeof(control));
    msg_hdr.msg_control = control;
    msg_hdr.msg_controllen = sizeof(control);
  }

  void setUdpSegmentSize(uint16_t segmentSize)
  {
    if (segmentSize == 0)
    {
      clearUdpSegmentSize();
      return;
    }
    udp_segment_size = segmentSize;
    memset(control, 0, sizeof(control));
    msg_hdr.msg_control = control;
    msg_hdr.msg_controllen = CMSG_SPACE(sizeof(segmentSize));
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg_hdr);
    cmsg->cmsg_level = IPPROTO_UDP;
    cmsg->cmsg_type = UDP_SEGMENT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(segmentSize));
    memcpy(CMSG_DATA(cmsg), &segmentSize, sizeof(segmentSize));
  }

  uint16_t udpSegmentSize(void) const
  {
    return udp_segment_size;
  }

  uint64_t udpPacketCount(void) const
  {
    size_t packetLength = length();
    if (udp_segment_size == 0)
    {
      return packetLength > 0 ? 1 : 0;
    }
    return (packetLength + udp_segment_size - 1) / udp_segment_size;
  }

  uint16_t receivedGroSegmentSize(void) const
  {
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(const_cast<struct msghdr *>(&msg_hdr));
         cmsg != nullptr;
         cmsg = CMSG_NXTHDR(const_cast<struct msghdr *>(&msg_hdr), cmsg))
    {
      if (cmsg->cmsg_level == IPPROTO_UDP && cmsg->cmsg_type == UDP_GRO &&
          cmsg->cmsg_len >= CMSG_LEN(sizeof(uint16_t)))
      {
        uint16_t segmentSize = 0;
        memcpy(&segmentSize, CMSG_DATA(cmsg), sizeof(segmentSize));
        return segmentSize;
      }
    }
    return 0;
  }

  bool sameAddressAs(const UDPContext& other) const
  {
    return msg_hdr.msg_namelen == other.msg_hdr.msg_namelen &&
           memcmp(msg_hdr.msg_name, other.msg_hdr.msg_name, msg_hdr.msg_namelen) == 0;
  }

  void copyInIov(struct iovec& opposingVec)
  {
    ensureCapacity(opposingVec.iov_len);
    msg_len = opposingVec.iov_len;
    msg_hdr.msg_iov[0].iov_len = opposingVec.iov_len;
    clearUdpSegmentSize();

    memcpy(buffer(), opposingVec.iov_base, msg_len);
  }

  void copyInIovs(const struct iovec *iov, size_t iovlen)
  {
    size_t totalLength = 0;
    for (size_t i = 0; i < iovlen; ++i)
    {
      totalLength += iov[i].iov_len;
    }
    ensureCapacity(totalLength);
    uint8_t *out = buffer();
    for (size_t i = 0; i < iovlen; ++i)
    {
      memcpy(out, iov[i].iov_base, iov[i].iov_len);
      out += iov[i].iov_len;
    }
    setLength(totalLength);
    clearUdpSegmentSize();
  }

  void copyInAddress(const struct sockaddr *destination)
  {
    memcpy(address(), destination, sizeof(struct sockaddr_in6));
    msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
  }

  void copyInPacket(const struct sockaddr *sourceAddress, socklen_t sourceAddressLen, const void *payload, size_t payloadLength)
  {
    memcpy(address(), sourceAddress, sourceAddressLen);
    msg_hdr.msg_namelen = sourceAddressLen;
    ensureCapacity(payloadLength);
    memcpy(buffer(), payload, payloadLength);
    setLength(payloadLength);
    clearUdpSegmentSize();
  }

  void copyFrom(const UDPContext& source)
  {
    size_t sourceLength = source.length();
    ensureCapacity(sourceLength);
    memcpy(address(), source.address(), source.msg_hdr.msg_namelen);
    msg_hdr.msg_namelen = source.msg_hdr.msg_namelen;
    memcpy(buffer(), source.msg_hdr.msg_iov[0].iov_base, sourceLength);
    setLength(sourceLength);
    if (source.udp_segment_size != 0)
    {
      setUdpSegmentSize(source.udp_segment_size);
    }
    else
    {
      clearUdpSegmentSize();
    }
  }

  void appendPayloadFrom(const UDPContext& source)
  {
    size_t originalLength = length();
    size_t sourceLength = source.length();
    ensureCapacity(originalLength + sourceLength);
    memcpy(buffer() + originalLength, source.msg_hdr.msg_iov[0].iov_base, sourceLength);
    setLength(originalLength + sourceLength);
  }

  void setExternalView(const struct sockaddr *sourceAddress, socklen_t sourceAddressLen, void *payload, size_t payloadLength)
  {
    memcpy(address(), sourceAddress, sourceAddressLen);
    msg_hdr.msg_namelen = sourceAddressLen;
    msg_hdr.msg_iov[0].iov_base = payload;
    setLength(payloadLength);
    clearUdpSegmentSize();
  }
};

struct MultiUDPContext {

  constexpr static uint16_t batchSize = benchmarkUdpBatchSize;

  UDPContext msgs[batchSize];
  uint16_t count;
  uint16_t sendsInFlight;
  uint64_t udpPacketsInFlight;
  uint16_t sendErrorsInFlight;

  MultiUDPContext()
  {
    reset();
  }

  UDPContext *nextPacket(void)
  {
    return (count < batchSize ? &msgs[count++] : NULL);
  }

  bool isFull(void)
  {
    return (count == batchSize);
  }

  void reset(void)
  {
    count = 0;
    sendsInFlight = 0;
    udpPacketsInFlight = 0;
    sendErrorsInFlight = 0;

    for (auto i = 0; i < batchSize; i++)
    {
      msgs[i].reset();
    }
  }

  void filterDroppedPackets(bool (*shouldDrop)(void *), void *opaque)
  {
    uint16_t write = 0;
    for (uint16_t read = 0; read < count; ++read)
    {
      if (shouldDrop(opaque))
      {
        continue;
      }
      if (write != read)
      {
        msgs[write].copyFrom(msgs[read]);
      }
      ++write;
    }
    for (uint16_t i = write; i < count; ++i)
    {
      msgs[i].reset();
    }
    count = write;
  }

  void coalesceGsoPackets(void)
  {
    if (!benchmarkUdpGsoEnabled() || count < 2)
    {
      return;
    }

    uint16_t configuredMaxSegments = benchmarkUdpGsoMaxSegments();
    uint16_t write = 0;
    for (uint16_t read = 0; read < count;)
    {
      if (write != read)
      {
        msgs[write].copyFrom(msgs[read]);
      }

      UDPContext& current = msgs[write];
      uint16_t segmentSize = static_cast<uint16_t>(current.length());
      uint16_t segments = 1;
      ++read;

      if (current.udpSegmentSize() == 0 && segmentSize > 0 && segmentSize <= MAX_IPV6_UDP_PACKET_SIZE)
      {
        uint16_t maxSegments = std::min<uint16_t>(configuredMaxSegments,
                                                  std::max<uint16_t>(1, static_cast<uint16_t>(MAX_IPV6_UDP_GSO_PAYLOAD_SIZE / segmentSize)));
        while (read < count &&
               segments < maxSegments &&
               msgs[read].udpSegmentSize() == 0 &&
               msgs[read].length() == segmentSize &&
               current.length() + segmentSize <= MAX_IPV6_UDP_GSO_BUFFER_SIZE &&
               current.length() + segmentSize <= MAX_IPV6_UDP_GSO_PAYLOAD_SIZE &&
               current.sameAddressAs(msgs[read]))
        {
          current.appendPayloadFrom(msgs[read]);
          ++segments;
          ++read;
        }
        if (segments > 1)
        {
          current.setUdpSegmentSize(segmentSize);
        }
      }

      ++write;
    }

    for (uint16_t i = write; i < count; ++i)
    {
      msgs[i].reset();
    }
    count = write;
  }
};

struct Timeout {

  struct __kernel_timespec timeout = {}; // same as struct timespec;

  void setTimeout(uint32_t microseconds)
  {
    timeout = {};

    if (microseconds > 0)
    {
      timeout.tv_sec = microseconds / 1'000'000;
      timeout.tv_nsec = (microseconds % 1'000'000) * 1000;
    }
  }

  float timeoutInSeconds(void)
  {
    return ((double)timeout.tv_sec + (double)timeout.tv_nsec / (double)1'000'000'000);
  }
};

template <Mode mode>
class NetworkHub {
private:

  constexpr static bool usesIouring = mode & Mode::iouring;
  constexpr static bool preserveIouringLossSendOrder =
#ifdef QUICZIGPERF
      true;
#else
      false;
#endif
  constexpr static uint16_t iouringBufferGroup = 7;
  constexpr static uint32_t iouringRecvBufferCount = 1024;
  constexpr static size_t iouringRecvControlSize = CMSG_SPACE(sizeof(uint16_t));
  constexpr static size_t iouringRecvBufferSize = sizeof(struct io_uring_recvmsg_out) + sizeof(struct sockaddr_storage) + iouringRecvControlSize + MAX_IPV6_UDP_GSO_BUFFER_SIZE;

  struct io_uring ring;

  void setCallbackData(struct io_uring_sqe *sqe, uint8_t op, void *data)
  {
    sqe->user_data = ((uint64_t)op << 48) | (uint64_t)data;
  }

  MultiUDPContext recvContext; // for syscall recv-ing
  Timeout recvTimeout;
  struct io_uring_buf_ring *iouringRecvRing = nullptr;
  std::vector<void *> iouringRecvBuffers;
  struct msghdr iouringRecvMsg = {};
  UDPContext iouringRecvView;
  UDPContext splitRecvView;
  bool iouringRecvArmed = false;
  int iouringRecvRingMask = 0;
  uint64_t impairmentPacketOrdinal = 0;
  uint64_t iouringSendErrorLogs = 0;
  uint64_t iouringPendingSendSqes = 0;
  struct DeferredIouringRecv {
    UDPContext *packet = nullptr;
    bool pooled = false;
  };
  std::unique_ptr<Pool<UDPContext>> iouringDeferredRecvPool;
  std::vector<std::unique_ptr<UDPContext>> iouringDeferredRecvOverflow;
  std::vector<DeferredIouringRecv> iouringDeferredRecv;

  [[noreturn]] void failIouringSetup(const char *step, int result)
  {
    fprintf(stderr, "quicperf_iouring_setup_failed network_profile=%s step=%s result=%d errno=%d\n",
            benchmarkNetworkProfile, step, result, errno);
    abort();
  }

  void setupIouringRecvRing(void)
  {
    int err = 0;
    iouringRecvRing = io_uring_setup_buf_ring(&ring, iouringRecvBufferCount, iouringBufferGroup, 0, &err);
    if (iouringRecvRing == nullptr)
    {
      failIouringSetup("setup_buf_ring", err);
    }

    iouringRecvRingMask = io_uring_buf_ring_mask(iouringRecvBufferCount);
    iouringRecvBuffers.resize(iouringRecvBufferCount, nullptr);
    for (uint32_t i = 0; i < iouringRecvBufferCount; ++i)
    {
      void *buffer = nullptr;
      if (posix_memalign(&buffer, 64, iouringRecvBufferSize) != 0)
      {
        failIouringSetup("alloc_recv_buffer", -ENOMEM);
      }
      iouringRecvBuffers[i] = buffer;
      io_uring_buf_ring_add(iouringRecvRing, buffer, iouringRecvBufferSize,
                            static_cast<unsigned short>(i), iouringRecvRingMask, static_cast<int>(i));
    }
    io_uring_buf_ring_advance(iouringRecvRing, static_cast<int>(iouringRecvBufferCount));

    memset(&iouringRecvMsg, 0, sizeof(iouringRecvMsg));
    iouringRecvMsg.msg_namelen = sizeof(struct sockaddr_storage);
    iouringRecvMsg.msg_controllen = iouringRecvControlSize;
  }

  void recycleIouringRecvBuffer(uint16_t bid)
  {
    if (bid >= iouringRecvBuffers.size() || iouringRecvBuffers[bid] == nullptr)
    {
      return;
    }

    io_uring_buf_ring_add(iouringRecvRing, iouringRecvBuffers[bid], iouringRecvBufferSize,
                          bid, iouringRecvRingMask, 0);
    io_uring_buf_ring_advance(iouringRecvRing, 1);
  }

  void armIouringRecv(void)
  {
    if (iouringRecvArmed)
    {
      return;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (sqe == nullptr)
    {
      failIouringSetup("get_recv_sqe", -ENOMEM);
    }

    io_uring_prep_recvmsg_multishot(sqe, 0, &iouringRecvMsg, 0);
    sqe->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
    sqe->buf_group = iouringBufferGroup;
    setCallbackData(sqe, IORING_OP_RECVMSG, nullptr);
    iouringRecvArmed = true;
  }

  uint16_t iouringGroSegmentSize(struct io_uring_recvmsg_out *out)
  {
    for (struct cmsghdr *cmsg = io_uring_recvmsg_cmsg_firsthdr(out, &iouringRecvMsg);
         cmsg != nullptr;
         cmsg = io_uring_recvmsg_cmsg_nexthdr(out, &iouringRecvMsg, cmsg))
    {
      if (cmsg->cmsg_level == IPPROTO_UDP && cmsg->cmsg_type == UDP_GRO &&
          cmsg->cmsg_len >= CMSG_LEN(sizeof(uint16_t)))
      {
        uint16_t segmentSize = 0;
        memcpy(&segmentSize, CMSG_DATA(cmsg), sizeof(segmentSize));
        return segmentSize;
      }
    }
    return 0;
  }

  DeferredIouringRecv acquireDeferredIouringRecv(void)
  {
    if (iouringDeferredRecvPool)
    {
      UDPContext *packet = iouringDeferredRecvPool->get();
      if (packet != nullptr)
      {
        return DeferredIouringRecv {.packet = packet, .pooled = true};
      }
    }

    auto owned = std::make_unique<UDPContext>();
    UDPContext *packet = owned.get();
    iouringDeferredRecvOverflow.emplace_back(std::move(owned));
    return DeferredIouringRecv {.packet = packet, .pooled = false};
  }

  void deferReceivedPayload(const struct sockaddr *sourceAddress, socklen_t sourceAddressLen,
                            void *payload, size_t payloadLength)
  {
    DeferredIouringRecv deferred = acquireDeferredIouringRecv();
    deferred.packet->copyInPacket(sourceAddress, sourceAddressLen, payload, payloadLength);
    iouringDeferredRecv.emplace_back(deferred);
  }

  template <typename Consumer>
  void deliverReceivedPacket(UDPContext& view, const struct sockaddr *sourceAddress, socklen_t sourceAddressLen,
                             void *payload, size_t payloadLength, uint16_t groSegmentSize, Consumer& msgConsumer)
  {
    if (groSegmentSize == 0 || payloadLength <= groSegmentSize)
    {
      view.setExternalView(sourceAddress, sourceAddressLen, payload, payloadLength);
      benchmarkRecordUdpPacketsReceived(1);
      msgConsumer(&view);
      return;
    }

    uint64_t delivered = 0;
    for (size_t offset = 0; offset < payloadLength; offset += groSegmentSize)
    {
      size_t segmentLength = std::min<size_t>(groSegmentSize, payloadLength - offset);
      view.setExternalView(sourceAddress, sourceAddressLen,
                           static_cast<uint8_t *>(payload) + offset, segmentLength);
      msgConsumer(&view);
      ++delivered;
    }
    benchmarkRecordUdpPacketsReceived(delivered);
  }

  void deferReceivedPacket(const struct sockaddr *sourceAddress, socklen_t sourceAddressLen,
                           void *payload, size_t payloadLength, uint16_t groSegmentSize)
  {
    if (groSegmentSize == 0 || payloadLength <= groSegmentSize)
    {
      deferReceivedPayload(sourceAddress, sourceAddressLen, payload, payloadLength);
      benchmarkRecordUdpPacketsReceived(1);
      return;
    }

    uint64_t deferredPackets = 0;
    for (size_t offset = 0; offset < payloadLength; offset += groSegmentSize)
    {
      size_t segmentLength = std::min<size_t>(groSegmentSize, payloadLength - offset);
      deferReceivedPayload(sourceAddress, sourceAddressLen,
                           static_cast<uint8_t *>(payload) + offset, segmentLength);
      ++deferredPackets;
    }
    benchmarkRecordUdpPacketsReceived(deferredPackets);
  }

  template <typename Consumer>
  void handleIouringRecvCqe(struct io_uring_cqe *cqe, Consumer& msgConsumer)
  {
    if ((cqe->flags & IORING_CQE_F_MORE) == 0)
    {
      iouringRecvArmed = false;
    }

    if (cqe->res <= 0 || (cqe->flags & IORING_CQE_F_BUFFER) == 0)
    {
      return;
    }

    uint16_t bid = static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    if (bid >= iouringRecvBuffers.size())
    {
      return;
    }

    void *buffer = iouringRecvBuffers[bid];
    struct io_uring_recvmsg_out *out = io_uring_recvmsg_validate(buffer, cqe->res, &iouringRecvMsg);
    if (out != nullptr && out->payloadlen <= MAX_IPV6_UDP_GSO_BUFFER_SIZE)
    {
      deliverReceivedPacket(iouringRecvView,
                            reinterpret_cast<const struct sockaddr *>(io_uring_recvmsg_name(out)),
                            out->namelen,
                            io_uring_recvmsg_payload(out, &iouringRecvMsg),
                            out->payloadlen,
                            iouringGroSegmentSize(out),
                            msgConsumer);
    }

    recycleIouringRecvBuffer(bid);
  }

  void deferIouringRecvCqe(struct io_uring_cqe *cqe)
  {
    if ((cqe->flags & IORING_CQE_F_MORE) == 0)
    {
      iouringRecvArmed = false;
    }

    if (cqe->res <= 0 || (cqe->flags & IORING_CQE_F_BUFFER) == 0)
    {
      return;
    }

    uint16_t bid = static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    if (bid >= iouringRecvBuffers.size())
    {
      return;
    }

    void *buffer = iouringRecvBuffers[bid];
    struct io_uring_recvmsg_out *out = io_uring_recvmsg_validate(buffer, cqe->res, &iouringRecvMsg);
    if (out != nullptr && out->payloadlen <= MAX_IPV6_UDP_GSO_BUFFER_SIZE)
    {
      deferReceivedPacket(
          reinterpret_cast<const struct sockaddr *>(io_uring_recvmsg_name(out)),
          out->namelen,
          io_uring_recvmsg_payload(out, &iouringRecvMsg),
          out->payloadlen,
          iouringGroSegmentSize(out));
    }

    recycleIouringRecvBuffer(bid);
  }

  void handleIouringSendCqe(void *callbackBuffer, int result)
  {
    if (result < 0 && iouringSendErrorLogs < 16)
    {
      ++iouringSendErrorLogs;
      fprintf(stderr, "quicperf_iouring_send_error result=%d\n", result);
    }
    if (callbackBuffer)
    {
      MultiUDPContext *packets = (MultiUDPContext *)callbackBuffer;
      if (result < 0)
      {
        ++packets->sendErrorsInFlight;
      }
      if (packets->sendsInFlight > 0 && --packets->sendsInFlight == 0)
      {
        if (packets->sendErrorsInFlight == 0)
        {
          benchmarkRecordUdpPacketsSent(packets->udpPacketsInFlight);
        }
        packets->reset();
        sendPool.relinquish(packets);
      }
    }
  }

  template <typename Consumer>
  bool deliverDeferredIouringRecv(Consumer& msgConsumer)
  {
    if (iouringDeferredRecv.empty())
    {
      return false;
    }

    std::vector<DeferredIouringRecv> deferred;
    std::vector<std::unique_ptr<UDPContext>> overflow;
    deferred.swap(iouringDeferredRecv);
    overflow.swap(iouringDeferredRecvOverflow);
    for (const DeferredIouringRecv& packet : deferred)
    {
      msgConsumer(packet.packet);
    }
    for (const DeferredIouringRecv& packet : deferred)
    {
      packet.packet->reset();
      if (packet.pooled)
      {
        iouringDeferredRecvPool->relinquish(packet.packet);
      }
    }
    return true;
  }

public:

  alignas(64) uint8_t junk[benchmarkAppChunkSize];

  UDPSocket socket;
  Pool<MultiUDPContext> sendPool;

  NetworkHub(uint16_t port)
      : recvTimeout(),
        socket(port),
        sendPool(50)
  {
    if constexpr (mode & Mode::server)
    {
      RAND_bytes(junk, sizeof(junk));
    }

    if constexpr (usesIouring)
    {
      iouringDeferredRecvPool = std::make_unique<Pool<UDPContext>>(iouringRecvBufferCount);
      iouringDeferredRecv.reserve(iouringRecvBufferCount);
      int flags = fcntl(socket.fd, F_GETFL, 0);
      if (flags >= 0)
      {
        fcntl(socket.fd, F_SETFL, flags | O_NONBLOCK);
      }

      struct io_uring_params params = {};
      params.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQSIZE;
      params.cq_entries = 32'768;

      int result = io_uring_queue_init_params(16'000, &ring, &params);
      if (result < 0)
      {
        failIouringSetup("queue_init", result);
      }

      result = io_uring_register_files(&ring, &socket.fd, 1);
      if (result < 0)
      {
        failIouringSetup("register_files", result);
      }

      setupIouringRecvRing();
      armIouringRecv();
      io_uring_submit(&ring);
    }

    if constexpr (mode & Mode::server)
    {
      listen(socket.fd, SOMAXCONN);
    }
  }

  ~NetworkHub()
  {
    if constexpr (usesIouring)
    {
      if (iouringRecvRing != nullptr)
      {
        io_uring_free_buf_ring(&ring, iouringRecvRing, iouringRecvBufferCount, iouringBufferGroup);
      }
      for (void *buffer : iouringRecvBuffers)
      {
        free(buffer);
      }
    }

    if constexpr (usesIouring)
    {
      io_uring_queue_exit(&ring);
    }

    close(socket.fd);
  }

  bool shouldDropBenchmarkPacket(void)
  {
    if (!benchmarkIsLossRecovery() || benchmarkLossDropEveryPackets == 0)
    {
      return false;
    }

    const uint64_t ordinal = ++impairmentPacketOrdinal;
    if (ordinal <= benchmarkLossWarmupPackets)
    {
      return false;
    }
    return ((ordinal - benchmarkLossWarmupPackets) % benchmarkLossDropEveryPackets) == 0;
  }

  static bool shouldDropBenchmarkPacketThunk(void *opaque)
  {
    return static_cast<NetworkHub *>(opaque)->shouldDropBenchmarkPacket();
  }

  void sendBatch(MultiUDPContext *packets)
  {
    if (benchmarkIsLossRecovery())
    {
      packets->filterDroppedPackets(&NetworkHub::shouldDropBenchmarkPacketThunk, this);
    }
    packets->coalesceGsoPackets();
    if (packets->count == 0)
    {
      packets->reset();
      sendPool.relinquish(packets);
      return;
    }

    if constexpr (mode & Mode::syscall)
    {
      uint16_t sent = 0;
      while (sent < packets->count)
      {
        benchmarkRecordUdpSendSyscalls(1);
        int result = sendmmsg(socket.fd, reinterpret_cast<struct mmsghdr *>(packets->msgs + sent), packets->count - sent, 0);
        if (result <= 0)
        {
          break;
        }
        uint64_t udpPackets = 0;
        for (int i = 0; i < result; ++i)
        {
          udpPackets += packets->msgs[sent + i].udpPacketCount();
        }
        benchmarkRecordUdpPacketsSent(udpPackets);
        sent += static_cast<uint16_t>(result);
      }

      packets->reset();
      sendPool.relinquish(packets);
    }
    else
    {
      struct io_uring_sqe *sqe;
      packets->sendsInFlight = 0;

      uint16_t submitCount = packets->count;

      // printf("(A) sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));

      for (uint16_t i = 0, submitted = 0; i < packets->count; i++)
      {
        ++submitted;
        struct msghdr& msg = packets->msgs[i].msg_hdr;

        sqe = io_uring_get_sqe(&ring);
        if (sqe == nullptr)
        {
          flush();
          sqe = io_uring_get_sqe(&ring);
        }
        if (sqe == nullptr)
        {
          failIouringSetup("get_send_sqe", -ENOMEM);
        }
        io_uring_prep_sendmsg(sqe, 0, &msg, 0);
        unsigned int flags = IOSQE_FIXED_FILE;
        if (benchmarkIsLossRecovery() && preserveIouringLossSendOrder && submitted < submitCount)
        {
          flags |= IOSQE_IO_LINK;
        }
        io_uring_sqe_set_flags(sqe, flags);
        setCallbackData(sqe, IORING_OP_SENDMSG, packets);
        ++packets->sendsInFlight;
        packets->udpPacketsInFlight += packets->msgs[i].udpPacketCount();
        ++iouringPendingSendSqes;
      }
      if (packets->sendsInFlight == 0)
      {
        packets->reset();
        sendPool.relinquish(packets);
      }

      // printf("(B) sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));
    }
  }

  void flush(void)
  {
    if constexpr (usesIouring)
    {
      if (!iouringRecvArmed)
      {
        armIouringRecv();
      }
      if (io_uring_sq_ready(&ring) > 0)
      {
        const bool hasPendingSend = iouringPendingSendSqes > 0;
        int result = io_uring_submit(&ring);
        if (result >= 0 && hasPendingSend)
        {
          benchmarkRecordUdpSendSyscalls(1);
          iouringPendingSendSqes = 0;
        }
      }
    }
  }

  void drainSendCompletions(void)
  {
    if constexpr (usesIouring)
    {
      for (int i = 0; i < 8; ++i)
      {
        io_uring_submit_and_get_events(&ring);
        struct io_uring_cqe *cqe;
        if (io_uring_peek_cqe(&ring, &cqe) < 0)
        {
          break;
        }

        uint32_t head;
        uint32_t count = 0;
        io_uring_for_each_cqe(&ring, head, cqe)
        {
          ++count;
          uint64_t user_data = (uint64_t)io_uring_cqe_get_data(cqe);
          int op = user_data >> 48;
          void *callbackBuffer = (void *)((user_data << 16) >> 16);
          switch (op)
          {
            case IORING_OP_SENDMSG:
              handleIouringSendCqe(callbackBuffer, cqe->res);
              break;
            case IORING_OP_RECVMSG:
              deferIouringRecvCqe(cqe);
              break;
            default:
              break;
          }
        }
        io_uring_cq_advance(&ring, count);
        if (!iouringRecvArmed)
        {
          armIouringRecv();
          io_uring_submit(&ring);
        }
        if (count == 0)
        {
          break;
        }
      }
    }
  }

  template <typename Consumer>
  bool recvmsgWithTimeout(int64_t timeoutus, Consumer&& msgConsumer) // timeout in microseconds
  {
    benchmarkRecordUdpRecvPoll();
    if constexpr (mode & Mode::syscall)
    {
      int flags = MSG_WAITFORONE;
      if (timeoutus <= 0)
      {
        flags |= MSG_DONTWAIT;
      }
      else
      {
        struct pollfd pfd = {.fd = socket.fd, .events = POLLIN, .revents = 0};
        int timeoutMs = static_cast<int>((timeoutus + 999) / 1000);
        int ready = poll(&pfd, 1, timeoutMs);
        if (ready == 0)
        {
          return true;
        }
        if (ready < 0)
        {
          if (errno == EINTR)
          {
            return true;
          }
          return false;
        }
        flags |= MSG_DONTWAIT;
      }

      for (uint16_t i = 0; i < MultiUDPContext::batchSize; ++i)
      {
        recvContext.msgs[i].ensureCapacity(MAX_IPV6_UDP_GSO_BUFFER_SIZE);
        recvContext.msgs[i].setLength(MAX_IPV6_UDP_GSO_BUFFER_SIZE);
        recvContext.msgs[i].enableRecvControl();
      }

      std::array<struct mmsghdr, MultiUDPContext::batchSize> recvHeaders = {};
      for (uint16_t i = 0; i < MultiUDPContext::batchSize; ++i)
      {
        recvHeaders[i].msg_hdr = recvContext.msgs[i].msg_hdr;
      }

      int result = recvmmsg(socket.fd, recvHeaders.data(), MultiUDPContext::batchSize, flags, NULL);

      if (result < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          return timeoutus <= 0;
        }
        return false;
      }

      for (auto i = 0; i < result; i++)
      {
        UDPContext *packet = &recvContext.msgs[i];
        packet->msg_hdr.msg_namelen = recvHeaders[i].msg_hdr.msg_namelen;
        packet->msg_hdr.msg_controllen = recvHeaders[i].msg_hdr.msg_controllen;
        packet->msg_hdr.msg_flags = recvHeaders[i].msg_hdr.msg_flags;
        packet->msg_len = recvHeaders[i].msg_len;
        deliverReceivedPacket(splitRecvView,
                              packet->address(),
                              packet->msg_hdr.msg_namelen,
                              packet->buffer(),
                              packet->msg_len,
                              packet->receivedGroSegmentSize(),
                              msgConsumer);
        packet->reset();
      }
    }
    else
    {
      if (deliverDeferredIouringRecv(msgConsumer))
      {
        return false;
      }

      armIouringRecv();

      struct io_uring_cqe *cqe;
      uint64_t user_data;
      void *callbackBuffer;
      int op;
      int result;
      uint32_t head;
      uint32_t count = 0;

      // printf("unconsumed cqes = %ld\n", io_uring_cq_ready(&ring));
      // printf("unsubmitted sqes = %ld\n", io_uring_sq_ready(&ring));
      // printf("cqe space left = %ld\n", *(ring.cq.kring_entries) - io_uring_cq_ready(&ring));
      // if ((rand() % 250) == 0) printf("sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));

      if (timeoutus <= 0)
      {
        io_uring_submit_and_get_events(&ring);
        if (io_uring_peek_cqe(&ring, &cqe) < 0)
        {
          return true;
        }
      }
      else
      {
        io_uring_submit(&ring);
        recvTimeout.setTimeout(timeoutus);
        if (io_uring_wait_cqe_timeout(&ring, &cqe, &recvTimeout.timeout) < 0)
        {
          return true;
        }
      }

      io_uring_for_each_cqe(&ring, head, cqe)
      {
        ++count;
        user_data = (uint64_t)io_uring_cqe_get_data(cqe);
        op = user_data >> 48;
        callbackBuffer = (void *)((user_data << 16) >> 16);
        result = cqe->res;

        switch (op)
        {
          case IORING_OP_RECVMSG:
            {
              handleIouringRecvCqe(cqe, msgConsumer);
              break;
            }
          case IORING_OP_SENDMSG:
            {
              // if (result < 0) printf("IORING_OP_SENDMMSG, result = %d\n", result);

              handleIouringSendCqe(callbackBuffer, result);

              break;
            }
          default:
            if (result < 0)
            {
              // printf("IORING_OP_SENDMSG, result = %d\n", result);
              // printf("unconsumed cqes = %ld\n", io_uring_cq_ready(&ring));
              // printf("unsubmitted sqes = %ld\n", io_uring_sq_ready(&ring));
              // printf("cqe space left = %ld\n", *(ring.cq.kring_entries) - io_uring_cq_ready(&ring));
              // printf("sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));
            }
            break;
        }
      }

      // uint32_t cqesAvailable = io_uring_cq_ready(&ring);

      io_uring_cq_advance(&ring, count);
      if constexpr (usesIouring)
      {
        if (!iouringRecvArmed)
        {
          armIouringRecv();
          io_uring_submit(&ring);
        }
      }
    }

    return false;
  }
};
