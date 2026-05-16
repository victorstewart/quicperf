#include "liburing.h"
#include <openssl/rand.h>
#include <cerrno>
#include <ctime>
#include <fcntl.h>
#include <memory>
#include <poll.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <stdlib.h>
#include <cstdlib>

#pragma once

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


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
	std::vector<T*> available;

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

	T* get(void)
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
	T* address(void)
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

				setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const uint32_t[]){ static_cast<uint32_t>(benchmarkConnectionWindow) }, sizeof(uint32_t));
				setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const uint32_t[]){ static_cast<uint32_t>(benchmarkConnectionWindow) }, sizeof(uint32_t));
				benchmarkRecordSocketBuffers(fd);

			addressLen = sizeof(struct sockaddr_in6);

		address6 = (struct sockaddr_in6 *)calloc(1, addressLen);
	   address6->sin6_family = AF_INET6;
	   address6->sin6_flowinfo = 0;
	   address6->sin6_port = htons(port);
	   address6->sin6_addr = serverAddress;

	      if (bind(fd, (struct sockaddr *)address6, addressLen) != 0)
			{
				fprintf(stderr, "quicperf_socket_error action=bind port=%u errno=%d message=%s\n",
					static_cast<unsigned>(port), errno, strerror(errno));
				abort();
			}
	    }
	};

#define MAX_IPV6_UDP_PACKET_SIZE benchmarkUdpPayloadSize
struct UDPContext {

	struct msghdr msg_hdr;
	unsigned int  msg_len;

		UDPContext()
		{
			memset(&msg_hdr, 0, sizeof(struct msghdr));
			msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
			msg_hdr.msg_name = malloc(msg_hdr.msg_namelen);

		msg_hdr.msg_iov = (struct iovec *)malloc(sizeof(struct iovec));
		msg_hdr.msg_iov[0].iov_len = MAX_IPV6_UDP_PACKET_SIZE;
		msg_hdr.msg_iov[0].iov_base = malloc(MAX_IPV6_UDP_PACKET_SIZE);
		msg_hdr.msg_iovlen = 1;

		// add the interface to every message

		// else if (cmsg->cmsg_level == IPPROTO_IPV6) {
  //           if (cmsg->cmsg_type == IPV6_PKTINFO) {
  //               if (addr_dest != NULL) {
  //                   struct in6_pktinfo* pPktInfo6 = (struct in6_pktinfo*)CMSG_DATA(cmsg);

  //                   ((struct sockaddr_in6*)addr_dest)->sin6_family = AF_INET6;
  //                   ((struct sockaddr_in6*)addr_dest)->sin6_port = 0;
  //                   memcpy(&((struct sockaddr_in6*)addr_dest)->sin6_addr, &pPktInfo6->ipi6_addr, sizeof(struct in6_addr));

  //                   if (dest_if != NULL) {
  //                       *dest_if = (int)pPktInfo6->ipi6_ifindex;
  //                   }
  //               }
  //           }
	}

	template <typename T = struct sockaddr>
	T* address(void)
	{
		return (T *)msg_hdr.msg_name;
	}

	uint8_t* buffer(void)
	{
		return (uint8_t *)msg_hdr.msg_iov[0].iov_base;
	}

		void setLength(size_t length)
		{
			msg_hdr.msg_iov[0].iov_len = length;
			msg_len = length;
	}

		void reset(void)
		{
			msg_len = 0;
			msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
			setLength(MAX_IPV6_UDP_PACKET_SIZE);
		}

	void copyInIov(struct iovec& opposingVec)
	{
		msg_len = opposingVec.iov_len;
		msg_hdr.msg_iov[0].iov_len = opposingVec.iov_len;

		memcpy(buffer(), opposingVec.iov_base, msg_len);
	}

		void copyInAddress(const struct sockaddr *destination)
		{
			memcpy(address(), destination, sizeof(struct sockaddr_in6));
			msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
		}
};

struct MultiUDPContext {

	static constexpr uint16_t batchSize = benchmarkUdpBatchSize;

	UDPContext msgs[batchSize];
	uint16_t count;
	uint16_t sendsInFlight;

	MultiUDPContext()
	{
		reset();
	}

	UDPContext* nextPacket(void)
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

		for (auto i = 0; i < batchSize; i++)
		{
			msgs[i].reset();
		}
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
			timeout.tv_nsec = (microseconds % 1'000'000) * 1'000;
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

	static constexpr bool usesIouring = mode & Mode::iouring;
	static constexpr bool preserveIouringLossSendOrder =
#ifdef QUICZIGPERF
		true;
#else
		false;
#endif
	static constexpr uint16_t iouringBufferGroup = 7;
	static constexpr uint32_t iouringRecvBufferCount = 1024;
	static constexpr size_t iouringRecvBufferSize = sizeof(struct io_uring_recvmsg_out) + sizeof(struct sockaddr_storage) + MAX_IPV6_UDP_PACKET_SIZE;

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
		bool iouringRecvArmed = false;
		int iouringRecvRingMask = 0;
		uint64_t impairmentPacketOrdinal = 0;
		uint64_t iouringSendErrorLogs = 0;
		uint64_t iouringPendingSendSqes = 0;
		std::vector<std::unique_ptr<UDPContext>> iouringDeferredRecv;

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
		if (out != nullptr && out->payloadlen <= MAX_IPV6_UDP_PACKET_SIZE)
		{
			iouringRecvView.msg_hdr.msg_name = io_uring_recvmsg_name(out);
			iouringRecvView.msg_hdr.msg_namelen = out->namelen;
			iouringRecvView.msg_hdr.msg_iov[0].iov_base = io_uring_recvmsg_payload(out, &iouringRecvMsg);
			iouringRecvView.msg_hdr.msg_iov[0].iov_len = out->payloadlen;
			iouringRecvView.msg_len = out->payloadlen;
			benchmarkRecordUdpPacketsReceived(1);
			msgConsumer(&iouringRecvView);
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
			if (out != nullptr && out->payloadlen <= MAX_IPV6_UDP_PACKET_SIZE)
			{
				auto deferred = std::make_unique<UDPContext>();
				deferred->copyInAddress(reinterpret_cast<const struct sockaddr *>(io_uring_recvmsg_name(out)));
				deferred->setLength(out->payloadlen);
				memcpy(deferred->buffer(), io_uring_recvmsg_payload(out, &iouringRecvMsg), out->payloadlen);
				iouringDeferredRecv.emplace_back(std::move(deferred));
				benchmarkRecordUdpPacketsReceived(1);
			}

		recycleIouringRecvBuffer(bid);
	}

		void handleIouringSendCqe(void *callbackBuffer, int result)
		{
			if (result >= 0)
			{
				benchmarkRecordUdpPacketsSent(1);
			}
			if (result < 0 && iouringSendErrorLogs < 16)
			{
				++iouringSendErrorLogs;
				fprintf(stderr, "quicperf_iouring_send_error result=%d\n", result);
			}
			if (callbackBuffer)
			{
			MultiUDPContext *packets = (MultiUDPContext *)callbackBuffer;
			if (packets->sendsInFlight > 0 && --packets->sendsInFlight == 0)
			{
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

		std::vector<std::unique_ptr<UDPContext>> deferred;
		deferred.swap(iouringDeferredRecv);
		for (auto& packet : deferred)
		{
			msgConsumer(packet.get());
		}
		return true;
	}

public:

	alignas(64) uint8_t junk[benchmarkAppChunkSize];

   UDPSocket socket;
   Pool<MultiUDPContext> sendPool;

   NetworkHub(uint16_t port) : recvTimeout(), socket(port), sendPool(50)
   {
      if constexpr (mode & Mode::server)
      {
		RAND_bytes(junk, sizeof(junk));
      }

      if constexpr (usesIouring)
      {
		int flags = fcntl(socket.fd, F_GETFL, 0);
		if (flags >= 0)
		{
			fcntl(socket.fd, F_SETFL, flags | O_NONBLOCK);
		}

			struct io_uring_params params = {};
			params.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQSIZE;
			params.cq_entries = 32768;

	      int result = io_uring_queue_init_params(16000, &ring, &params);
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

   void sendBatch(MultiUDPContext *packets)
   {
	if constexpr (mode & Mode::syscall)
	{
		if (benchmarkIsLossRecovery())
		{
				for (uint16_t i = 0; i < packets->count; ++i)
				{
					if (shouldDropBenchmarkPacket())
					{
						continue;
					}
					benchmarkRecordUdpSendSyscalls(1);
					if (sendmsg(socket.fd, &packets->msgs[i].msg_hdr, 0) < 0)
					{
						break;
					}
					benchmarkRecordUdpPacketsSent(1);
				}
			}
			else
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
					benchmarkRecordUdpPacketsSent(static_cast<uint64_t>(result));
					sent += static_cast<uint16_t>(result);
				}
			}

			packets->reset();
			sendPool.relinquish(packets);
		}
	else
	{
		struct io_uring_sqe *sqe;
		packets->sendsInFlight = 0;

			bool submitPacket[MultiUDPContext::batchSize] = {};
			uint16_t submitCount = 0;
			for (uint16_t i = 0; i < packets->count; ++i)
			{
				submitPacket[i] = !shouldDropBenchmarkPacket();
				if (submitPacket[i])
				{
					++submitCount;
				}
			}

			//printf("(A) sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));

				for (uint16_t i = 0, submitted = 0; i < packets->count; i++)
				{
					if (!submitPacket[i])
					{
					continue;
				}
				++submitted;
				struct msghdr& msg = packets->msgs[i].msg_hdr;

				sqe = io_uring_get_sqe(&ring);
				io_uring_prep_sendmsg(sqe, 0, &msg, 0);
					unsigned int flags = IOSQE_FIXED_FILE;
					if (benchmarkIsLossRecovery() && preserveIouringLossSendOrder && submitted < submitCount)
					{
						flags |= IOSQE_IO_LINK;
					}
					io_uring_sqe_set_flags(sqe, flags);
					setCallbackData(sqe, IORING_OP_SENDMSG, packets);
					++packets->sendsInFlight;
					++iouringPendingSendSqes;
				}
			if (packets->sendsInFlight == 0)
			{
				packets->reset();
				sendPool.relinquish(packets);
			}

			//printf("(B) sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));
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
				int timeoutMs = static_cast<int>((timeoutus + 999) / 1'000);
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

			int result = recvmmsg(socket.fd, reinterpret_cast<struct mmsghdr *>(recvContext.msgs), MultiUDPContext::batchSize, flags, NULL);

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
						msgConsumer(packet);
						packet->reset();
					}
					benchmarkRecordUdpPacketsReceived(static_cast<uint64_t>(result));
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
			//if ((rand() % 250) == 0) printf("sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));

			if (timeoutus <= 0)
			{
					io_uring_submit_and_get_events(&ring);
				if (io_uring_peek_cqe(&ring, &cqe) < 0) return true;
			}
			else
			{
				io_uring_submit(&ring);
				recvTimeout.setTimeout(timeoutus);
				if (io_uring_wait_cqe_timeout(&ring, &cqe, &recvTimeout.timeout) < 0) return true;
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
						//if (result < 0) printf("IORING_OP_SENDMMSG, result = %d\n", result);

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
