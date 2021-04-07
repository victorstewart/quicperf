#include "liburing.h"
#include <openssl/rand.h>
#include <vector>
#include <stdlib.h>
#include <cstdlib>

#pragma once

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


uint64_t timeNowUs(void)
{
	return std::chrono::duration_cast<std::chrono::microseconds>((std::chrono::system_clock::now().time_since_epoch())).count();
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

   	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const uint32_t[]){ 10'000 * 1500 }, sizeof(uint32_t));
   	auto val = 1;
   	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                   static_cast<socklen_t>(sizeof(val)));

   	addressLen = sizeof(struct sockaddr_in6);

   	address6 = (struct sockaddr_in6 *)calloc(1, addressLen);
	   address6->sin6_family = AF_INET6;
	   address6->sin6_flowinfo = 0;
	   address6->sin6_port = htons(port);
	   address6->sin6_addr = serverAddress;

      bind(fd, (struct sockaddr *)address6, addressLen);
    }
};

#define MAX_IPV6_UDP_PACKET_SIZE (1500 - 40 - 8)
#define MAX_GRO_SIZE (MAX_IPV6_UDP_PACKET_SIZE * 64)

struct UDPContext {

	struct msghdr msg_hdr;
	unsigned int  msg_len;

	UDPContext()
	{
		memset(&msg_hdr, 0, sizeof(struct msghdr));
		msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
		msg_hdr.msg_name = malloc(msg_hdr.msg_namelen);
	   
		msg_hdr.msg_iov = (struct iovec *)malloc(sizeof(struct iovec));
		msg_hdr.msg_iov[0].iov_len = MAX_GRO_SIZE;
		msg_hdr.msg_iov[0].iov_base = malloc(MAX_GRO_SIZE);
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

	void setLength(uint16_t length)
	{
		msg_hdr.msg_iov[0].iov_len = length;
		msg_len = length;
	}

	void reset(void)
	{
		msg_len = 0;
		setLength(MAX_GRO_SIZE);
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
	}
};

struct MultiUDPContext {
		
	static constexpr uint16_t batchSize = 150;

	UDPContext msgs[batchSize];
	uint16_t count;

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

   struct io_uring ring;

	void setCallbackData(struct io_uring_sqe *sqe, uint8_t op, void *data)
	{
		sqe->user_data = ((uint64_t)op << 48) | (uint64_t)data;
	}

	MultiUDPContext recvContext; // for syscall recv-ing
   Pool<UDPContext> recvPool;	  // for iouring recv-ing
   Timeout recvTimeout;

public:

	uint8_t junk[94 * 1024];

   UDPSocket socket;
   Pool<MultiUDPContext> sendPool;

   NetworkHub(uint16_t port) : socket(port), recvTimeout(), sendPool(50), recvPool(25)
   {
      if constexpr (mode & Mode::server)
      {
      	RAND_bytes(junk, sizeof(junk));
      }

      if constexpr (mode & Mode::iouring)
      {
      	struct io_uring_params params = {};

	      io_uring_queue_init_params(16000, &ring, &params);

	      io_uring_register_files(&ring, &socket.fd, 1);
      }

      if constexpr (mode & Mode::server)
      {
      	listen(socket.fd, SOMAXCONN);
      }
   }

   void sendBatch(MultiUDPContext *packets)
   {
   	if constexpr (mode & Mode::syscall)
   	{
   		int result = sendmmsg(socket.fd, (struct mmsghdr *)packets->msgs, packets->count, 0);

   		//if (result < 0) printf("syscall sendBatch -> errno = %d\n", errno);

   		packets->reset();
   		sendPool.relinquish(packets);
   	}
   	else
   	{
   		struct io_uring_sqe *sqe;

   		//printf("(A) sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));

   		for (uint16_t i = 0; i < packets->count; i++)
   		{
   			struct msghdr& msg = packets->msgs[i].msg_hdr;

   			sqe = io_uring_get_sqe(&ring);
   			io_uring_prep_sendmsg(sqe, 0, &msg, 0);
   			io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
   		}

   		//printf("(B) sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));

   		setCallbackData(sqe, IORING_OP_SENDMSG, packets);
   	}
   }

   template <typename Consumer>
   bool recvmsgWithTimeout(int64_t timeoutus, Consumer&& msgConsumer) // timeout in microseconds
   {
   	if constexpr (mode & Mode::syscall)
   	{
   		if (timeoutus > 0)
   		{
           	struct timeval t = {.tv_sec = timeoutus / 1'000'000, .tv_usec = (timeoutus % 1'000'000)};

   			fd_set read_fds;
   			FD_ZERO(&read_fds);
   			FD_SET(socket.fd, &read_fds);

   			if (select(socket.fd + 1, &read_fds, NULL, NULL, &t) == 0) return true;
   		}

   		int result = recvmmsg(socket.fd, (struct mmsghdr *)recvContext.msgs, 150, MSG_WAITFORONE,  NULL);

   		//if (result < 0) printf("syscall sendBatch -> errno = %d\n", errno);

 			for (auto i = 0; i < result; i++)
 			{
 				UDPContext *packet = &recvContext.msgs[i];
 				msgConsumer(packet);
 				packet->reset();
 			}
   	}
   	else
   	{
   		// recvPool keep max in play at all times
			while (recvPool.howManyLeft() > 0)
			{
				UDPContext *context = recvPool.get();
				context->setLength(MAX_IPV6_UDP_PACKET_SIZE);

				struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
      		io_uring_prep_recvmsg(sqe, 0, &context->msg_hdr, 0);
      		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
      		setCallbackData(sqe, IORING_OP_RECVMSG, context);
      	}

	   	struct io_uring_cqe *cqe;
			uint64_t user_data;
			void *callbackBuffer;
			int op;
			int result;
			uint32_t head;
			uint32_t count;

			// printf("unconsumed cqes = %ld\n", io_uring_cq_ready(&ring));
			// printf("unsubmitted sqes = %ld\n", io_uring_sq_ready(&ring));
			// printf("cqe space left = %ld\n", *(ring.cq.kring_entries) - io_uring_cq_ready(&ring));
			//if ((rand() % 250) == 0) printf("sqe space left = %ld\n", *(ring.sq.kring_entries) - io_uring_sq_ready(&ring));

			io_uring_submit(&ring);

			recvTimeout.setTimeout(timeoutus);
			if (io_uring_wait_cqe_timeout(&ring, &cqe, &recvTimeout.timeout) < 0) return true;

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
						//if (result < 0) printf("IORING_OP_RECVMSG, result = %d\n", result);

						if (result > 0)
						{
							UDPContext *packet = (UDPContext *)callbackBuffer;
							packet->msg_len = result;
							msgConsumer(packet);
							recvPool.relinquish(packet);
						}
			
						break;
					}
					case IORING_OP_SENDMSG:
					{
						//if (result < 0) printf("IORING_OP_SENDMMSG, result = %d\n", result);

						if (callbackBuffer)
						{
							MultiUDPContext *packets = (MultiUDPContext *)callbackBuffer;
							packets->reset();
							sendPool.relinquish(packets);
						}
						
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
		}

		return false;
   }
};