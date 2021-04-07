#pragma once

#include <netinet/in.h>
#include <sys/socket.h>
#include <chrono>
#include <cstring>
#include <string>
#include <byteswap.h>
#include <sched.h>

enum class Mode : uint16_t {

	client 		 = 0b0000'0000'0000'0001,
	server 		 = 0b0000'0000'0000'0010,
	iouring 		 = 0b0000'0000'0000'0100,
	syscall 		 = 0b0000'0000'0000'1000
};

constexpr bool operator &(Mode lhs, Mode rhs)
{
   return static_cast<bool>((static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs)) == static_cast<uint8_t>(rhs));
}

constexpr Mode operator |(Mode lhs, Mode rhs)  
{
   return static_cast<Mode> (static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs));
}

// static const char * modeToString(Mode mode)
// {
// 	if (mode & Mode::server) 	return "server";
// 	else 								return "client";
// }

template <Mode mode>
class NetworkHub;

template <Mode mode>
class QuicLibrary {
public:

	NetworkHub<mode> *networkHub;

	virtual void instanceSetup(uint16_t localPort, int argc, char *argv[]) = 0;

	virtual void connectToServer(struct sockaddr *address) = 0;
	virtual void openStream(void) = 0;
	virtual void startPerfTest(uint64_t nBytes = 0) = 0;
};

#ifdef LSPERF
	#include "perf.networking.h"
	#include "perf.tls.h"
	#include "perf.lsquic.h"
#endif

#ifdef PICOPERF
	#include "perf.networking.h"
	#include "perf.picoquic.h"
#endif

#ifdef QUICHEPERF
	#include "perf.networking.h"
	#include "perf.tls.h"
	#include "perf.quiche.h"
#endif

#ifdef NGTCP2PERF
	#include "perf.networking.h"
	#include "perf.tls.h"
	#include "perf.ngtcp2.h"
#endif

#ifdef TCPPERF
	#include "perf.tls.h"
	#include "perf.tcp.h"
#endif

template <Mode mode>
static void globalSetup(void)
{
	int cpu_pin = sched_getcpu();

   cpu_set_t affinity;
   CPU_SET(cpu_pin, &affinity);
   sched_setaffinity(0, sizeof(affinity), &affinity);

#ifdef LSPERF
	Lsquic<mode>::globalSetup();
#endif
}

template <Mode mode>
static QuicLibrary<mode>* libraryForChoice(void)
{
#ifdef LSPERF
	return new Lsquic<mode>();
#endif
#ifdef PICOPERF
	return new Picoquic<mode>();
#endif
#ifdef QUICHEPERF
	return new Quiche<mode>();
#endif
#ifdef NGTCP2PERF
   return new Ngtcp2<mode>();
#endif
#ifdef TCPPERF
   return new TCPTLS<mode>();
#endif
}
