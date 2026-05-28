#pragma once

#include <netinet/in.h>
#include <sys/socket.h>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <byteswap.h>

#include "perf.benchmark.h"

enum class Mode : uint16_t {

  client = 0b0000'0000'0000'0001,
  server = 0b0000'0000'0000'0010,
  iouring = 0b0000'0000'0000'0100,
  syscall = 0b0000'0000'0000'1000
};

constexpr bool operator&(Mode lhs, Mode rhs)
{
  return static_cast<bool>((static_cast<uint16_t>(lhs) & static_cast<uint16_t>(rhs)) == static_cast<uint16_t>(rhs));
}

constexpr Mode operator|(Mode lhs, Mode rhs)
{
  return static_cast<Mode>(static_cast<uint16_t>(lhs) | static_cast<uint16_t>(rhs));
}

// static const char * modeToString(Mode mode)
// {
// 	if (mode & Mode::server) 	return "server";
// 	else 								return "client";
// }

template <Mode mode>
class NetworkHub;

struct BenchmarkResumptionState {
  std::vector<uint8_t> session;
  std::vector<uint8_t> transportParams;
  std::string proofLabel;
  std::shared_ptr<void> opaqueState;
};

template <Mode mode>
class QuicLibrary {
public:

  NetworkHub<mode> *networkHub;

  virtual ~QuicLibrary() = default;

  virtual void instanceSetup(uint16_t localPort, int argc, char *argv[]) = 0;

  virtual void connectToServer(struct sockaddr *address) = 0;
  virtual void openStream(void) = 0;
  virtual void startPerfTest(uint64_t nBytes = 0) = 0;
  virtual void idleHold(uint64_t holdMs)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(holdMs));
  }
  virtual void postPerfTest() {}
  virtual bool supportsSessionResumption(void) const
  {
    return false;
  }
  virtual bool supportsZeroRtt(void) const
  {
    return false;
  }
  virtual bool exportResumptionState(BenchmarkResumptionState&)
  {
    return false;
  }
  virtual bool importResumptionState(const BenchmarkResumptionState&, bool)
  {
    return false;
  }
  virtual void connectToServerForZeroRtt(struct sockaddr *address)
  {
    connectToServer(address);
  }
  virtual bool connectionWasResumed(void) const
  {
    return false;
  }
  virtual bool zeroRttWasAttempted(void) const
  {
    return false;
  }
  virtual bool zeroRttWasAccepted(void) const
  {
    return false;
  }
  virtual bool zeroRttWasRejected(void) const
  {
    return false;
  }
  virtual const char *resumptionProofLabel(void) const
  {
    return "none";
  }
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

#ifdef TQUICPERF
#include "perf.networking.h"
#include "perf.tquic.h"
#endif

#ifdef XQUICPERF
#include "perf.networking.h"
#include "perf.xquic.h"
#endif

#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF) || defined(QUICZIGPERF)
#include "perf.networking.h"
#include "perf.packet_engine.h"
#endif

#ifdef MVFSTPERF
#include "perf.networking.h"
#include "perf.mvfst.h"
#endif

template <Mode mode>
static void globalSetup(void)
{
#ifdef LSPERF
  Lsquic<mode>::globalSetup();
#endif
}

template <Mode mode>
static QuicLibrary<mode> *libraryForChoice(void)
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
#ifdef TQUICPERF
  return new Tquic<mode>();
#endif
#ifdef XQUICPERF
  return new Xquic<mode>();
#endif
#ifdef QUINNPERF
  return new Quinn<mode>();
#endif
#ifdef NOQPERF
  return new Noq<mode>();
#endif
#ifdef NEQOPERF
  return new Neqo<mode>();
#endif
#ifdef S2NPERF
  return new S2n<mode>();
#endif
#ifdef QUICZIGPERF
  return new QuicZig<mode>();
#endif
#ifdef MVFSTPERF
  return new Mvfst<mode>();
#endif
}
