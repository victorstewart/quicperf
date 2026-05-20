#define _1GB (1ULL * 1024 * 1024 * 1024)

#include <arpa/inet.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <dirent.h>
#include <string_view>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>
#include <vector>

static const char *tls_cert;
static const char *tls_key;
static const char *tls_chain;
static struct in6_addr serverAddress = {};
static struct in6_addr localAddress = {};

#include "perf.services.h"

constexpr static uint64_t defaultTestBytes = _1GB;

static const char *benchmarkLibrary(void)
{
#ifdef LSPERF
  return "lsquic";
#endif
#ifdef PICOPERF
  return "picoquic";
#endif
#ifdef QUICHEPERF
  return "quiche";
#endif
#ifdef NGTCP2PERF
  return "ngtcp2";
#endif
#ifdef TCPPERF
  return "tcp_tls";
#endif
#ifdef TQUICPERF
  return "tquic";
#endif
#ifdef XQUICPERF
  return "xquic";
#endif
#ifdef QUINNPERF
  return "quinn";
#endif
#ifdef NOQPERF
  return "noq";
#endif
#ifdef NEQOPERF
  return "neqo";
#endif
#ifdef S2NPERF
  return "s2n_quic";
#endif
#ifdef QUICZIGPERF
  return "quic_zig";
#endif
#ifdef MVFSTPERF
  return "mvfst";
#endif
}

[[maybe_unused]] static const char *benchmarkCommonUdpGsoFeature(void)
{
  return benchmarkUdpGsoEnabled() ? "common_cpp" : "off";
}

[[maybe_unused]] static const char *benchmarkCommonUdpGroFeature(void)
{
  return benchmarkUdpGsoEnabled() ? "on" : "debug";
}

static const char *benchmarkAdapterFeatures(void)
{
#ifndef PICOPERF
  static thread_local char features[512];
#endif
#ifdef LSPERF
  snprintf(features, sizeof(features),
           "cc=%s|pacing=on|spin=on|ql_bits=2|ecn=off|pmtud=off|send_batch=50|udp_gso=%s|udp_gro=%s",
           benchmarkCongestionControllerLabel(), benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef PICOPERF
  return benchmarkPicoquicAdapterFeatures();
#endif
#ifdef QUICHEPERF
  snprintf(features, sizeof(features),
           "cc=%s|migration=off|pmtud=off|max_windows=profile|udp_gso=%s|udp_gro=%s",
           benchmarkCongestionControllerLabel("bbr2_gcongestion"), benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef NGTCP2PERF
  snprintf(features, sizeof(features),
           "cc=%s|udp_payload_shaping=off|pmtud=off|max_tx_payload=1452|udp_gso=%s|udp_gro=%s",
           benchmarkCongestionControllerLabel(), benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef TCPPERF
  snprintf(features, sizeof(features),
           "cc=%s_requested|nodelay=on|quickack=on|partial_write=on",
           benchmarkCongestionControllerLabel());
  return features;
#endif
#ifdef TQUICPERF
  snprintf(features, sizeof(features),
           "cc=%s|pacing=on|pmtud=off|send_batch=150|max_conns=server_connections|tls_sigalgs=explicit|udp_gso=%s|udp_gro=%s",
           benchmarkCongestionControllerLabel(), benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef XQUICPERF
  snprintf(features, sizeof(features),
           "cc=%s|pacing=on|sendmmsg=%s|cid_len=12|qlog=off|tls_sigalgs=ssl_ctx_wrap|tls_verify=config_chain_preflight|udp_gso=%s|udp_gro=%s",
           benchmarkCongestionControllerLabel(),
           strcmp(benchmarkNetworkProfile, "iouring") == 0 ? "off" : "on",
           benchmarkCommonUdpGsoFeature(),
           benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef QUINNPERF
  snprintf(features, sizeof(features),
           "cc=%s|sans_io=quinn-proto|cpp_networkhub=on|udp_gso=%s|udp_gro=%s|runtime=none",
           benchmarkCongestionControllerLabel(), benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef NOQPERF
  snprintf(features, sizeof(features),
           "cc=%s|sans_io=noq-proto|cpp_networkhub=on|udp_gso=%s|udp_gro=%s|runtime=none",
           benchmarkCongestionControllerLabel("bbr3"), benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef NEQOPERF
  snprintf(features, sizeof(features),
           "cc=cubic|sans_io=neqo-transport|cpp_networkhub=on|runtime=none|tls_verify=config_chain_preflight|udp_gso=%s|udp_gro=%s",
           benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef S2NPERF
  snprintf(features, sizeof(features),
           "cc=%s|manual_endpoint=s2n-quic|cpp_networkhub=on|udp_gso=%s|udp_gro=%s|runtime=none",
           benchmarkCongestionControllerLabel(), benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef QUICZIGPERF
  snprintf(features, sizeof(features),
           "cc=cubic|bbr=unsupported|packet_api=quic-zig-connection|cpp_networkhub=on|udp_gso=%s|udp_gro=%s|runtime=none|pmtud=off|pacing=library_default|send_backpressure=stream_window|flow_window=profile_request|server_send_rr=on",
           benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
#ifdef MVFSTPERF
  snprintf(features, sizeof(features),
           "cc=%s|cpp_networkhub=on|socket=quic_async_udp_adapter|folly_eventbase=manual|udp_gso=%s|udp_gro=%s|runtime=none|pmtud=off|pacing=on",
           benchmarkCongestionControllerLabel(), benchmarkCommonUdpGsoFeature(), benchmarkCommonUdpGroFeature());
  return features;
#endif
}

static uint64_t envU64(const char *name, uint64_t fallback)
{
  const char *value = getenv(name);
  if (value == nullptr || value[0] == '\0')
  {
    return fallback;
  }

  errno = 0;
  char *end = nullptr;
  uint64_t parsed = strtoull(value, &end, 10);

  if (errno != 0 || end == value || *end != '\0' || parsed == 0)
  {
    return fallback;
  }

  return parsed;
}

static bool envFlag(const char *name, bool fallback)
{
  const char *value = getenv(name);
  if (value == nullptr || value[0] == '\0')
  {
    return fallback;
  }
  if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 ||
      strcmp(value, "yes") == 0 || strcmp(value, "on") == 0)
  {
    return true;
  }
  if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 ||
      strcmp(value, "no") == 0 || strcmp(value, "off") == 0)
  {
    return false;
  }
  return fallback;
}

static uint16_t envPort(const char *name, uint16_t fallback)
{
  uint64_t parsed = envU64(name, fallback);
  if (parsed > 65'535)
  {
    fprintf(stderr, "%s must be <= 65535\n", name);
    exit(2);
  }
  return static_cast<uint16_t>(parsed);
}

static bool parseBenchmarkScenario(std::string_view value, BenchmarkScenario& scenario)
{
  if (value == "download")
  {
    scenario = BenchmarkScenario::download;
    return true;
  }
  if (value == "upload")
  {
    scenario = BenchmarkScenario::upload;
    return true;
  }
  if (value == "connect")
  {
    scenario = BenchmarkScenario::connect;
    return true;
  }
  if (value == "reqresp")
  {
    scenario = BenchmarkScenario::reqresp;
    return true;
  }
  if (value == "stream_churn")
  {
    scenario = BenchmarkScenario::stream_churn;
    return true;
  }
  if (value == "multistream_download")
  {
    scenario = BenchmarkScenario::multistream_download;
    return true;
  }
  if (value == "multistream_upload")
  {
    scenario = BenchmarkScenario::multistream_upload;
    return true;
  }
  if (value == "bidi")
  {
    scenario = BenchmarkScenario::bidi;
    return true;
  }
  if (value == "small_payload_pps")
  {
    scenario = BenchmarkScenario::small_payload_pps;
    return true;
  }
  if (value == "loss_recovery")
  {
    scenario = BenchmarkScenario::loss_recovery;
    return true;
  }
  if (value == "flow_control")
  {
    scenario = BenchmarkScenario::flow_control;
    return true;
  }
  if (value == "resumed_connect")
  {
    scenario = BenchmarkScenario::resumed_connect;
    return true;
  }
  if (value == "zero_rtt_reqresp")
  {
    scenario = BenchmarkScenario::zero_rtt_reqresp;
    return true;
  }
  if (value == "datagram")
  {
    scenario = BenchmarkScenario::datagram;
    return true;
  }
  if (value == "idle_footprint")
  {
    scenario = BenchmarkScenario::idle_footprint;
    return true;
  }
  if (value == "close_reset_cleanup")
  {
    scenario = BenchmarkScenario::close_reset_cleanup;
    return true;
  }

  return false;
}

static void usage(const char *argv0)
{
  fprintf(stderr, "usage: %s <server|client> <syscall|iouring> <any|loopback|ipv6> [scenario]\n", argv0);
  fprintf(stderr, "scenarios: download upload connect reqresp stream_churn multistream_download multistream_upload bidi small_payload_pps loss_recovery flow_control resumed_connect zero_rtt_reqresp datagram idle_footprint close_reset_cleanup\n");
}

static const char *benchmarkNetworkLabel(std::string_view requested)
{
  if (requested == "iouring")
  {
    return requested.data();
  }
  return "syscall";
}

static const char *envString(const char *name, const char *fallback)
{
  const char *value = getenv(name);
  return (value == nullptr || value[0] == '\0') ? fallback : value;
}

static bool tlsVerifyModeIsKnown(const char *mode)
{
  return strcmp(mode, "disabled") == 0 || strcmp(mode, "peer") == 0 || strcmp(mode, "chain") == 0;
}

static bool parseBenchmarkAddress(const char *value, struct in6_addr& address)
{
  if (strcmp(value, "any") == 0)
  {
    address = in6addr_any;
    return true;
  }
  if (strcmp(value, "loopback") == 0)
  {
    address = in6addr_loopback;
    return true;
  }
  return inet_pton(AF_INET6, value, &address) == 1;
}

static uint64_t benchmarkBdpWindowBytes(void)
{
  if (benchmarkPathRttUs == 0 || benchmarkPathMaxRateBps == 0)
  {
    return benchmarkDefaultConnectionWindow;
  }

  const uint64_t bdpBytes = ((benchmarkPathMaxRateBps * benchmarkPathRttUs) + 7'999'999ULL) / 8'000'000ULL;
  const uint64_t minWindow = 1ULL * 1024ULL * 1024ULL;
  const uint64_t maxWindow = 512ULL * 1024ULL * 1024ULL;
  return std::clamp<uint64_t>(bdpBytes * 4ULL, minWindow, maxWindow);
}

static void applyBenchmarkBdpWindowProfile(void)
{
  const uint64_t window = benchmarkBdpWindowBytes();
  benchmarkConnectionWindow = window;
  benchmarkStreamWindow = window;
  benchmarkWindowProfile = "wan-bdp";
}

static void configureBenchmarkProfiles(std::string_view requestedNetwork)
{
  benchmarkBuildProfile = envString("QUICPERF_BUILD_PROFILE", "native-lto");
  benchmarkWindowProfile = envString("QUICPERF_WINDOW_PROFILE", "default");
  benchmarkCongestionProfile = envString("QUICPERF_CONGESTION_PROFILE", "path-auto");
  benchmarkNetworkProfile = envString("QUICPERF_NETWORK_PROFILE", requestedNetwork == "iouring" ? requestedNetwork.data() : "syscall");
  benchmarkPathProfile = envString("QUICPERF_PATH_PROFILE", "loopback");
  benchmarkTlsVerifyMode = envString("QUICPERF_TLS_VERIFY_MODE", envString("QUICPERF_TLS_VERIFY", "disabled"));
  if (!tlsVerifyModeIsKnown(benchmarkTlsVerifyMode))
  {
    benchmarkTlsVerifyMode = "disabled";
  }
  benchmarkTlsCertProfile = envString("QUICPERF_TLS_CERT_PROFILE", "ed25519");
  benchmarkServerTargetConnections = static_cast<uint32_t>(envU64("QUICPERF_SERVER_CONNECTIONS", 1));
  benchmarkPathRttUs = envU64("QUICPERF_PATH_RTT_US", 0);
  benchmarkPathDownlinkBps = envU64("QUICPERF_PATH_DOWNLINK_BPS", 0);
  benchmarkPathUplinkBps = envU64("QUICPERF_PATH_UPLINK_BPS", 0);
  benchmarkPathMaxRateBps = envU64("QUICPERF_PATH_MAX_RATE_BPS", std::max(benchmarkPathDownlinkBps, benchmarkPathUplinkBps));
  benchmarkPicoquicPacketTrainMode = static_cast<uint32_t>(envFlag("QUICPERF_PICOQUIC_PACKET_TRAIN", false));
  benchmarkPicoquicBdpFrameMode = static_cast<uint32_t>(envFlag("QUICPERF_PICOQUIC_BDP_FRAME", true));
  const bool pathAutoCongestion =
      strcmp(benchmarkCongestionProfile, "path-auto") == 0 ||
      strcmp(benchmarkCongestionProfile, "auto") == 0;
  const bool pathCanSeedBdp =
      pathAutoCongestion &&
      strcmp(benchmarkPathProfile, "loopback") != 0 &&
      benchmarkPathRttUs != 0 &&
      benchmarkPathMaxRateBps != 0;
  benchmarkPicoquicBdpSeedMode = static_cast<uint32_t>(envFlag("QUICPERF_PICOQUIC_BDP_SEED", pathCanSeedBdp));
  benchmarkPicoquicBdpSeedImmediateMode = static_cast<uint32_t>(envFlag("QUICPERF_PICOQUIC_BDP_SEED_IMMEDIATE", pathCanSeedBdp));

  if (strcmp(benchmarkWindowProfile, "large") == 0)
  {
    benchmarkConnectionWindow = benchmarkLargeConnectionWindow;
    benchmarkStreamWindow = benchmarkLargeStreamWindow;
  }
  else if (strcmp(benchmarkWindowProfile, "bdp") == 0 || strcmp(benchmarkWindowProfile, "wan-bdp") == 0)
  {
    applyBenchmarkBdpWindowProfile();
  }
  else
  {
    benchmarkConnectionWindow = benchmarkDefaultConnectionWindow;
    benchmarkStreamWindow = benchmarkDefaultStreamWindow;
    benchmarkWindowProfile = "default";
  }
}

static void configureBenchmarkScenarioProfile(void)
{
  benchmarkScenarioProfile = "default";
  benchmarkLossDropEveryPackets = 0;
  benchmarkLossWarmupPackets = envU64("QUICPERF_LOSS_WARMUP_PACKETS", 128);
  const uint64_t defaultScenarioOperations = benchmarkScenario == BenchmarkScenario::datagram ? 8'388'608 : 1024;
  benchmarkScenarioOperations = envU64("QUICPERF_SCENARIO_OPERATIONS", defaultScenarioOperations);
  const uint64_t defaultStreamsInFlight = benchmarkScenario == BenchmarkScenario::datagram ? 1024 : 8;
  benchmarkScenarioStreamsInFlight = static_cast<uint32_t>(envU64("QUICPERF_STREAMS_IN_FLIGHT", defaultStreamsInFlight));
  benchmarkScenarioRequestBytes = static_cast<uint32_t>(envU64("QUICPERF_REQUEST_BYTES", 64));
  benchmarkScenarioResponseBytes = static_cast<uint32_t>(envU64("QUICPERF_RESPONSE_BYTES", 1024));
  benchmarkScenarioMessageBytes = static_cast<uint32_t>(envU64("QUICPERF_MESSAGE_BYTES", 64));
  benchmarkIdleHoldMs = envU64("QUICPERF_IDLE_HOLD_MS", 1000);

  if (strcmp(benchmarkWindowProfile, "default") == 0 &&
      strcmp(benchmarkPathProfile, "loopback") != 0 &&
      !benchmarkIsFlowControl())
  {
    applyBenchmarkBdpWindowProfile();
  }

  if (benchmarkIsFlowControl())
  {
    benchmarkScenarioProfile = "small_flow_windows";
    if (strcmp(benchmarkWindowProfile, "default") == 0)
    {
      benchmarkConnectionWindow = benchmarkFlowControlConnectionWindow;
      benchmarkStreamWindow = benchmarkFlowControlStreamWindow;
      benchmarkWindowProfile = "flow-control-small";
    }
  }
  else if (benchmarkIsLossRecovery())
  {
    benchmarkScenarioProfile = envString("QUICPERF_LOSS_PROFILE", "deterministic_loss_download");
    benchmarkLossDropEveryPackets = envU64("QUICPERF_LOSS_DROP_EVERY_PACKETS", 5000);
  }
  else if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
  {
    benchmarkScenarioProfile = benchmarkScenario == BenchmarkScenario::close_reset_cleanup
                                   ? envString("QUICPERF_CLOSE_PROFILE", "graceful_fin_cleanup")
                                   : envString("QUICPERF_SCENARIO_PROFILE", "generic_stream");
    benchmarkMaxBidiStreams = std::max<uint64_t>(benchmarkMaxBidiStreams,
                                                 benchmarkGenericStreamsPerConnection() + 16ULL);
  }
  else if (benchmarkScenario == BenchmarkScenario::datagram)
  {
    benchmarkScenarioProfile = envString("QUICPERF_SCENARIO_PROFILE", "datagram_echo");
  }
  else if (benchmarkIsIdleFootprint())
  {
    benchmarkScenarioProfile = envString("QUICPERF_SCENARIO_PROFILE", "idle_established_no_app_data");
  }

  if (benchmarkIsResumptionScenario() && getenv("QUICPERF_SERVER_CONNECTIONS") == nullptr)
  {
    benchmarkServerTargetConnections = std::max<uint32_t>(2, benchmarkServerTargetConnections * 2);
  }
}

static void installNoNewThreadGuard(void)
{
#if defined(__linux__) && defined(__x86_64__)
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#ifdef __NR_clone3
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#endif
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {
      .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
      syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program) != 0)
  {
    fprintf(stderr, "failed to install no-new-thread syscall guard: errno=%d\n", errno);
    abort();
  }
#endif
}

static int currentThreadCount(void)
{
  FILE *status = fopen("/proc/self/status", "r");
  if (status == nullptr)
  {
    return -1;
  }

  char line[256];
  while (fgets(line, sizeof(line), status) != nullptr)
  {
    if (strncmp(line, "Threads:", 8) != 0)
    {
      continue;
    }

    char *value = line + 8;
    while (*value == '\t' || *value == ' ')
    {
      ++value;
    }
    int threads = atoi(value);
    fclose(status);
    return threads;
  }

  fclose(status);
  return -1;
}

struct ThreadStats {
  int countedThreads = 0;
  int totalThreads = 0;
  int kernelIowqThreads = 0;
};

static ThreadStats currentThreadStats(void)
{
  ThreadStats stats = {};
  DIR *tasks = opendir("/proc/self/task");
  if (tasks == nullptr)
  {
    stats.countedThreads = currentThreadCount();
    stats.totalThreads = stats.countedThreads;
    return stats;
  }

  struct dirent *entry;
  while ((entry = readdir(tasks)) != nullptr)
  {
    if (entry->d_name[0] == '.')
    {
      continue;
    }

    ++stats.totalThreads;
    char path[256];
    snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
    FILE *comm = fopen(path, "r");
    if (comm == nullptr)
    {
      ++stats.countedThreads;
      continue;
    }

    char name[128] = {};
    bool kernelIowq = false;
    if (fgets(name, sizeof(name), comm) != nullptr)
    {
      name[strcspn(name, "\n")] = '\0';
      kernelIowq = strncmp(name, "iou-wrk-", 8) == 0;
    }
    fclose(comm);

    if (kernelIowq)
    {
      ++stats.kernelIowqThreads;
    }
    else
    {
      ++stats.countedThreads;
    }
  }
  closedir(tasks);
  return stats;
}

static void verifyThreadCount(const char *role, const char *phase, int expectedThreads)
{
  ThreadStats stats = {};
  for (int attempt = 0; attempt < 50; ++attempt)
  {
    stats = currentThreadStats();
    if (stats.countedThreads == expectedThreads)
    {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  if (stats.countedThreads != expectedThreads)
  {
    fprintf(stderr, "thread-count check failed: role=%s phase=%s pid=%ld expected_threads=%d threads=%d total_threads=%d kernel_iowq_threads=%d\n",
            role, phase, static_cast<long>(getpid()), expectedThreads, stats.countedThreads, stats.totalThreads, stats.kernelIowqThreads);
    DIR *tasks = opendir("/proc/self/task");
    if (tasks != nullptr)
    {
      struct dirent *entry;
      while ((entry = readdir(tasks)) != nullptr)
      {
        if (entry->d_name[0] == '.')
        {
          continue;
        }
        char path[256];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
        FILE *comm = fopen(path, "r");
        if (comm == nullptr)
        {
          continue;
        }
        char name[128] = {};
        if (fgets(name, sizeof(name), comm) != nullptr)
        {
          name[strcspn(name, "\n")] = '\0';
          fprintf(stderr, "thread-count task tid=%s comm=%s\n", entry->d_name, name);
        }
        fclose(comm);
      }
      closedir(tasks);
    }
    abort();
  }

  printf("quicperf_thread_check library=%s role=%s phase=%s pid=%ld expected_threads=%d threads=%d total_threads=%d kernel_iowq_threads=%d status=ok\n",
         benchmarkLibrary(), role, phase, static_cast<long>(getpid()), expectedThreads, stats.countedThreads, stats.totalThreads, stats.kernelIowqThreads);
}

// mode (client or server) networking (iouring or syscall) serverIpAddress (any, loopback, or ipv6)
int main(int argc, char *argv[])
{
  setvbuf(stdout, nullptr, _IOLBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);

  if (argc < 4)
  {
    usage(argv[0]);
    return 2;
  }

  std::string_view role = argv[1];
  std::string_view network = argv[2];
  configureBenchmarkProfiles(network);

  if ((role != "server" && role != "client") ||
      (network != "syscall" && network != "iouring"))
  {
    usage(argv[0]);
    return 2;
  }

#ifdef TCPPERF
  if (network == "iouring")
  {
    fprintf(stderr, "tcpperf: iouring is unsupported; TCP+TLS is wired to the blocking syscall backend in this harness\n");
    return 77;
  }
#endif

  const uint64_t bytesForTest = envU64("QUICPERF_TEST_BYTES", defaultTestBytes);
  BenchmarkScenario selectedScenario = BenchmarkScenario::download;
  if (!parseBenchmarkScenario(envString("QUICPERF_SCENARIO", "download"), selectedScenario))
  {
    usage(argv[0]);
    return 2;
  }
  if (argc >= 5 && !parseBenchmarkScenario(argv[4], selectedScenario))
  {
    usage(argv[0]);
    return 2;
  }
  benchmarkScenario = selectedScenario;
  configureBenchmarkScenarioProfile();
  if (!benchmarkScenarioSupportedByAdapter(benchmarkScenario))
  {
    printf("quicperf_run_result library=%s scenario=%s status=unsupported reason=%s\n",
           benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkScenarioUnsupportedReason(benchmarkScenario));
    return 77;
  }
  const int extraArgc = argc > 5 ? argc - 5 : 0;
  char **extraArgv = argc > 5 ? argv + 5 : argv + argc;
  const uint16_t serverPort = envPort("QUICPERF_SERVER_PORT", 4433);

  const char *localAddressText = envString("QUICPERF_LOCAL_ADDRESS", argv[3]);
  const char *remoteAddressText = envString("QUICPERF_REMOTE_ADDRESS", argv[3]);
  if (!parseBenchmarkAddress(localAddressText, localAddress))
  {
    fprintf(stderr, "invalid local IPv6 address: %s\n", localAddressText);
    return 2;
  }
  if (!parseBenchmarkAddress(remoteAddressText, serverAddress))
  {
    fprintf(stderr, "invalid remote IPv6 address: %s\n", remoteAddressText);
    return 2;
  }

  if (role == "server")
  {
    tls_cert = envString("QUICPERF_TLS_CERT", "tls/bench.cert.pem");
    tls_key = envString("QUICPERF_TLS_KEY", "tls/bench.key.pem");
    tls_chain = envString("QUICPERF_TLS_CHAIN", "tls/bench.chain.pem");

    installNoNewThreadGuard();
    verifyThreadCount(argv[1], "entry", 1);

    globalSetup<Mode::server>();
    benchmarkResetDatagramClientCounters();
    benchmarkResetUdpCounters();

    auto runServerTest = [&]<Mode mode>(QuicLibrary<mode> *server) -> void {
      server->instanceSetup(serverPort, extraArgc, extraArgv);
      if (benchmarkIsResumedConnect() && !server->supportsSessionResumption())
      {
        printf("quicperf_run_result library=%s scenario=%s status=unsupported reason=%s\n",
               benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkScenarioUnsupportedReason(benchmarkScenario));
        delete server;
        std::exit(77);
      }
      if (benchmarkIsZeroRttReqResp() && !server->supportsZeroRtt())
      {
        printf("quicperf_run_result library=%s scenario=%s status=unsupported reason=%s\n",
               benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkScenarioUnsupportedReason(benchmarkScenario));
        delete server;
        std::exit(77);
      }
      printf("quicperf_server_ready library=%s scenario=%s role=server network=%s address=%s local_address=%s remote_address=%s path_profile=%s port=%u\n",
             benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario),
             benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, benchmarkPathProfile, static_cast<unsigned>(serverPort));
      server->startPerfTest();
      delete server;
      verifyThreadCount(argv[1], "complete", 1);

      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        const uint64_t udpPacketsSent = benchmarkUdpPacketsSentTotal.load(std::memory_order_relaxed);
        const uint64_t udpPacketsReceived = benchmarkUdpPacketsReceivedTotal.load(std::memory_order_relaxed);
        const uint64_t udpSendSyscalls = benchmarkUdpSendSyscallsTotal.load(std::memory_order_relaxed);
        const uint64_t udpRecvPolls = benchmarkUdpRecvPollsTotal.load(std::memory_order_relaxed);
        printf("quicperf_result library=%s scenario=%s role=server network=%s address=%s local_address=%s remote_address=%s "
               "build_profile=%s window_profile=%s congestion_profile=%s network_profile=%s path_profile=%s "
               "app_chunk=%u server_connections=%u tls_verify_mode=%s tls_cert_profile=%s "
               "adapter_features=%s initial_cwnd_packets=%u ack_frequency_packets=%u "
               "socket_sndbuf_requested=%" PRIu64 " socket_sndbuf_effective=%d "
               "socket_rcvbuf_requested=%" PRIu64 " socket_rcvbuf_effective=%d "
               "scenario_profile=%s loss_drop_every_packets=%" PRIu64 " loss_warmup_packets=%" PRIu64 " "
               "udp_packets_sent=%" PRIu64 " udp_packets_received=%" PRIu64 " "
               "udp_send_syscalls=%" PRIu64 " udp_recv_polls=%" PRIu64 " status=complete\n",
               benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText,
               benchmarkBuildProfile, benchmarkWindowProfile, benchmarkCongestionProfile, benchmarkNetworkProfile, benchmarkPathProfile,
               benchmarkAppChunkSize, benchmarkServerTargetConnections, benchmarkTlsVerifyMode, benchmarkTlsCertProfile,
               benchmarkAdapterFeatures(), benchmarkAdapterInitialCwndPackets(), benchmarkAdapterAckFrequencyPackets(),
               benchmarkConnectionWindow, benchmarkSocketSndbufEffective.load(std::memory_order_relaxed),
               benchmarkConnectionWindow, benchmarkSocketRcvbufEffective.load(std::memory_order_relaxed),
               benchmarkScenarioProfile, benchmarkLossDropEveryPackets, benchmarkLossWarmupPackets,
               udpPacketsSent, udpPacketsReceived, udpSendSyscalls, udpRecvPolls);
        return;
      }

      printf("quicperf_result library=%s scenario=%s role=server network=%s address=%s local_address=%s remote_address=%s "
             "build_profile=%s window_profile=%s congestion_profile=%s network_profile=%s path_profile=%s "
             "app_chunk=%u server_connections=%u tls_verify_mode=%s tls_cert_profile=%s "
             "adapter_features=%s initial_cwnd_packets=%u ack_frequency_packets=%u "
             "socket_sndbuf_requested=%" PRIu64 " socket_sndbuf_effective=%d "
             "socket_rcvbuf_requested=%" PRIu64 " socket_rcvbuf_effective=%d "
             "scenario_profile=%s loss_drop_every_packets=%" PRIu64 " loss_warmup_packets=%" PRIu64 " "
             "status=complete\n",
             benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText,
             benchmarkBuildProfile, benchmarkWindowProfile, benchmarkCongestionProfile, benchmarkNetworkProfile, benchmarkPathProfile,
             benchmarkAppChunkSize, benchmarkServerTargetConnections, benchmarkTlsVerifyMode, benchmarkTlsCertProfile,
             benchmarkAdapterFeatures(), benchmarkAdapterInitialCwndPackets(), benchmarkAdapterAckFrequencyPackets(),
             benchmarkConnectionWindow, benchmarkSocketSndbufEffective.load(std::memory_order_relaxed),
             benchmarkConnectionWindow, benchmarkSocketRcvbufEffective.load(std::memory_order_relaxed),
             benchmarkScenarioProfile, benchmarkLossDropEveryPackets, benchmarkLossWarmupPackets);
    };

    if (network == "iouring")
    {
      runServerTest(libraryForChoice<Mode::server | Mode::iouring>());
    }
    else
    {
      runServerTest(libraryForChoice<Mode::server | Mode::syscall>());
    }
  }
  else
  {
    tls_cert = envString("QUICPERF_TLS_CERT", "tls/bench.cert.pem");
    tls_key = envString("QUICPERF_TLS_KEY", "tls/bench.key.pem");
    tls_chain = envString("QUICPERF_TLS_CHAIN", "tls/bench.chain.pem");

    const uint16_t nThreads = static_cast<uint16_t>(envU64("QUICPERF_CLIENT_THREADS", 1));
    const uint16_t clientBasePort = envPort("QUICPERF_CLIENT_BASE_PORT", 1111);
    if (nThreads == 0)
    {
      fprintf(stderr, "QUICPERF_CLIENT_THREADS must be at least 1\n");
      return 2;
    }

    struct sockaddr_in6 *server_in6 = (struct sockaddr_in6 *)calloc(1, sizeof(struct sockaddr_in6));
    server_in6->sin6_family = AF_INET6;
    server_in6->sin6_flowinfo = 0;
    server_in6->sin6_port = htons(serverPort);
    server_in6->sin6_addr = serverAddress;

    std::vector<std::jthread> threads;
    std::vector<double> seconds(nThreads, 0.0);
    std::vector<std::string> resumptionProofLabels(nThreads);
    std::atomic<uint16_t> guardWaiters = 0;
    std::atomic<bool> guardInstalled = false;
    std::atomic<uint16_t> clientsReady = 0;
    std::atomic<bool> harnessReadyVerified = false;

    auto runClientTest = [&]<Mode mode>(QuicLibrary<mode> *client, uint16_t threadIndex) -> void {
      client->instanceSetup(clientBasePort + threadIndex, extraArgc, extraArgv);
      if (benchmarkIsResumedConnect() && !client->supportsSessionResumption())
      {
        printf("quicperf_run_result library=%s scenario=%s status=unsupported reason=%s\n",
               benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkScenarioUnsupportedReason(benchmarkScenario));
        delete client;
        std::exit(77);
      }
      if (benchmarkIsZeroRttReqResp() && !client->supportsZeroRtt())
      {
        printf("quicperf_run_result library=%s scenario=%s status=unsupported reason=%s\n",
               benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkScenarioUnsupportedReason(benchmarkScenario));
        delete client;
        std::exit(77);
      }

      if (benchmarkIsResumptionScenario())
      {
        BenchmarkResumptionState state;
        client->connectToServer((struct sockaddr *)server_in6);
        if (!benchmarkScenarioOpensOwnStreams(benchmarkScenario))
        {
          client->openStream();
        }
        client->startPerfTest(benchmarkConnectCleanupBytes);
        client->postPerfTest();
        if (!client->exportResumptionState(state))
        {
          fprintf(stderr, "%s: failed to export resumption state after warmup\n", benchmarkLibrary());
          abort();
        }
        delete client;

        client = libraryForChoice<mode>();
        const uint32_t measuredClientPort =
            static_cast<uint32_t>(clientBasePort) + nThreads + threadIndex;
        if (measuredClientPort > 65'535)
        {
          fprintf(stderr, "resumption measured client port exceeds 65535: base=%u threads=%u thread=%u\n",
                  clientBasePort, nThreads, threadIndex);
          abort();
        }
        client->instanceSetup(static_cast<uint16_t>(measuredClientPort), extraArgc, extraArgv);
        if (!client->importResumptionState(state, benchmarkIsZeroRttReqResp()))
        {
          fprintf(stderr, "%s: failed to import resumption state before measured connection\n", benchmarkLibrary());
          abort();
        }

        clientsReady.fetch_add(1, std::memory_order_acq_rel);
        while (clientsReady.load(std::memory_order_acquire) != nThreads)
        {
          std::this_thread::yield();
        }
        if (threadIndex == 0)
        {
          verifyThreadCount(argv[1], "harness_ready", nThreads);
          harnessReadyVerified.store(true, std::memory_order_release);
        }
        else
        {
          while (!harnessReadyVerified.load(std::memory_order_acquire))
          {
            std::this_thread::yield();
          }
        }

        auto start = std::chrono::steady_clock::now();
        if (benchmarkIsZeroRttReqResp())
        {
          client->connectToServerForZeroRtt((struct sockaddr *)server_in6);
          client->startPerfTest(bytesForTest);
        }
        else
        {
          client->connectToServer((struct sockaddr *)server_in6);
          client->openStream();
        }
        auto end = std::chrono::steady_clock::now();
        double time = std::chrono::duration<double>(end - start).count();

        const bool resumed = client->connectionWasResumed();
        const bool zeroAttempted = client->zeroRttWasAttempted();
        const bool zeroAccepted = client->zeroRttWasAccepted();
        const bool zeroRejected = client->zeroRttWasRejected();
        resumptionProofLabels[threadIndex] = client->resumptionProofLabel();
        if (!resumed)
        {
          fprintf(stderr, "%s: measured connection did not prove resumption\n", benchmarkLibrary());
          abort();
        }
        if (benchmarkIsZeroRttReqResp() && !zeroAttempted)
        {
          fprintf(stderr, "%s: measured connection did not attempt 0-RTT\n", benchmarkLibrary());
          abort();
        }

        if (benchmarkIsResumedConnect())
        {
          const double connectionsPerSecond = 1.0 / time;
          client->startPerfTest(benchmarkConnectCleanupBytes);
          client->postPerfTest();
          printf("quicperf_thread library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s path_profile=%s thread=%u connections=1 seconds=%.9f resumption_attempted=1 resumption_confirmed=%u zero_rtt_attempted=0 zero_rtt_accepted=0 zero_rtt_rejected=0 resumption_proof=%s connections_per_second=%.6f\n",
                 benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, benchmarkPathProfile, threadIndex,
                 time, resumed ? 1 : 0, resumptionProofLabels[threadIndex].c_str(), connectionsPerSecond);
        }
        else
        {
          client->postPerfTest();
          const uint64_t unitsForTest = benchmarkScenarioUnitsPerThread(bytesForTest);
          const double requestsPerSecond = ((double)unitsForTest) / time;
          printf("quicperf_thread library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s path_profile=%s thread=%u units=%" PRIu64 " seconds=%.9f resumption_attempted=1 resumption_confirmed=%u zero_rtt_attempted=%u zero_rtt_accepted=%u zero_rtt_rejected=%u resumption_proof=%s requests_per_second=%.6f\n",
                 benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, benchmarkPathProfile, threadIndex,
                 unitsForTest, time, resumed ? 1 : 0, zeroAttempted ? 1 : 0, zeroAccepted ? 1 : 0, zeroRejected ? 1 : 0,
                 resumptionProofLabels[threadIndex].c_str(), requestsPerSecond);
        }
        benchmarkRecordResumptionResult(resumed, zeroAttempted, zeroAccepted, zeroRejected);
        delete client;
        seconds[threadIndex] = time;
        return;
      }

      if (benchmarkIsConnect())
      {
        clientsReady.fetch_add(1, std::memory_order_acq_rel);
        while (clientsReady.load(std::memory_order_acquire) != nThreads)
        {
          std::this_thread::yield();
        }
        if (threadIndex == 0)
        {
          verifyThreadCount(argv[1], "harness_ready", nThreads);
          harnessReadyVerified.store(true, std::memory_order_release);
        }
        else
        {
          while (!harnessReadyVerified.load(std::memory_order_acquire))
          {
            std::this_thread::yield();
          }
        }

        auto start = std::chrono::steady_clock::now();

        client->connectToServer((struct sockaddr *)server_in6);
        client->openStream();

        auto end = std::chrono::steady_clock::now();
        double time = std::chrono::duration<double>(end - start).count();
        const double connectionsPerSecond = 1.0 / time;

        client->startPerfTest(benchmarkConnectCleanupBytes);
        client->postPerfTest();
        delete client;

        printf("quicperf_thread library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s path_profile=%s thread=%u connections=1 seconds=%.9f connections_per_second=%.6f\n",
               benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, benchmarkPathProfile, threadIndex, time, connectionsPerSecond);

        seconds[threadIndex] = time;
        return;
      }

      if (benchmarkIsIdleFootprint())
      {
        client->connectToServer((struct sockaddr *)server_in6);
        client->openStream();
        clientsReady.fetch_add(1, std::memory_order_acq_rel);
        while (clientsReady.load(std::memory_order_acquire) != nThreads)
        {
          std::this_thread::yield();
        }
        if (threadIndex == 0)
        {
          verifyThreadCount(argv[1], "harness_ready", nThreads);
          harnessReadyVerified.store(true, std::memory_order_release);
        }
        else
        {
          while (!harnessReadyVerified.load(std::memory_order_acquire))
          {
            std::this_thread::yield();
          }
        }

        auto start = std::chrono::steady_clock::now();
        client->idleHold(benchmarkIdleHoldMs);
        auto end = std::chrono::steady_clock::now();
        double time = std::chrono::duration<double>(end - start).count();

        client->startPerfTest(benchmarkConnectCleanupBytes);
        client->postPerfTest();
        delete client;

        printf("quicperf_thread library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s path_profile=%s thread=%u units=1 seconds=%.9f idle_hold_seconds=%.9f idle_connections=1\n",
               benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, benchmarkPathProfile, threadIndex, time, time);

        seconds[threadIndex] = time;
        return;
      }

      client->connectToServer((struct sockaddr *)server_in6);
      if (!benchmarkScenarioOpensOwnStreams(benchmarkScenario))
      {
        client->openStream();
      }
      clientsReady.fetch_add(1, std::memory_order_acq_rel);
      while (clientsReady.load(std::memory_order_acquire) != nThreads)
      {
        std::this_thread::yield();
      }
      if (threadIndex == 0)
      {
        verifyThreadCount(argv[1], "harness_ready", nThreads);
        harnessReadyVerified.store(true, std::memory_order_release);
      }
      else
      {
        while (!harnessReadyVerified.load(std::memory_order_acquire))
        {
          std::this_thread::yield();
        }
      }

      auto start = std::chrono::steady_clock::now();
      client->startPerfTest(bytesForTest);
      auto end = std::chrono::steady_clock::now();
      client->postPerfTest();
      double time = std::chrono::duration<double>(end - start).count();
      const uint64_t unitsForTest = benchmarkScenarioUnitsPerThread(bytesForTest);
      const bool reportsThroughput = strcmp(benchmarkScenarioMetricName(benchmarkScenario), "throughput_gbps") == 0;
      const double metricValue = reportsThroughput
                                     ? ((double)unitsForTest * 8.0) / time / 1'000'000'000.0
                                     : ((double)unitsForTest) / time;
      delete client;

      printf("quicperf_thread library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s path_profile=%s thread=%u units=%" PRIu64 " seconds=%.9f %s=%.6f\n",
             benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, benchmarkPathProfile, threadIndex,
             unitsForTest, time, benchmarkScenarioMetricName(benchmarkScenario), metricValue);
      seconds[threadIndex] = time;
    };

    auto waitForGuard = [&] {
      guardWaiters.fetch_add(1, std::memory_order_acq_rel);
      while (!guardInstalled.load(std::memory_order_acquire))
      {
        std::this_thread::yield();
      }
    };

    for (uint16_t threadIndex = 1; threadIndex < nThreads; ++threadIndex)
    {
      threads.emplace_back([&, threadIndex](std::stop_token st) {
        waitForGuard();
        if (network == "iouring")
        {
          runClientTest(libraryForChoice<Mode::client | Mode::iouring>(), threadIndex);
        }
        else
        {
          runClientTest(libraryForChoice<Mode::client | Mode::syscall>(), threadIndex);
        }
      });
    }

    while (guardWaiters.load(std::memory_order_acquire) != static_cast<uint16_t>(nThreads - 1))
    {
      std::this_thread::yield();
    }
    installNoNewThreadGuard();
    globalSetup<Mode::client>();
    benchmarkResetDatagramClientCounters();
    benchmarkResetUdpCounters();
    benchmarkResetResumptionCounters();
    verifyThreadCount(argv[1], "guard_installed", nThreads);
    guardInstalled.store(true, std::memory_order_release);

    if (network == "iouring")
    {
      runClientTest(libraryForChoice<Mode::client | Mode::iouring>(), 0);
    }
    else
    {
      runClientTest(libraryForChoice<Mode::client | Mode::syscall>(), 0);
    }

    for (auto& thread : threads)
    {
      thread.join();
    }

    double maxSeconds = 0;
    for (uint16_t threadIndex = 0; threadIndex < nThreads; ++threadIndex)
    {
      maxSeconds = std::max(maxSeconds, seconds[threadIndex]);
    }
    verifyThreadCount(argv[1], "complete", 1);

    if (benchmarkIsConnect())
    {
      const double connectionsPerSecond = ((double)nThreads) / maxSeconds;
      printf("quicperf_result library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s threads=%u "
             "build_profile=%s window_profile=%s congestion_profile=%s network_profile=%s path_profile=%s "
             "app_chunk=%u server_connections=%u tls_verify_mode=%s tls_cert_profile=%s "
             "adapter_features=%s initial_cwnd_packets=%u ack_frequency_packets=%u "
             "socket_sndbuf_requested=%" PRIu64 " socket_sndbuf_effective=%d "
             "socket_rcvbuf_requested=%" PRIu64 " socket_rcvbuf_effective=%d "
             "scenario_profile=%s loss_drop_every_packets=%" PRIu64 " loss_warmup_packets=%" PRIu64 " "
             "connections=%u wall_seconds=%.9f connections_per_second=%.6f\n",
             benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, nThreads,
             benchmarkBuildProfile, benchmarkWindowProfile, benchmarkCongestionProfile, benchmarkNetworkProfile, benchmarkPathProfile,
             benchmarkAppChunkSize, benchmarkServerTargetConnections, benchmarkTlsVerifyMode, benchmarkTlsCertProfile,
             benchmarkAdapterFeatures(), benchmarkAdapterInitialCwndPackets(), benchmarkAdapterAckFrequencyPackets(),
             benchmarkConnectionWindow, benchmarkSocketSndbufEffective.load(std::memory_order_relaxed),
             benchmarkConnectionWindow, benchmarkSocketRcvbufEffective.load(std::memory_order_relaxed),
             benchmarkScenarioProfile, benchmarkLossDropEveryPackets, benchmarkLossWarmupPackets,
             nThreads, maxSeconds, connectionsPerSecond);
      return 0;
    }

    if (benchmarkIsIdleFootprint())
    {
      const uint64_t idleConnections = nThreads;
      printf("quicperf_result library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s threads=%u "
             "build_profile=%s window_profile=%s congestion_profile=%s network_profile=%s path_profile=%s "
             "app_chunk=%u server_connections=%u tls_verify_mode=%s tls_cert_profile=%s "
             "adapter_features=%s initial_cwnd_packets=%u ack_frequency_packets=%u "
             "socket_sndbuf_requested=%" PRIu64 " socket_sndbuf_effective=%d "
             "socket_rcvbuf_requested=%" PRIu64 " socket_rcvbuf_effective=%d "
             "scenario_profile=%s loss_drop_every_packets=%" PRIu64 " loss_warmup_packets=%" PRIu64 " "
             "units_per_thread=1 total_units=%" PRIu64 " wall_seconds=%.9f idle_hold_seconds=%.9f idle_connections=%" PRIu64 "\n",
             benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, nThreads,
             benchmarkBuildProfile, benchmarkWindowProfile, benchmarkCongestionProfile, benchmarkNetworkProfile, benchmarkPathProfile,
             benchmarkAppChunkSize, benchmarkServerTargetConnections, benchmarkTlsVerifyMode, benchmarkTlsCertProfile,
             benchmarkAdapterFeatures(), benchmarkAdapterInitialCwndPackets(), benchmarkAdapterAckFrequencyPackets(),
             benchmarkConnectionWindow, benchmarkSocketSndbufEffective.load(std::memory_order_relaxed),
             benchmarkConnectionWindow, benchmarkSocketRcvbufEffective.load(std::memory_order_relaxed),
             benchmarkScenarioProfile, benchmarkLossDropEveryPackets, benchmarkLossWarmupPackets,
             idleConnections, maxSeconds, maxSeconds, idleConnections);
      return 0;
    }

    const uint64_t unitsPerThread = benchmarkScenarioUnitsPerThread(bytesForTest);
    const uint64_t totalUnits = unitsPerThread * nThreads;
    const bool reportsThroughput = strcmp(benchmarkScenarioMetricName(benchmarkScenario), "throughput_gbps") == 0;
    const double metricValue = reportsThroughput
                                   ? ((double)totalUnits * 8.0) / maxSeconds / 1'000'000'000.0
                                   : ((double)totalUnits) / maxSeconds;

    if (benchmarkIsResumptionScenario())
    {
      const uint64_t resumptionAttempted = benchmarkResumptionAttemptedTotal.load(std::memory_order_relaxed);
      const uint64_t resumptionConfirmed = benchmarkResumptionConfirmedTotal.load(std::memory_order_relaxed);
      const uint64_t zeroRttAttempted = benchmarkZeroRttAttemptedTotal.load(std::memory_order_relaxed);
      const uint64_t zeroRttAccepted = benchmarkZeroRttAcceptedTotal.load(std::memory_order_relaxed);
      const uint64_t zeroRttRejected = benchmarkZeroRttRejectedTotal.load(std::memory_order_relaxed);
      const char *proofLabel = resumptionProofLabels.empty() || resumptionProofLabels[0].empty()
                                   ? "adapter_api"
                                   : resumptionProofLabels[0].c_str();
      printf("quicperf_result library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s threads=%u "
             "build_profile=%s window_profile=%s congestion_profile=%s network_profile=%s path_profile=%s "
             "app_chunk=%u server_connections=%u tls_verify_mode=%s tls_cert_profile=%s "
             "adapter_features=%s initial_cwnd_packets=%u ack_frequency_packets=%u "
             "socket_sndbuf_requested=%" PRIu64 " socket_sndbuf_effective=%d "
             "socket_rcvbuf_requested=%" PRIu64 " socket_rcvbuf_effective=%d "
             "scenario_profile=%s loss_drop_every_packets=%" PRIu64 " loss_warmup_packets=%" PRIu64 " "
             "resumption_attempted=%" PRIu64 " resumption_confirmed=%" PRIu64 " "
             "zero_rtt_attempted=%" PRIu64 " zero_rtt_accepted=%" PRIu64 " zero_rtt_rejected=%" PRIu64 " "
             "resumption_proof=%s units_per_thread=%" PRIu64 " total_units=%" PRIu64 " wall_seconds=%.9f %s=%.6f\n",
             benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, nThreads,
             benchmarkBuildProfile, benchmarkWindowProfile, benchmarkCongestionProfile, benchmarkNetworkProfile, benchmarkPathProfile,
             benchmarkAppChunkSize, benchmarkServerTargetConnections, benchmarkTlsVerifyMode, benchmarkTlsCertProfile,
             benchmarkAdapterFeatures(), benchmarkAdapterInitialCwndPackets(), benchmarkAdapterAckFrequencyPackets(),
             benchmarkConnectionWindow, benchmarkSocketSndbufEffective.load(std::memory_order_relaxed),
             benchmarkConnectionWindow, benchmarkSocketRcvbufEffective.load(std::memory_order_relaxed),
             benchmarkScenarioProfile, benchmarkLossDropEveryPackets, benchmarkLossWarmupPackets,
             resumptionAttempted, resumptionConfirmed, zeroRttAttempted, zeroRttAccepted, zeroRttRejected,
             proofLabel, unitsPerThread, totalUnits, maxSeconds, benchmarkScenarioMetricName(benchmarkScenario), metricValue);
      return 0;
    }

    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      const uint64_t datagramSent = benchmarkDatagramClientSentTotal.load(std::memory_order_relaxed);
      const uint64_t datagramReceived = benchmarkDatagramClientReceivedTotal.load(std::memory_order_relaxed);
      const uint64_t datagramLost = datagramSent > datagramReceived ? datagramSent - datagramReceived : 0;
      const double datagramDeliveryRatio = datagramSent == 0 ? 0.0 : (double)datagramReceived / (double)datagramSent;
      const uint64_t udpPacketsSent = benchmarkUdpPacketsSentTotal.load(std::memory_order_relaxed);
      const uint64_t udpPacketsReceived = benchmarkUdpPacketsReceivedTotal.load(std::memory_order_relaxed);
      const uint64_t udpSendSyscalls = benchmarkUdpSendSyscallsTotal.load(std::memory_order_relaxed);
      const uint64_t udpRecvPolls = benchmarkUdpRecvPollsTotal.load(std::memory_order_relaxed);
      const double datagramsPerUdpPacket = udpPacketsReceived == 0 ? 0.0 : (double)datagramReceived / (double)udpPacketsReceived;
      printf("quicperf_result library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s threads=%u "
             "build_profile=%s window_profile=%s congestion_profile=%s network_profile=%s path_profile=%s "
             "app_chunk=%u server_connections=%u tls_verify_mode=%s tls_cert_profile=%s "
             "adapter_features=%s initial_cwnd_packets=%u ack_frequency_packets=%u "
             "socket_sndbuf_requested=%" PRIu64 " socket_sndbuf_effective=%d "
             "socket_rcvbuf_requested=%" PRIu64 " socket_rcvbuf_effective=%d "
             "scenario_profile=%s loss_drop_every_packets=%" PRIu64 " loss_warmup_packets=%" PRIu64 " "
             "units_per_thread=%" PRIu64 " total_units=%" PRIu64 " wall_seconds=%.9f "
             "datagram_sent=%" PRIu64 " datagram_received=%" PRIu64 " datagram_lost=%" PRIu64 " "
             "datagram_delivery_ratio=%.9f udp_packets_sent=%" PRIu64 " udp_packets_received=%" PRIu64 " "
             "udp_send_syscalls=%" PRIu64 " udp_recv_polls=%" PRIu64 " datagrams_per_udp_packet=%.9f %s=%.6f\n",
             benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, nThreads,
             benchmarkBuildProfile, benchmarkWindowProfile, benchmarkCongestionProfile, benchmarkNetworkProfile, benchmarkPathProfile,
             benchmarkAppChunkSize, benchmarkServerTargetConnections, benchmarkTlsVerifyMode, benchmarkTlsCertProfile,
             benchmarkAdapterFeatures(), benchmarkAdapterInitialCwndPackets(), benchmarkAdapterAckFrequencyPackets(),
             benchmarkConnectionWindow, benchmarkSocketSndbufEffective.load(std::memory_order_relaxed),
             benchmarkConnectionWindow, benchmarkSocketRcvbufEffective.load(std::memory_order_relaxed),
             benchmarkScenarioProfile, benchmarkLossDropEveryPackets, benchmarkLossWarmupPackets,
             unitsPerThread, totalUnits, maxSeconds, datagramSent, datagramReceived, datagramLost,
             datagramDeliveryRatio, udpPacketsSent, udpPacketsReceived, udpSendSyscalls, udpRecvPolls,
             datagramsPerUdpPacket, benchmarkScenarioMetricName(benchmarkScenario), metricValue);
      return 0;
    }

    printf("quicperf_result library=%s scenario=%s role=client network=%s address=%s local_address=%s remote_address=%s threads=%u "
           "build_profile=%s window_profile=%s congestion_profile=%s network_profile=%s path_profile=%s "
           "app_chunk=%u server_connections=%u tls_verify_mode=%s tls_cert_profile=%s "
           "adapter_features=%s initial_cwnd_packets=%u ack_frequency_packets=%u "
           "socket_sndbuf_requested=%" PRIu64 " socket_sndbuf_effective=%d "
           "socket_rcvbuf_requested=%" PRIu64 " socket_rcvbuf_effective=%d "
           "scenario_profile=%s loss_drop_every_packets=%" PRIu64 " loss_warmup_packets=%" PRIu64 " "
           "units_per_thread=%" PRIu64 " total_units=%" PRIu64 " wall_seconds=%.9f %s=%.6f\n",
           benchmarkLibrary(), benchmarkScenarioName(benchmarkScenario), benchmarkNetworkLabel(network), argv[3], localAddressText, remoteAddressText, nThreads,
           benchmarkBuildProfile, benchmarkWindowProfile, benchmarkCongestionProfile, benchmarkNetworkProfile, benchmarkPathProfile,
           benchmarkAppChunkSize, benchmarkServerTargetConnections, benchmarkTlsVerifyMode, benchmarkTlsCertProfile,
           benchmarkAdapterFeatures(), benchmarkAdapterInitialCwndPackets(), benchmarkAdapterAckFrequencyPackets(),
           benchmarkConnectionWindow, benchmarkSocketSndbufEffective.load(std::memory_order_relaxed),
           benchmarkConnectionWindow, benchmarkSocketRcvbufEffective.load(std::memory_order_relaxed),
           benchmarkScenarioProfile, benchmarkLossDropEveryPackets, benchmarkLossWarmupPackets,
           unitsPerThread, totalUnits, maxSeconds, benchmarkScenarioMetricName(benchmarkScenario), metricValue);
  }
}
