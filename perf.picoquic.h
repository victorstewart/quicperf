#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquic_config.h"
#include "picotls.h"

#include <algorithm>
#include <atomic>
#include <array>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <unistd.h>

#pragma once

extern "C" void picoquic_seed_bandwidth(
    picoquic_cnx_t *cnx,
    uint64_t rtt_min,
    uint64_t cwin,
    const uint8_t *ip_addr,
    uint8_t ip_addr_length);

extern "C" void quicperf_picoquic_seed_sender_now(
    picoquic_cnx_t *cnx,
    uint64_t cwin,
    uint64_t pacing_rate,
    uint64_t current_time);

static inline const char *benchmarkPicoquicCongestionAlgorithmName(void)
{
  if (benchmarkCongestionProfileUsesCubic())
  {
    return "cubic";
  }
  if (strcmp(benchmarkCongestionProfile, "path-auto") == 0 ||
      strcmp(benchmarkCongestionProfile, "auto") == 0)
  {
    if (strcmp(benchmarkPathProfile, "dc-fabric-10g") == 0)
    {
      return "cubic";
    }
    return "bbr";
  }
  if (strcmp(benchmarkCongestionProfile, "cubic") == 0)
  {
    return "cubic";
  }
  if (strcmp(benchmarkCongestionProfile, "dcubic") == 0)
  {
    return "dcubic";
  }
  if (strcmp(benchmarkCongestionProfile, "newreno") == 0 ||
      strcmp(benchmarkCongestionProfile, "reno") == 0)
  {
    return "newreno";
  }
  if (strcmp(benchmarkCongestionProfile, "prague") == 0)
  {
    return "prague";
  }
  if (strcmp(benchmarkCongestionProfile, "c4") == 0)
  {
    return "c4";
  }
  return "bbr";
}

static inline const picoquic_congestion_algorithm_t *benchmarkPicoquicCongestionAlgorithm(void)
{
  static std::once_flag registerAlgorithmsOnce;
  std::call_once(registerAlgorithmsOnce, [] {
    picoquic_register_all_congestion_control_algorithms();
  });
  const picoquic_congestion_algorithm_t *algorithm =
      picoquic_get_congestion_algorithm(benchmarkPicoquicCongestionAlgorithmName());
  if (algorithm == nullptr)
  {
    algorithm = picoquic_get_congestion_algorithm("cubic");
  }
  return algorithm;
}

static inline const char *benchmarkPicoquicAdapterFeatures(void)
{
  static thread_local char features[256];
  const bool gsoRequested = benchmarkUdpGsoEnabled();
  const bool nativeGso = benchmarkPicoquicPacketTrainMode && gsoRequested;
  const char *udpGso = "off";
  if (nativeGso)
  {
    udpGso = "native_picoquic";
  }
  else if (gsoRequested)
  {
    udpGso = "common_cpp_after_impairment";
  }
  snprintf(features, sizeof(features),
           "cc=%s|pmtud=off|packet_train=%s|bdp_frame=%s|bdp_seed=%s|seed_now=%s|udp_gso=%s|udp_gro=%s|mtu=%u|null_verifier=ed25519_sigalgs",
           benchmarkPicoquicCongestionAlgorithmName(),
           nativeGso ? "on" : "off",
           benchmarkPicoquicBdpFrameMode ? "on" : "off",
           benchmarkPicoquicBdpSeedMode ? "on" : "off",
           benchmarkPicoquicBdpSeedImmediateMode ? "on" : "off",
           udpGso,
           benchmarkUdpGroEnabled() ? "on" : "off",
           static_cast<unsigned>(benchmarkUdpPayloadSize));
  return features;
}

template <Mode mode>
class Picoquic : public QuicLibrary<mode> {
private:

  using QuicLibrary<mode>::networkHub;

  picoquic_quic_t *engine = nullptr;
  picoquic_cnx_t *cnx = nullptr;
  int64_t bytesInFlight = -1;
  bool useUdpGso = false;
  uint16_t localPort = 0;
  static inline std::atomic<uint64_t> nextTicketFileId {1};
  uint64_t ticketFileId = nextTicketFileId.fetch_add(1, std::memory_order_relaxed);
  std::string ticketFile;
  bool importedResumption = false;
  bool importedZeroRtt = false;
  bool resumedObserved = false;
  bool zeroRttAttemptedObserved = false;
  bool zeroRttAcceptedObserved = false;
  std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
  size_t requestBytesRead = 0;
  size_t requestBytesWritten = 0;
  bool requestParsed = false;
  bool ready = false;
  bool clientDone = false;
  bool downloadDoneSignalSent = false;
  bool downloadCompletionAckRead = false;
  bool uploadFinSent = false;
  uint32_t serverCompletedConnections = 0;
  bool stallTrace = false;
  uint64_t nextStallTraceUs = 0;
  bool durationTransferMode = false;
  bool durationTransferRunning = false;
  uint64_t durationTransferDeadlineUs = 0;
  uint64_t durationCompletedUnits = 0;
  double durationMeasuredSeconds = 0.0;
  bool genericDurationMode = false;
  bool genericDurationOpening = false;
  bool genericDurationDoneSent = false;

  enum class GenericPhase : uint8_t {
    sendRequest,
    readRequest,
    sendPayload,
    readPayload,
    sendResponse,
    readDone,
    sendDone,
    sendAck,
    readAck,
    complete
  };

  struct GenericStreamState {
    Picoquic<mode> *owner = nullptr;
    picoquic_cnx_t *cnx = nullptr;
    uint64_t streamId = 0;
    GenericPhase phase = GenericPhase::sendRequest;
    std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
    uint64_t requestValue = 0;
    uint64_t requestBytesExpected = 0;
    uint64_t requestBytesRead = 0;
    uint64_t requestBytesWritten = 0;
    uint64_t payloadRemaining = 0;
    uint64_t responseRemaining = 0;
    size_t doneBytesRead = 0;
    size_t doneBytesWritten = 0;
    size_t ackBytesRead = 0;
    size_t ackBytesWritten = 0;
    bool durationCounted = false;
    bool controlStream = false;
    bool complete = false;
  };

  static int noVerifyCertificate(
      ptls_verify_certificate_t *self,
      ptls_t *tls,
      const char *serverName,
      int (**verifySign)(void *verifyCtx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign),
      void **verifyData,
      ptls_iovec_t *certs,
      size_t numCerts)
  {
    *verifySign = nullptr;
    *verifyData = nullptr;
    return 0;
  }

  constexpr static uint16_t noVerifySignatureAlgorithms[] = {
      PTLS_SIGNATURE_ED25519,
      PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
      PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
      PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
      PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
      PTLS_SIGNATURE_RSA_PKCS1_SHA256,
      PTLS_SIGNATURE_RSA_PKCS1_SHA1,
      UINT16_MAX,
  };

  static inline ptls_verify_certificate_t noVerifyWithEd25519 = {
      noVerifyCertificate,
      noVerifySignatureAlgorithms,
  };

  constexpr static uint8_t ticketEncryptionKey[16] = {
      0x51,
      0x75,
      0x69,
      0x63,
      0x50,
      0x65,
      0x72,
      0x66,
      0x50,
      0x69,
      0x63,
      0x6f,
      0x54,
      0x69,
      0x6b,
      0x31,
  };

  std::string makeTicketFileName(const char *label) const
  {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/quicperf-picoquic-%s-%ld-%" PRIu64 "-%p.ticket",
             label, static_cast<long>(getpid()), ticketFileId, static_cast<const void *>(this));
    return path;
  }

  static bool readFile(const std::string& path, std::vector<uint8_t>& out)
  {
    FILE *file = fopen(path.c_str(), "rb");
    if (file == nullptr)
    {
      return false;
    }
    if (fseek(file, 0, SEEK_END) != 0)
    {
      fclose(file);
      return false;
    }
    const long size = ftell(file);
    if (size <= 0 || fseek(file, 0, SEEK_SET) != 0)
    {
      fclose(file);
      return false;
    }
    out.resize(static_cast<size_t>(size));
    const size_t read = fread(out.data(), 1, out.size(), file);
    fclose(file);
    if (read != out.size())
    {
      out.clear();
      return false;
    }
    return true;
  }

  static bool writeFile(const std::string& path, const std::vector<uint8_t>& data)
  {
    FILE *file = fopen(path.c_str(), "wb");
    if (file == nullptr)
    {
      return false;
    }
    const size_t written = fwrite(data.data(), 1, data.size(), file);
    fclose(file);
    return written == data.size();
  }

  struct ServerStreamState {
    Picoquic<mode> *owner = nullptr;
    picoquic_cnx_t *cnx = nullptr;
    uint64_t streamId = 0;
    int64_t bytesInFlight = -1;
    std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
    size_t requestBytesRead = 0;
    size_t requestBytesWritten = 0;
    bool requestParsed = false;
    bool clientDone = false;
    bool uploadFinSent = false;
    bool completionAckSent = false;
    uint64_t serverDrainDeadlineUs = 0;
    bool complete = false;
    bool durationMode = false;
  };

  std::vector<std::unique_ptr<ServerStreamState>> serverStreams;
  std::vector<std::unique_ptr<GenericStreamState>> genericStreams;
  std::unordered_map<uint64_t, GenericStreamState *> genericStreamById;
  bool genericStarted = false;
  uint64_t genericClientBytes = 0;
  uint64_t genericRequestedStreams = 0;
  uint64_t genericOpenedStreams = 0;
  uint64_t genericCompletedStreams = 0;
  uint64_t genericServerCompletedStreams = 0;
  uint64_t genericActiveStreams = 0;
  std::unordered_map<picoquic_cnx_t *, bool> genericDurationDoneByConnection;
  std::unordered_map<picoquic_cnx_t *, bool> genericDurationCompleteByConnection;
  std::unordered_map<picoquic_cnx_t *, uint64_t> genericDurationDrainDeadlineByConnection;
  std::unordered_map<picoquic_cnx_t *, uint64_t> genericDurationServerDeadlineByConnection;
  struct DatagramConnState {
    picoquic_cnx_t *cnx = nullptr;
    uint64_t received = 0;
    uint64_t echoed = 0;
    std::deque<uint64_t> pendingEchoes;
    std::vector<uint8_t> seen;
    uint64_t drainDeadlineUs = 0;
    bool clientDone = false;
    bool complete = false;
  };
  std::vector<std::unique_ptr<DatagramConnState>> datagramServerConns;
  uint64_t datagramClientSent = 0;
  uint64_t datagramClientReceived = 0;
  uint64_t datagramClientDrainDeadlineUs = 0;
  bool datagramStarted = false;
  bool datagramDoneSignalSent = false;
  bool datagramDoneStreamWritten = false;
  std::vector<uint8_t> datagramClientSeen;
  std::array<uint8_t, benchmarkAppChunkSize> datagramScratch = {};

  bool perfComplete(void) const
  {
    if constexpr (mode & Mode::server)
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        if (durationModeActive() && supportsSmallGenericDurationMode(benchmarkScenario))
        {
          return serverCompletedConnections >= benchmarkServerTargetConnections;
        }
        return genericServerCompletedStreams >=
               static_cast<uint64_t>(benchmarkServerTargetConnections) * benchmarkGenericStreamsPerConnection();
      }
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        return serverCompletedConnections >= benchmarkServerTargetConnections;
      }
      return serverCompletedConnections >= benchmarkServerTargetConnections;
    }
    else
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        return genericCompletedStreams >= benchmarkGenericStreamsPerConnection();
      }
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        return datagramClientSendBudgetReached() &&
               datagramDoneSignalSent &&
               datagramDoneStreamWritten &&
               datagramClientDrainDeadlineUs != 0 &&
               timeNowUs() >= datagramClientDrainDeadlineUs;
      }
      return benchmarkIsUpload()
                 ? clientDone
             : durationTransferMode
                 ? false
                 : bytesInFlight == 0;
    }
  }

  static bool supportsSimpleDurationMode(BenchmarkScenario scenario)
  {
    switch (scenario)
    {
      case BenchmarkScenario::download:
      case BenchmarkScenario::upload:
      case BenchmarkScenario::loss_recovery:
      case BenchmarkScenario::flow_control:
        return true;
      default:
        return false;
    }
  }

  static bool supportsSmallGenericDurationMode(BenchmarkScenario scenario)
  {
    switch (scenario)
    {
      case BenchmarkScenario::reqresp:
      case BenchmarkScenario::zero_rtt_reqresp:
      case BenchmarkScenario::stream_churn:
      case BenchmarkScenario::small_payload_pps:
      case BenchmarkScenario::close_reset_cleanup:
        return true;
      default:
        return false;
    }
  }

  static bool supportsByteGenericDurationMode(BenchmarkScenario scenario)
  {
    switch (scenario)
    {
      case BenchmarkScenario::multistream_download:
      case BenchmarkScenario::multistream_upload:
      case BenchmarkScenario::bidi:
        return true;
      default:
        return false;
    }
  }

  static bool supportsGenericDurationMode(BenchmarkScenario scenario)
  {
    return supportsSmallGenericDurationMode(scenario) ||
           supportsByteGenericDurationMode(scenario);
  }

  bool durationModeActive(void) const
  {
    return benchmarkDurationModeActive() &&
           benchmarkTargetDurationMs > 0 &&
           (supportsSimpleDurationMode(benchmarkScenario) ||
            supportsGenericDurationMode(benchmarkScenario) ||
            benchmarkScenario == BenchmarkScenario::datagram);
  }

  bool datagramDurationModeActive(void) const
  {
    return benchmarkDurationModeActive() &&
           benchmarkTargetDurationMs > 0 &&
           benchmarkScenario == BenchmarkScenario::datagram;
  }

  bool datagramClientSendBudgetOpen(void) const
  {
    if (!datagramDurationModeActive())
    {
      return datagramClientSent < benchmarkScenarioOperations;
    }
    return durationTransferRunning &&
           durationTransferDeadlineUs != 0 &&
           timeNowUs() < durationTransferDeadlineUs;
  }

  bool datagramClientSendBudgetReached(void) const
  {
    if (!datagramDurationModeActive())
    {
      return datagramClientSent >= benchmarkScenarioOperations;
    }
    return durationTransferDeadlineUs != 0 &&
           timeNowUs() >= durationTransferDeadlineUs;
  }

  constexpr static uint64_t durationTransferRequest(void)
  {
    return UINT64_MAX;
  }

  constexpr static uint8_t genericDurationDoneByte(void)
  {
    return 0xff;
  }

  uint64_t durationDeadlineUs(uint64_t startUs) const
  {
    return startUs + benchmarkTargetDurationMs * 1000ULL;
  }

  void recordDurationResult(uint64_t completedUnits, uint64_t startUs, uint64_t endUs)
  {
    durationCompletedUnits = completedUnits;
    durationMeasuredSeconds = std::max(0.000001, static_cast<double>(endUs - startUs) / 1'000'000.0);
  }

  ServerStreamState *newServerStreamState(picoquic_cnx_t *activeConnection, uint64_t streamId)
  {
    auto state = std::make_unique<ServerStreamState>();
    state->owner = this;
    state->cnx = activeConnection;
    state->streamId = streamId;
    ServerStreamState *raw = state.get();
    serverStreams.push_back(std::move(state));
    picoquic_set_app_stream_ctx(activeConnection, streamId, raw);
    return raw;
  }

  void markServerStateComplete(ServerStreamState *state)
  {
    if (state == nullptr || state->complete)
    {
      return;
    }
    if (state->durationMode)
    {
      if (!state->requestParsed)
      {
        return;
      }
      if (state->serverDrainDeadlineUs == 0)
      {
        state->serverDrainDeadlineUs =
            timeNowUs() + benchmarkTargetDurationMs * 1000ULL + benchmarkDurationCompletionDrainUs;
      }
      if (timeNowUs() < state->serverDrainDeadlineUs)
      {
        return;
      }
      state->complete = true;
      ++serverCompletedConnections;
      return;
    }
    if (benchmarkIsUpload())
    {
      if ((state->durationMode && !state->clientDone) ||
          !state->uploadFinSent || state->serverDrainDeadlineUs == 0 || timeNowUs() < state->serverDrainDeadlineUs)
      {
        return;
      }
    }
    else if (!state->requestParsed || state->bytesInFlight != 0 ||
             !state->clientDone || !state->completionAckSent ||
             state->serverDrainDeadlineUs == 0 || timeNowUs() < state->serverDrainDeadlineUs)
    {
      return;
    }
    state->complete = true;
    ++serverCompletedConnections;
  }

  static uint64_t picoquicBdpSeedCwin(void)
  {
    if (benchmarkPathRttUs == 0 || benchmarkPathMaxRateBps == 0)
    {
      return 0;
    }
    const uint64_t seedRateBps = picoquicBdpSeedRate();
    const uint64_t bdpBytes = ((seedRateBps * benchmarkPathRttUs) + 7'999'999ULL) / 8'000'000ULL;
    return std::clamp<uint64_t>(bdpBytes * 2ULL, 64ULL * 1024ULL, 16ULL * 1024ULL * 1024ULL);
  }

  static uint64_t picoquicBdpSeedRate(void)
  {
    if (strcmp(benchmarkPathProfile, "lte-good") == 0 &&
        benchmarkPathDownlinkBps != 0)
    {
      return benchmarkPathDownlinkBps;
    }
    return benchmarkPathMaxRateBps;
  }

  static uint64_t picoquicBdpSeedPacingRate(void)
  {
    return picoquicBdpSeedRate() / 8ULL;
  }

  static void seedServerBandwidth(picoquic_cnx_t *activeConnection)
  {
    if constexpr (mode & Mode::server)
    {
      if (!benchmarkPicoquicBdpSeedMode ||
          strcmp(benchmarkPathProfile, "loopback") == 0)
      {
        return;
      }
      const uint64_t seedCwin = picoquicBdpSeedCwin();
      if (seedCwin != 0)
      {
        picoquic_seed_bandwidth(activeConnection, benchmarkPathRttUs, seedCwin, serverAddress.s6_addr, 16);
        if (benchmarkPicoquicBdpSeedImmediateMode)
        {
          quicperf_picoquic_seed_sender_now(
              activeConnection, seedCwin, picoquicBdpSeedPacingRate(), timeNowUs());
        }
      }
    }
  }

  static void encodeU64(uint64_t value, std::array<uint8_t, sizeof(uint64_t)>& out)
  {
    uint64_t swapped = bswap_64(value);
    memcpy(out.data(), &swapped, out.size());
  }

  static uint64_t decodeU64(const std::array<uint8_t, sizeof(uint64_t)>& in)
  {
    uint64_t value = 0;
    memcpy(&value, in.data(), in.size());
    return bswap_64(value);
  }

  static bool genericUsesTerminalAck(void)
  {
    return benchmarkScenario == BenchmarkScenario::multistream_download ||
           benchmarkScenario == BenchmarkScenario::bidi;
  }

  uint64_t genericTransferBytesForStream(uint64_t index) const
  {
    const uint64_t count = std::max<uint64_t>(1, benchmarkGenericStreamsPerConnection());
    const uint64_t base = genericClientBytes / count;
    if (index + 1 == count)
    {
      return genericClientBytes - (base * (count - 1));
    }
    return std::max<uint64_t>(1, base);
  }

  uint64_t durationGenericTransferBytesPerStream(void) const
  {
    const uint64_t streamCount =
        benchmarkScenario == BenchmarkScenario::bidi
            ? 1
            : std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    const uint64_t finiteBytesPerStream = std::max<uint64_t>(1, genericClientBytes / streamCount);
    constexpr uint64_t maxDurationStreamBytes = uint64_t {benchmarkAppChunkSize} * 4U;
    return std::max<uint64_t>(
        1,
        std::min<uint64_t>(finiteBytesPerStream, maxDurationStreamBytes));
  }

  void initializeGenericClientState(GenericStreamState& state, uint64_t streamId)
  {
    state.owner = this;
    state.cnx = cnx;
    state.streamId = streamId;
    state.phase = GenericPhase::sendRequest;
    const uint64_t index = genericOpenedStreams++;
    if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
    {
      state.requestBytesExpected = benchmarkGenericReqRespRequestBytes();
      state.responseRemaining = benchmarkGenericReqRespResponseBytes();
    }
    else
    {
      const uint64_t streamBytes =
          genericDurationMode && supportsByteGenericDurationMode(benchmarkScenario)
              ? durationGenericTransferBytesPerStream()
              : genericTransferBytesForStream(index);
      state.requestValue = streamBytes;
      encodeU64(streamBytes, state.requestBytes);
      state.requestBytesExpected = state.requestBytes.size();
      state.payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                                benchmarkScenario == BenchmarkScenario::bidi)
                                   ? streamBytes
                                   : 0;
      state.responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : streamBytes;
    }
  }

  GenericStreamState *newGenericServerStreamState(picoquic_cnx_t *activeConnection, uint64_t streamId)
  {
    auto state = std::make_unique<GenericStreamState>();
    state->owner = this;
    state->cnx = activeConnection;
    state->streamId = streamId;
    state->phase = GenericPhase::readRequest;
    GenericStreamState *raw = state.get();
    genericStreams.push_back(std::move(state));
    picoquic_set_app_stream_ctx(activeConnection, streamId, raw);
    return raw;
  }

  GenericStreamState *genericClientStreamFor(uint64_t streamId)
  {
    auto found = genericStreamById.find(streamId);
    return found == genericStreamById.end() ? nullptr : found->second;
  }

  DatagramConnState *datagramServerStateFor(picoquic_cnx_t *activeConnection)
  {
    for (auto& state : datagramServerConns)
    {
      if (state->cnx == activeConnection)
      {
        return state.get();
      }
    }

    auto state = std::make_unique<DatagramConnState>();
    state->cnx = activeConnection;
    DatagramConnState *raw = state.get();
    datagramServerConns.push_back(std::move(state));
    return raw;
  }

  void markDatagramServerComplete(DatagramConnState *state)
  {
    if (state == nullptr || state->complete)
    {
      return;
    }
    if (!state->clientDone || !state->pendingEchoes.empty())
    {
      return;
    }
    if (state->drainDeadlineUs == 0)
    {
      state->drainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
    }
    if (!state->clientDone)
    {
      return;
    }
    if (timeNowUs() < state->drainDeadlineUs)
    {
      return;
    }
    state->complete = true;
    ++serverCompletedConnections;
  }

  void markDatagramServerCompleteAfterSendPass(void)
  {
    if constexpr (mode & Mode::server)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram)
      {
        return;
      }
      for (auto& owned : datagramServerConns)
      {
        markDatagramServerComplete(owned.get());
      }
    }
  }

  void sendPendingServerDatagrams(void)
  {
    if constexpr (mode & Mode::server)
    {
      const size_t payloadSize = benchmarkDatagramPayloadBytesForNoMssApiLimit(
          sizeof(networkHub->junk),
          benchmarkUdpPayloadSize);
      if (payloadSize == 0)
      {
        return;
      }
      for (auto& owned : datagramServerConns)
      {
        auto *state = owned.get();
        while (!state->pendingEchoes.empty())
        {
          benchmarkFillDatagramPayload(datagramScratch.data(), payloadSize, networkHub->junk, state->pendingEchoes.front());
          int rv = picoquic_queue_datagram_frame(state->cnx, payloadSize, datagramScratch.data());
          if (rv != 0)
          {
            break;
          }
          state->pendingEchoes.pop_front();
          ++state->echoed;
        }
        markDatagramServerComplete(state);
      }
    }
  }

  void sendClientDatagrams(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram ||
          cnx == nullptr ||
          !datagramStarted)
      {
        return;
      }
      if (!datagramClientSendBudgetOpen())
      {
        if (datagramClientSendBudgetReached() && !datagramDoneSignalSent)
        {
          sendClientDatagramDoneSignal();
        }
        return;
      }
      const uint64_t maxInFlight = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
      const size_t payloadSize = benchmarkDatagramPayloadBytesForNoMssApiLimit(
          sizeof(networkHub->junk),
          benchmarkUdpPayloadSize);
      if (payloadSize == 0)
      {
        return;
      }
      uint64_t sentThisCall = 0;
      while (sentThisCall < maxInFlight &&
             datagramClientSendBudgetOpen())
      {
        benchmarkFillDatagramPayload(datagramScratch.data(), payloadSize, networkHub->junk, datagramClientSent);
        int rv = picoquic_queue_datagram_frame(cnx, payloadSize, datagramScratch.data());
        if (rv != 0)
        {
          break;
        }
        ++datagramClientSent;
        ++sentThisCall;
      }
      if (datagramClientSendBudgetReached() && !datagramDoneSignalSent)
      {
        sendClientDatagramDoneSignal();
      }
    }
  }

  void sendClientDatagramDoneSignal(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (datagramDoneSignalSent || cnx == nullptr)
      {
        return;
      }
      static const uint8_t done = 0;
      if (picoquic_add_to_stream_with_ctx(cnx, 0, &done, sizeof(done), true, this) == 0)
      {
        datagramDoneSignalSent = true;
        datagramDoneStreamWritten = true;
        datagramClientDrainDeadlineUs = datagramClientReceived >= datagramClientSent
                                            ? timeNowUs()
                                            : timeNowUs() + benchmarkDatagramDrainUs;
      }
    }
  }

  void markGenericClientComplete(GenericStreamState *state)
  {
    if (state == nullptr || state->complete)
    {
      return;
    }
    state->complete = true;
    state->phase = GenericPhase::complete;
    ++genericCompletedStreams;
    if (genericActiveStreams > 0)
    {
      --genericActiveStreams;
    }
    openMoreGenericClientStreams();
  }

  void maybeCountGenericDurationUnit(GenericStreamState *state)
  {
    if (state == nullptr ||
        !genericDurationMode ||
        state->durationCounted ||
        state->responseRemaining != 0 ||
        !supportsSmallGenericDurationMode(benchmarkScenario) ||
        !durationTransferRunning ||
        durationTransferDeadlineUs == 0 ||
        timeNowUs() > durationTransferDeadlineUs)
    {
      return;
    }
    state->durationCounted = true;
    ++durationCompletedUnits;
  }

  void maybeMarkGenericDurationConnectionComplete(picoquic_cnx_t *activeConnection)
  {
    if constexpr (mode & Mode::server)
    {
      if (activeConnection == nullptr ||
          !durationModeActive() ||
          !supportsGenericDurationMode(benchmarkScenario) ||
          genericDurationCompleteByConnection[activeConnection])
      {
        return;
      }
      const uint64_t nowUs = timeNowUs();
      uint64_t& serverDeadlineUs = genericDurationServerDeadlineByConnection[activeConnection];
      if (serverDeadlineUs == 0)
      {
        serverDeadlineUs = nowUs + benchmarkTargetDurationMs * 1000ULL + benchmarkDatagramDrainUs;
      }
      const bool deadlineElapsed = nowUs >= serverDeadlineUs;
      if (!genericDurationDoneByConnection[activeConnection] && !deadlineElapsed)
      {
        return;
      }
      uint64_t& drainDeadlineUs = genericDurationDrainDeadlineByConnection[activeConnection];
      if (drainDeadlineUs == 0)
      {
        drainDeadlineUs = nowUs + benchmarkDatagramDrainUs;
      }
      size_t pendingStreams = 0;
      for (const auto& stream : genericStreams)
      {
        if (stream->cnx == activeConnection &&
            !stream->controlStream &&
            !stream->complete)
        {
          ++pendingStreams;
        }
      }
      if (pendingStreams != 0 && nowUs < drainDeadlineUs)
      {
        if (stallTrace)
        {
          fprintf(stderr,
                  "picoquic debug=generic_duration role=server event=wait_pending "
                  "pending_streams=%zu streams=%zu completed_streams=%" PRIu64
                  " drain_left_us=%" PRIu64 "\n",
                  pendingStreams, genericStreams.size(), genericServerCompletedStreams,
                  drainDeadlineUs - nowUs);
        }
        return;
      }
      genericDurationCompleteByConnection[activeConnection] = true;
      ++serverCompletedConnections;
      if (stallTrace)
      {
        fprintf(stderr,
                "picoquic debug=generic_duration role=server event=complete "
                "pending_streams=%zu streams=%zu completed_streams=%" PRIu64
                " server_completed_connections=%u\n",
                pendingStreams, genericStreams.size(), genericServerCompletedStreams,
                serverCompletedConnections);
      }
    }
  }

  void markGenericDurationConnectionsAfterDrain(void)
  {
    if constexpr (mode & Mode::server)
    {
      if (!durationModeActive() ||
          !supportsGenericDurationMode(benchmarkScenario))
      {
        return;
      }
      for (const auto& entry : genericDurationDoneByConnection)
      {
        if (entry.second)
        {
          maybeMarkGenericDurationConnectionComplete(entry.first);
        }
      }
      for (const auto& stream : genericStreams)
      {
        maybeMarkGenericDurationConnectionComplete(stream->cnx);
      }
    }
  }

  void markGenericServerComplete(GenericStreamState *state)
  {
    if (state == nullptr || state->complete)
    {
      return;
    }
    state->complete = true;
    state->phase = GenericPhase::complete;
    ++genericServerCompletedStreams;
    maybeMarkGenericDurationConnectionComplete(state->cnx);
  }

  void openMoreGenericClientStreams(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (!genericStarted || !benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) || cnx == nullptr)
      {
        return;
      }
      if (genericDurationMode &&
          (!genericDurationOpening ||
           durationTransferDeadlineUs == 0 ||
           timeNowUs() >= durationTransferDeadlineUs))
      {
        return;
      }
      const uint64_t targetStreams =
          genericDurationMode ? UINT64_MAX : benchmarkGenericStreamsPerConnection();
      const uint64_t maxActive =
          benchmarkScenario == BenchmarkScenario::bidi
              ? 1
              : std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
      while (genericRequestedStreams < targetStreams && genericActiveStreams < maxActive)
      {
        const uint64_t streamId = genericRequestedStreams * 4;
        auto state = std::make_unique<GenericStreamState>();
        initializeGenericClientState(*state, streamId);
        GenericStreamState *raw = state.get();
        genericStreams.push_back(std::move(state));
        genericStreamById[streamId] = raw;
        picoquic_mark_active_stream(cnx, streamId, true, raw);
        ++genericRequestedStreams;
        ++genericActiveStreams;
      }
    }
  }

  bool genericClientHasActiveStreams(void) const
  {
    for (const auto& stream : genericStreams)
    {
      if (!stream->controlStream && !stream->complete)
      {
        return true;
      }
    }
    return false;
  }

  // static const char* picoeventToString(picoquic_call_back_event_t fin_or_event)
  // {
  // 	switch (fin_or_event)
  // 	{
  // 		case picoquic_callback_stream_data: 			return "picoquic_callback_stream_data";
  // 		case picoquic_callback_stream_fin:  			return "picoquic_callback_stream_fin";
  // 		case picoquic_callback_stream_reset:  			return "picoquic_callback_stream_reset";
  // 		case picoquic_callback_stop_sending:  			return "picoquic_callback_stop_sending";
  // 		case picoquic_callback_stateless_reset:  		return "picoquic_callback_stateless_reset";
  // 		case picoquic_callback_close:  					return "picoquic_callback_close";
  // 		case picoquic_callback_application_close:  	return "picoquic_callback_application_close";
  // 		case picoquic_callback_stream_gap:  			return "picoquic_callback_stream_gap";
  // 		case picoquic_callback_prepare_to_send:  		return "picoquic_callback_prepare_to_send";
  // 		case picoquic_callback_almost_ready:  			return "picoquic_callback_almost_ready";
  // 		case picoquic_callback_ready:  					return "picoquic_callback_ready";
  // 		case picoquic_callback_datagram:  				return "picoquic_callback_datagram";
  // 		case picoquic_callback_version_negotiation:  return "picoquic_callback_version_negotiation";
  // 		case picoquic_callback_request_alpn_list:  	return "picoquic_callback_request_alpn_list";
  // 		case picoquic_callback_set_alpn:  				return "picoquic_callback_set_alpn";
  // 		case picoquic_callback_pacing_changed:  		return "picoquic_callback_pacing_changed";
  // 		default: break;
  // 	}

  // 	printf("got bad picoevent value = %d\n", fin_or_event);
  // 	return "";
  // }

  static int datain(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes, size_t length, picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *stream_ctx)
  {
    // printf("datain -> %s\n", picoeventToString(fin_or_event));

    Picoquic<mode> *instance = (Picoquic<mode> *)callback_ctx;
    ServerStreamState *serverState = nullptr;
    if constexpr (mode & Mode::server)
    {
      if (!benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) &&
          benchmarkScenario != BenchmarkScenario::datagram)
      {
        serverState = (ServerStreamState *)stream_ctx;
        if (serverState == nullptr)
        {
          serverState = instance->newServerStreamState(cnx, stream_id);
        }
      }
    }
    GenericStreamState *genericState = nullptr;
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if constexpr (mode & Mode::server)
      {
        genericState = (GenericStreamState *)stream_ctx;
        if (genericState == nullptr)
        {
          genericState = instance->newGenericServerStreamState(cnx, stream_id);
        }
      }
      else
      {
        genericState = (GenericStreamState *)stream_ctx;
        if (genericState == nullptr)
        {
          genericState = instance->genericClientStreamFor(stream_id);
          if (genericState != nullptr)
          {
            picoquic_set_app_stream_ctx(cnx, stream_id, genericState);
          }
        }
      }
    }
    switch (fin_or_event)
    {
        // Data received from peer on stream N
      case picoquic_callback_stream_data:
      // Fin received from peer on stream N; data is optional
      case picoquic_callback_stream_fin:
        {
          if (benchmarkScenario == BenchmarkScenario::datagram)
          {
            if constexpr (mode & Mode::server)
            {
              if (fin_or_event == picoquic_callback_stream_fin)
              {
                auto *datagramState = instance->datagramServerStateFor(cnx);
                datagramState->clientDone = true;
                instance->markDatagramServerComplete(datagramState);
              }
            }
            break;
          }
          if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) && genericState != nullptr)
          {
            size_t consumed = 0;
            if constexpr (mode & Mode::client)
            {
              if (genericState->responseRemaining > 0)
              {
                const uint64_t copied = std::min<uint64_t>(genericState->responseRemaining, length);
                genericState->responseRemaining -= copied;
                consumed += static_cast<size_t>(copied);
                if (instance->genericDurationMode &&
                    supportsByteGenericDurationMode(benchmarkScenario) &&
                    (benchmarkScenario == BenchmarkScenario::multistream_download ||
                     benchmarkScenario == BenchmarkScenario::bidi) &&
                    instance->durationTransferRunning &&
                    instance->durationTransferDeadlineUs != 0 &&
                    timeNowUs() <= instance->durationTransferDeadlineUs)
                {
                  instance->durationCompletedUnits += copied;
                }
                if (genericState->responseRemaining == 0)
                {
                  instance->maybeCountGenericDurationUnit(genericState);
                  if (genericUsesTerminalAck())
                  {
                    genericState->phase = GenericPhase::sendDone;
                    picoquic_mark_active_stream(cnx, stream_id, true, genericState);
                  }
                  else
                  {
                    instance->markGenericClientComplete(genericState);
                  }
                }
              }
              if (genericUsesTerminalAck() &&
                  genericState->phase == GenericPhase::readAck &&
                  genericState->ackBytesRead < 1 && consumed < length)
              {
                const size_t copied = std::min<size_t>(1 - genericState->ackBytesRead, length - consumed);
                genericState->ackBytesRead += copied;
                consumed += copied;
                if (genericState->ackBytesRead >= 1)
                {
                  instance->markGenericClientComplete(genericState);
                }
              }
            }
            else
            {
              if (genericState->phase == GenericPhase::readRequest)
              {
                if (instance->durationModeActive() &&
                    supportsGenericDurationMode(benchmarkScenario) &&
                    !genericState->controlStream &&
                    genericState->requestBytesRead == 0 &&
                    length == 1 &&
                    bytes != nullptr &&
                    bytes[0] == genericDurationDoneByte())
                {
                  genericState->controlStream = true;
                  consumed = 1;
                  if (instance->stallTrace)
                  {
                    fprintf(stderr,
                            "picoquic debug=generic_duration role=server "
                            "event=control_marker stream=%" PRIu64 " fin=%u length=%zu\n",
                            stream_id,
                            fin_or_event == picoquic_callback_stream_fin ? 1 : 0,
                            length);
                  }
                }
                if (genericState->controlStream)
                {
                  if (fin_or_event == picoquic_callback_stream_fin)
                  {
                    genericState->complete = true;
                    genericState->phase = GenericPhase::complete;
                    instance->genericDurationDoneByConnection[cnx] = true;
                    if (instance->stallTrace)
                    {
                      fprintf(stderr,
                              "picoquic debug=generic_duration role=server "
                              "event=control_fin stream=%" PRIu64 "\n",
                              stream_id);
                    }
                    instance->maybeMarkGenericDurationConnectionComplete(cnx);
                  }
                  break;
                }
                if (instance->durationModeActive() &&
                    supportsGenericDurationMode(benchmarkScenario) &&
                    genericState->requestBytesRead == 0 &&
                    fin_or_event == picoquic_callback_stream_fin &&
                    length == 0)
                {
                  genericState->controlStream = true;
                  genericState->complete = true;
                  genericState->phase = GenericPhase::complete;
                  instance->genericDurationDoneByConnection[cnx] = true;
                  if (instance->stallTrace)
                  {
                    fprintf(stderr,
                            "picoquic debug=generic_duration role=server "
                            "event=control_empty_fin stream=%" PRIu64 "\n",
                            stream_id);
                  }
                  instance->maybeMarkGenericDurationConnectionComplete(cnx);
                  break;
                }
                if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
                {
                  if (genericState->requestBytesExpected == 0)
                  {
                    genericState->requestBytesExpected = benchmarkGenericReqRespRequestBytes();
                  }
                  const uint64_t copied = std::min<uint64_t>(
                      genericState->requestBytesExpected - genericState->requestBytesRead, length);
                  genericState->requestBytesRead += copied;
                  consumed += static_cast<size_t>(copied);
                  if (genericState->requestBytesRead == genericState->requestBytesExpected)
                  {
                    genericState->responseRemaining = benchmarkGenericReqRespResponseBytes();
                    genericState->phase = GenericPhase::sendResponse;
                    picoquic_mark_active_stream(cnx, stream_id, true, genericState);
                  }
                }
                else
                {
                  while (genericState->requestBytesRead < genericState->requestBytes.size() && consumed < length)
                  {
                    genericState->requestBytes[genericState->requestBytesRead++] = bytes[consumed++];
                  }
                  if (genericState->requestBytesRead == genericState->requestBytes.size())
                  {
                    genericState->requestValue = decodeU64(genericState->requestBytes);
                    genericState->payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                                                      benchmarkScenario == BenchmarkScenario::bidi)
                                                         ? genericState->requestValue
                                                         : 0;
                    genericState->responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : genericState->requestValue;
                    genericState->phase = genericState->payloadRemaining > 0 ? GenericPhase::readPayload : GenericPhase::sendResponse;
                    if (genericState->phase == GenericPhase::sendResponse)
                    {
                      picoquic_mark_active_stream(cnx, stream_id, true, genericState);
                    }
                  }
                }
              }
              if ((benchmarkScenario == BenchmarkScenario::multistream_upload ||
                   benchmarkScenario == BenchmarkScenario::bidi) &&
                  consumed < length && genericState->payloadRemaining > 0)
              {
                const uint64_t copied = std::min<uint64_t>(genericState->payloadRemaining, length - consumed);
                genericState->payloadRemaining -= copied;
                consumed += static_cast<size_t>(copied);
                if (genericState->payloadRemaining == 0)
                {
                  genericState->phase = GenericPhase::sendResponse;
                  picoquic_mark_active_stream(cnx, stream_id, true, genericState);
                }
              }
              if (genericUsesTerminalAck() &&
                  genericState->phase == GenericPhase::readDone &&
                  genericState->doneBytesRead < 1 && consumed < length)
              {
                const size_t copied = std::min<size_t>(1 - genericState->doneBytesRead, length - consumed);
                genericState->doneBytesRead += copied;
                consumed += copied;
                if (genericState->doneBytesRead >= 1)
                {
                  genericState->phase = GenericPhase::sendAck;
                  picoquic_mark_active_stream(cnx, stream_id, true, genericState);
                }
              }
            }
            break;
          }
          if constexpr (mode & Mode::client)
          {
            if (benchmarkIsUpload())
            {
              if (!instance->durationTransferMode)
              {
                instance->bytesInFlight -= length;
              }
              if (fin_or_event == picoquic_callback_stream_fin)
              {
                instance->clientDone = true;
              }
            }
            else if (instance->durationTransferMode)
            {
              if (instance->durationTransferRunning &&
                  instance->durationTransferDeadlineUs != 0 &&
                  timeNowUs() <= instance->durationTransferDeadlineUs)
              {
                instance->durationCompletedUnits += length;
              }
              if (instance->downloadDoneSignalSent &&
                  !instance->downloadCompletionAckRead && length > 0)
              {
                instance->downloadCompletionAckRead = true;
              }
              if (fin_or_event == picoquic_callback_stream_fin)
              {
                instance->clientDone = true;
                if (instance->downloadDoneSignalSent)
                {
                  instance->downloadCompletionAckRead = true;
                }
              }
            }
            else if (instance->bytesInFlight > 0)
            {
              const int64_t copied = std::min<int64_t>(
                  instance->bytesInFlight, static_cast<int64_t>(length));
              instance->bytesInFlight -= copied;
              if (instance->bytesInFlight == 0)
              {
                picoquic_mark_active_stream(cnx, stream_id, true, instance);
              }
            }
            else if (instance->downloadDoneSignalSent &&
                     !instance->downloadCompletionAckRead && length > 0)
            {
              instance->downloadCompletionAckRead = true;
            }
            // if ((rand() % 250) == 0) printf("received %.1f%%\n", 100.0 * (double)(_1GB - instance->bytesInFlight)/(double)_1GB );
          }
          else
          {
            size_t consumed = 0;
            while (serverState->requestBytesRead < serverState->requestBytes.size() && consumed < length)
            {
              serverState->requestBytes[serverState->requestBytesRead++] = bytes[consumed++];
            }

            if (!serverState->requestParsed && serverState->requestBytesRead == serverState->requestBytes.size())
            {
              uint64_t requested = 0;
              memcpy(&requested, serverState->requestBytes.data(), serverState->requestBytes.size());
              requested = bswap_64(requested);
              serverState->durationMode = instance->durationModeActive() && requested == durationTransferRequest();
              serverState->bytesInFlight = serverState->durationMode
                                               ? (benchmarkIsUpload() ? 0 : INT64_MAX)
                                               : static_cast<int64_t>(requested);
              serverState->requestParsed = true;
              if (serverState->durationMode)
              {
                serverState->serverDrainDeadlineUs =
                    timeNowUs() + benchmarkTargetDurationMs * 1000ULL + benchmarkDurationCompletionDrainUs;
              }
              if (!benchmarkIsUpload())
              {
                seedServerBandwidth(cnx);
                picoquic_mark_active_stream(cnx, stream_id, true, serverState);
              }
            }

            if (benchmarkIsUpload() && serverState->requestParsed && consumed < length)
            {
              if (!serverState->durationMode)
              {
                serverState->bytesInFlight -= std::min<int64_t>(serverState->bytesInFlight, static_cast<int64_t>(length - consumed));
              }
              if (serverState->bytesInFlight == 0)
              {
                picoquic_mark_active_stream(cnx, stream_id, true, serverState);
              }
            }
            if (fin_or_event == picoquic_callback_stream_fin)
            {
              serverState->clientDone = true;
              if (serverState->durationMode)
              {
                serverState->bytesInFlight = 0;
              }
              if (!benchmarkIsUpload())
              {
                picoquic_mark_active_stream(cnx, stream_id, true, serverState);
              }
              else if (serverState->durationMode)
              {
                picoquic_mark_active_stream(cnx, stream_id, true, serverState);
              }
            }
          }

          break;
        }
        // Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details
      case picoquic_callback_prepare_to_send:
        {
          if (benchmarkScenario == BenchmarkScenario::datagram)
          {
            if constexpr (mode & Mode::client)
            {
              if (instance->datagramClientSendBudgetReached() &&
                  !instance->datagramDoneSignalSent)
              {
                instance->sendClientDatagramDoneSignal();
              }
              if (instance->datagramDoneSignalSent && !instance->datagramDoneStreamWritten)
              {
                uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, 1, true, false);
                if (buffer != nullptr)
                {
                  buffer[0] = 0;
                  instance->datagramDoneStreamWritten = true;
                  instance->datagramClientDrainDeadlineUs = instance->datagramClientReceived >= instance->datagramClientSent
                                                                ? timeNowUs()
                                                                : timeNowUs() + benchmarkDatagramDrainUs;
                }
              }
            }
            break;
          }
          if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) && genericState != nullptr)
          {
            if constexpr (mode & Mode::client)
            {
              size_t sendLength = 0;
              const uint8_t *source = nullptr;
              bool finished = false;
              bool stillActive = false;
              if (genericState->controlStream && !instance->genericDurationDoneSent)
              {
                static const uint8_t done = genericDurationDoneByte();
                sendLength = std::min<size_t>(length, sizeof(done));
                source = &done;
                finished = true;
              }
              else if (genericState->requestBytesWritten < genericState->requestBytesExpected)
              {
                const size_t left = static_cast<size_t>(
                    genericState->requestBytesExpected - genericState->requestBytesWritten);
                sendLength = std::min<size_t>(length, left);
                source = benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario)
                             ? instance->networkHub->junk
                             : genericState->requestBytes.data() + genericState->requestBytesWritten;
                stillActive = sendLength < left || genericState->payloadRemaining > 0;
                finished = sendLength == left && genericState->payloadRemaining == 0 &&
                           !genericUsesTerminalAck();
              }
              else if (genericState->payloadRemaining > 0)
              {
                sendLength = static_cast<size_t>(
                    std::min<uint64_t>(length, genericState->payloadRemaining));
                source = instance->networkHub->junk;
                stillActive = sendLength < genericState->payloadRemaining;
                finished = sendLength == genericState->payloadRemaining &&
                           !genericUsesTerminalAck();
              }
              else if (genericUsesTerminalAck() &&
                       genericState->phase == GenericPhase::sendDone &&
                       genericState->doneBytesWritten < 1)
              {
                sendLength = std::min<size_t>(length, 1 - genericState->doneBytesWritten);
                source = instance->networkHub->junk;
                finished = sendLength == 1 - genericState->doneBytesWritten;
              }

              uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sendLength, finished, stillActive);
              if (buffer != nullptr && sendLength > 0 && source != nullptr)
              {
                memcpy(buffer, source, sendLength);
                if (genericState->controlStream)
                {
                  genericState->complete = true;
                  instance->genericDurationDoneSent = true;
                  if (instance->stallTrace)
                  {
                    fprintf(stderr,
                            "picoquic debug=generic_duration role=client "
                            "event=control_sent stream=%" PRIu64 "\n",
                            stream_id);
                  }
                }
                else if (genericState->requestBytesWritten < genericState->requestBytesExpected)
                {
                  genericState->requestBytesWritten += sendLength;
                }
                else if (genericState->payloadRemaining > 0)
                {
                  const uint64_t before = genericState->payloadRemaining;
                  genericState->payloadRemaining -= sendLength;
                  if (instance->genericDurationMode &&
                      supportsByteGenericDurationMode(benchmarkScenario) &&
                      (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                       benchmarkScenario == BenchmarkScenario::bidi) &&
                      instance->durationTransferRunning &&
                      instance->durationTransferDeadlineUs != 0 &&
                      timeNowUs() <= instance->durationTransferDeadlineUs)
                  {
                    instance->durationCompletedUnits += before - genericState->payloadRemaining;
                  }
                }
                else if (genericUsesTerminalAck() &&
                         genericState->phase == GenericPhase::sendDone)
                {
                  genericState->doneBytesWritten += sendLength;
                  if (genericState->doneBytesWritten >= 1)
                  {
                    genericState->phase = GenericPhase::readAck;
                  }
                }
              }
            }
            else
            {
              size_t sendLength = 0;
              const uint8_t *source = nullptr;
              bool finished = false;
              bool stillActive = false;
              if (genericState->phase == GenericPhase::sendAck &&
                  genericState->ackBytesWritten < 1)
              {
                sendLength = std::min<size_t>(length, 1 - genericState->ackBytesWritten);
                source = instance->networkHub->junk;
                finished = sendLength == 1 - genericState->ackBytesWritten;
              }
              else if (genericState->phase == GenericPhase::sendResponse && genericState->responseRemaining > 0)
              {
                sendLength = static_cast<size_t>(
                    std::min<uint64_t>(length, genericState->responseRemaining));
                source = instance->networkHub->junk;
                stillActive = sendLength < genericState->responseRemaining;
                finished = sendLength == genericState->responseRemaining &&
                           !genericUsesTerminalAck();
              }

              uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sendLength, finished, stillActive);
              if (buffer != nullptr && sendLength > 0 && source != nullptr)
              {
                memcpy(buffer, source, sendLength);
                if (genericState->phase == GenericPhase::sendAck)
                {
                  genericState->ackBytesWritten += sendLength;
                  if (genericState->ackBytesWritten >= 1)
                  {
                    instance->markGenericServerComplete(genericState);
                  }
                }
                else if (genericState->phase == GenericPhase::sendResponse)
                {
                  genericState->responseRemaining -= sendLength;
                  if (genericState->responseRemaining == 0)
                  {
                    if (genericUsesTerminalAck())
                    {
                      genericState->phase = GenericPhase::readDone;
                    }
                    else
                    {
                      instance->markGenericServerComplete(genericState);
                    }
                  }
                }
              }
            }
            break;
          }
          if constexpr (mode & Mode::client)
          {
            if (benchmarkIsUpload())
            {
              const size_t headerLeft = instance->requestBytes.size() - instance->requestBytesWritten;
              const bool durationHeaderOnly = instance->durationTransferMode &&
                                              !instance->durationTransferRunning &&
                                              headerLeft != 0;
              const size_t payloadLeft = durationHeaderOnly
                                             ? 0
                                             : static_cast<size_t>(std::max<int64_t>(instance->bytesInFlight, 0));
              const size_t sendLength = std::min<size_t>(length, headerLeft + payloadLeft);
              const bool finished = !durationHeaderOnly && sendLength == headerLeft + payloadLeft;
              const bool stillActive = durationHeaderOnly || !finished;
              uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sendLength, finished, stillActive);
              if (buffer != nullptr)
              {
                size_t copied = 0;
                const size_t headerBytes = std::min(headerLeft, sendLength);
                if (headerBytes != 0)
                {
                  memcpy(buffer, instance->requestBytes.data() + instance->requestBytesWritten, headerBytes);
                  instance->requestBytesWritten += headerBytes;
                  copied += headerBytes;
                }

                const size_t payloadBytes = sendLength - copied;
                if (payloadBytes != 0)
                {
                  memset(buffer + copied, 7, payloadBytes);
                  instance->bytesInFlight -= payloadBytes;
                  if (instance->durationTransferMode && instance->durationTransferRunning)
                  {
                    instance->durationCompletedUnits += payloadBytes;
                  }
                }
              }
            }
            else if (instance->requestBytesWritten < instance->requestBytes.size())
            {
              const size_t left = instance->requestBytes.size() - instance->requestBytesWritten;
              const size_t sendLength = std::min<size_t>(length, left);
              uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sendLength, false, sendLength < left);
              if (buffer != nullptr && sendLength > 0)
              {
                memcpy(buffer, instance->requestBytes.data() + instance->requestBytesWritten, sendLength);
                instance->requestBytesWritten += sendLength;
                if (instance->requestBytesWritten == instance->requestBytes.size())
                {
                  picoquic_mark_active_stream(cnx, stream_id, false, instance);
                }
              }
            }
            else if (!instance->downloadDoneSignalSent &&
                     (!instance->durationTransferMode || !instance->durationTransferRunning))
            {
              static const uint8_t done = 0;
              uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sizeof(done), true, false);
              if (buffer != nullptr)
              {
                buffer[0] = done;
                instance->downloadDoneSignalSent = true;
              }
            }
            else
            {
              instance->ready = true;
            }
          }
          else
          {
            if (serverState->bytesInFlight <= 0)
            {
              if (benchmarkIsUpload())
              {
                if (serverState->durationMode && !serverState->clientDone)
                {
                  picoquic_provide_stream_data_buffer(bytes, 0, false, false);
                  picoquic_mark_active_stream(cnx, stream_id, false, serverState);
                  break;
                }
                picoquic_provide_stream_data_buffer(bytes, 0, true, false);
                serverState->uploadFinSent = true;
                if (serverState->serverDrainDeadlineUs == 0)
                {
                  serverState->serverDrainDeadlineUs = timeNowUs() + 100'000;
                }
                instance->markServerStateComplete(serverState);
              }
              else if (serverState->clientDone && !serverState->completionAckSent)
              {
                static const uint8_t ack = 0;
                uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sizeof(ack), true, false);
                if (buffer != nullptr)
                {
                  buffer[0] = ack;
                  serverState->completionAckSent = true;
                  serverState->serverDrainDeadlineUs = timeNowUs() + 100'000;
                  instance->markServerStateComplete(serverState);
                }
              }
              else
              {
                picoquic_provide_stream_data_buffer(bytes, 0, false, false);
                picoquic_mark_active_stream(cnx, stream_id, false, serverState);
              }
              break;
            }

            size_t bytesSending = serverState->bytesInFlight > (int64_t)length ? length : serverState->bytesInFlight;
            bool stillActive = bytesSending < (size_t)serverState->bytesInFlight;
            bool finished = benchmarkIsUpload() && !stillActive;
            uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, bytesSending, finished, stillActive);

            if (buffer != nullptr)
            {
              memset(buffer, 7, bytesSending);
              serverState->bytesInFlight -= bytesSending;
              if (benchmarkIsUpload() && serverState->bytesInFlight == 0 && serverState->serverDrainDeadlineUs == 0)
              {
                serverState->serverDrainDeadlineUs = timeNowUs() + 100'000;
              }
            }
          }

          break;
        }
      // Data can be sent, but the connection is not fully established
      case picoquic_callback_almost_ready:
        {
          if constexpr (mode & Mode::client)
          {
            instance->resumedObserved = instance->resumedObserved ||
                                        picoquic_tls_is_psk_handshake(cnx) != 0;
            instance->zeroRttAcceptedObserved = instance->zeroRttAcceptedObserved ||
                                                cnx->zero_rtt_data_accepted != 0;
          }
          break;
        }
      // Data can be sent and received, connection migration can be initiated
      case picoquic_callback_ready:
        {
          instance->ready = true;
          if constexpr (mode & Mode::client)
          {
            instance->resumedObserved = instance->resumedObserved ||
                                        picoquic_tls_is_psk_handshake(cnx) != 0;
            instance->zeroRttAcceptedObserved = instance->zeroRttAcceptedObserved ||
                                                cnx->zero_rtt_data_accepted != 0;
          }
          instance->seedServerBandwidth(cnx);
          break;
        }
      // version negotiation requested
      case picoquic_callback_version_negotiation:
      // Provide the list of supported ALPN
      case picoquic_callback_request_alpn_list:
      // Set ALPN to negotiated value
      case picoquic_callback_set_alpn:
      // Pacing rate for the connection changed
      case picoquic_callback_pacing_changed:
      // Reset Stream received from peer on stream N; bytes=NULL, len = 0
      case picoquic_callback_stream_reset:
      // Stop sending received from peer on stream N; bytes=NULL, len = 0
      case picoquic_callback_stop_sending:
      // Stateless reset received from peer. Stream=0, bytes=NULL, len=0
      case picoquic_callback_stateless_reset:
      // Connection close. Stream=0, bytes=NULL, len=0
      case picoquic_callback_close:
      // Application closed by peer. Stream=0, bytes=NULL, len=0
      case picoquic_callback_application_close:
        {
          if (benchmarkScenario == BenchmarkScenario::datagram)
          {
            if constexpr (mode & Mode::server)
            {
              auto *datagramState = instance->datagramServerStateFor(cnx);
              datagramState->clientDone = true;
              instance->markDatagramServerComplete(datagramState);
            }
          }
          break;
        }
      // bytes=NULL, len = length-of-gap or 0 (if unknown)
      case picoquic_callback_stream_gap:
        break;
      // Datagram frame has been received
      case picoquic_callback_datagram:
        {
          if (benchmarkScenario == BenchmarkScenario::datagram)
          {
            if constexpr (mode & Mode::client)
            {
              const uint64_t sequence = benchmarkDecodeDatagramSequence(bytes, length);
              if (benchmarkMarkDatagramSeen(instance->datagramClientSeen, sequence))
              {
                ++instance->datagramClientReceived;
              }
              if (instance->datagramDoneStreamWritten && instance->datagramClientReceived >= instance->datagramClientSent)
              {
                instance->datagramClientDrainDeadlineUs = timeNowUs();
              }
              if (instance->datagramClientSendBudgetReached() &&
                  !instance->datagramDoneSignalSent)
              {
                instance->sendClientDatagramDoneSignal();
              }
              else
              {
                instance->sendClientDatagrams();
              }
            }
            else
            {
              auto *datagramState = instance->datagramServerStateFor(cnx);
              const uint64_t sequence = benchmarkDecodeDatagramSequence(bytes, length);
              if (benchmarkMarkDatagramSeen(datagramState->seen, sequence))
              {
                ++datagramState->received;
                datagramState->pendingEchoes.push_back(sequence);
              }
              instance->sendPendingServerDatagrams();
            }
          }
          break;
        }
      default:
        break;
    }

    return 0;
  }

  void advance(int32_t count = 0)
  {
    // printf("picoquic %s: advance(%d)\n", modeToString(mode), count);

    MultiUDPContext *packets;
    UDPContext *packet;

    size_t send_length;
    size_t send_msg_size;
    int result;
    int interfaceIndex;
    int64_t usTil;

    // max sendBatches to push
    uint16_t metaBatchSize = 1; // tried values of 2 and 3, makes no difference for syscalls

    if constexpr (mode & Mode::iouring)
    {
      metaBatchSize = 1;
    }

    // max we push per sendBatch
    uint16_t batchSize = MultiUDPContext::batchSize;

    if constexpr (mode & Mode::iouring)
    {
      batchSize = 125;
    }

    uint32_t completeDrainLoops = 0;
    while (true)
    {
      if constexpr (mode & Mode::client)
      {
        sendClientDatagrams();
      }
      else
      {
        sendPendingServerDatagrams();
      }
      do
      {
        if constexpr (mode & Mode::iouring)
        {
          // considering iouring is async, sometimes the recvs outrun the sends completions that refill the pool
          if (likely(networkHub->sendPool.howManyLeft() == 0))
          {
            break;
          }
        }

        packets = networkHub->sendPool.get();

        do
        {
          packet = &packets->msgs[packets->count];
          send_msg_size = 0;
          if (useUdpGso)
          {
            packet->ensureCapacity(MAX_IPV6_UDP_GSO_SEND_BUFFER_SIZE);
          }

          result = picoquic_prepare_next_packet_ex(engine, timeNowUs(), packet->buffer(),
                                                   useUdpGso ? MAX_IPV6_UDP_GSO_SEND_BUFFER_SIZE : MAX_IPV6_UDP_PACKET_SIZE,
                                                   &send_length, packet->address<sockaddr_storage>(), NULL, &interfaceIndex,
                                                   NULL, NULL, useUdpGso ? &send_msg_size : NULL);

          if (result == 0 && send_length > 0)
          {
            packet->msg_hdr.msg_iov[0].iov_len = send_length;
            packet->msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
            if (useUdpGso && send_msg_size > 0 && send_length > send_msg_size)
            {
              packet->setUdpSegmentSize(static_cast<uint16_t>(send_msg_size));
            }
            ++packets->count;
          }
          else
          {
            metaBatchSize = 1; // terminate outer loop too
            break;
          }

        } while (packets->count < batchSize);

        if (packets->count > 0)
        {
          networkHub->sendBatch(packets);
        }
        else
        {
          networkHub->sendPool.relinquish(packets);
        }

      } while (--metaBatchSize > 0);

      if constexpr (mode & Mode::server)
      {
        markDatagramServerCompleteAfterSendPass();
      }

      const uint64_t nowUs = timeNowUs();
      usTil = picoquic_get_next_wake_delay(engine, nowUs, 300'000);
      if (usTil > 300'000)
      {
        usTil = 300'000;
      }
      if constexpr (mode & Mode::client)
      {
        if (durationTransferRunning && durationTransferDeadlineUs != 0)
        {
          usTil = nowUs >= durationTransferDeadlineUs
                      ? 0
                      : std::min<int64_t>(usTil, static_cast<int64_t>(durationTransferDeadlineUs - nowUs));
        }
      }
      if constexpr (mode & Mode::iouring)
      {
        if constexpr (mode & Mode::server)
        {
          if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) && perfComplete())
          {
            usTil = 0;
          }
        }
        if (benchmarkIsZeroRttReqResp())
        {
          usTil = std::min<int64_t>(usTil, 1000);
        }
        if (benchmarkScenario == BenchmarkScenario::datagram)
        {
          usTil = std::min<int64_t>(usTil, 1000);
        }
      }

      if (stallTrace && cnx != nullptr && nowUs >= nextStallTraceUs)
      {
        fprintf(stderr,
                "picoquic debug=advance scenario=%s role=%s state=%d ready=%u perf_complete=%u "
                "generic_started=%u generic_requested=%" PRIu64 " generic_completed=%" PRIu64
                " generic_active=%" PRIu64 " zero_available=%u zero_accepted=%u wake_us=%" PRId64
                " send_pool=%u pending_send_sqes=%" PRIu64 " outstanding_send_sqes=%" PRIu64
                " sq_ready=%u cq_ready=%u\n",
                benchmarkScenarioName(benchmarkScenario),
                (mode & Mode::client) ? "client" : "server",
                static_cast<int>(cnx->cnx_state), ready ? 1 : 0,
                perfComplete() ? 1 : 0, genericStarted ? 1 : 0,
                genericRequestedStreams, genericCompletedStreams,
                genericActiveStreams, picoquic_is_0rtt_available(cnx) != 0 ? 1 : 0,
                cnx->zero_rtt_data_accepted != 0 ? 1 : 0, usTil,
                networkHub->debugSendPoolAvailable(),
                networkHub->debugPendingSendSqes(),
                networkHub->debugOutstandingSendSqes(),
                networkHub->debugSqReady(),
                networkHub->debugCqReady());
        nextStallTraceUs = nowUs + 1'000'000;
      }

      networkHub->recvmsgWithTimeout(usTil, [&](UDPContext *msg) -> void {
        picoquic_incoming_packet(engine, msg->buffer(), msg->msg_len, msg->address(), networkHub->socket.address(), 0, 0, timeNowUs());
      });

      if constexpr (mode & Mode::server)
      {
        for (auto& state : serverStreams)
        {
          markServerStateComplete(state.get());
        }
        markGenericDurationConnectionsAfterDrain();
        sendPendingServerDatagrams();
      }

      const bool complete = perfComplete();
      bool drainAfterComplete = false;
      if constexpr ((mode & Mode::server) && (mode & Mode::iouring))
      {
        drainAfterComplete = complete &&
                             benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) &&
                             completeDrainLoops++ < 64;
      }
      if (complete && !drainAfterComplete)
      {
        break;
      }
      if (count != 0 && --count == 0)
      {
        break;
      }
    }
  }

  void resetDurationTransferState(void)
  {
    durationTransferMode = true;
    durationTransferRunning = false;
    durationTransferDeadlineUs = 0;
    durationCompletedUnits = 0;
    durationMeasuredSeconds = 0.0;
    bytesInFlight = 0;
    clientDone = false;
    downloadDoneSignalSent = false;
    downloadCompletionAckRead = false;
    uploadFinSent = false;
    uint64_t request = bswap_64(durationTransferRequest());
    memcpy(requestBytes.data(), &request, requestBytes.size());
    requestBytesWritten = 0;
  }

  void runClientDownloadDuration(void)
  {
    resetDurationTransferState();
    picoquic_mark_active_stream(cnx, 0, true, this);
    while (requestBytesWritten < requestBytes.size())
    {
      advance(1);
    }

    const uint64_t startUs = timeNowUs();
    durationTransferDeadlineUs = durationDeadlineUs(startUs);
    durationTransferRunning = true;
    while (timeNowUs() < durationTransferDeadlineUs)
    {
      advance(1);
    }
    durationTransferRunning = false;
    const uint64_t measuredEndUs = std::min<uint64_t>(timeNowUs(), durationTransferDeadlineUs);
    recordDurationResult(durationCompletedUnits, startUs, measuredEndUs);

    picoquic_mark_active_stream(cnx, 0, true, this);
    const uint64_t drainDeadlineUs = timeNowUs() + 1'000'000;
    while ((!downloadDoneSignalSent || !downloadCompletionAckRead) && timeNowUs() < drainDeadlineUs)
    {
      advance(1);
    }
    durationTransferMode = false;
    bytesInFlight = 0;
  }

  void runClientUploadDuration(void)
  {
    resetDurationTransferState();
    const uint64_t startUs = timeNowUs();
    durationTransferDeadlineUs = durationDeadlineUs(startUs);
    durationTransferRunning = true;
    bytesInFlight = INT64_MAX;
    picoquic_mark_active_stream(cnx, 0, true, this);
    while (timeNowUs() < durationTransferDeadlineUs)
    {
      picoquic_mark_active_stream(cnx, 0, true, this);
      advance(1);
    }
    durationTransferRunning = false;
    bytesInFlight = 0;
    const uint64_t measuredEndUs = std::min<uint64_t>(timeNowUs(), durationTransferDeadlineUs);
    recordDurationResult(durationCompletedUnits, startUs, measuredEndUs);

    picoquic_mark_active_stream(cnx, 0, true, this);
    const uint64_t drainDeadlineUs = timeNowUs() + 1'000'000;
    while (!clientDone && timeNowUs() < drainDeadlineUs)
    {
      advance(1);
    }
    durationTransferMode = false;
    bytesInFlight = 0;
  }

  void sendGenericDurationDone(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (genericDurationDoneSent)
      {
        return;
      }
      const uint64_t streamId = genericRequestedStreams * 4;
      auto state = std::make_unique<GenericStreamState>();
      state->owner = this;
      state->cnx = cnx;
      state->streamId = streamId;
      state->controlStream = true;
      state->phase = GenericPhase::sendPayload;
      GenericStreamState *raw = state.get();
      genericStreams.push_back(std::move(state));
      genericStreamById[streamId] = raw;
      picoquic_mark_active_stream(cnx, streamId, true, raw);
      if (stallTrace)
      {
        fprintf(stderr,
                "picoquic debug=generic_duration role=client "
                "event=control_armed stream=%" PRIu64 " requested=%" PRIu64
                " active=%" PRIu64 "\n",
                streamId, genericRequestedStreams, genericActiveStreams);
      }

      const uint64_t deadlineUs = timeNowUs() + 100'000;
      while (!genericDurationDoneSent && timeNowUs() < deadlineUs)
      {
        advance(1);
      }
      if (stallTrace)
      {
        fprintf(stderr,
                "picoquic debug=generic_duration role=client "
                "event=control_send_loop_done sent=%u\n",
                genericDurationDoneSent ? 1 : 0);
      }
    }
  }

  void runClientGenericDuration(uint64_t nBytes)
  {
    genericClientBytes = nBytes;
    genericRequestedStreams = 0;
    genericOpenedStreams = 0;
    genericCompletedStreams = 0;
    genericServerCompletedStreams = 0;
    genericActiveStreams = 0;
    genericStreams.clear();
    genericStreamById.clear();
    genericDurationDoneByConnection.clear();
    genericDurationCompleteByConnection.clear();
    genericDurationDrainDeadlineByConnection.clear();
    genericDurationServerDeadlineByConnection.clear();
    genericStarted = true;
    genericDurationMode = true;
    genericDurationOpening = true;
    genericDurationDoneSent = false;
    durationTransferRunning = true;
    durationTransferDeadlineUs = 0;
    durationCompletedUnits = 0;
    durationMeasuredSeconds = 0.0;

    genericStreams.reserve(static_cast<size_t>(
        std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight) + 1));
    genericStreamById.reserve(static_cast<size_t>(
        std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight) + 1));

    const uint64_t startUs = timeNowUs();
    durationTransferDeadlineUs = durationDeadlineUs(startUs);
    while (timeNowUs() < durationTransferDeadlineUs)
    {
      openMoreGenericClientStreams();
      advance(1);
    }

    durationTransferRunning = false;
    genericDurationOpening = false;
    const uint64_t measuredEndUs = std::min<uint64_t>(timeNowUs(), durationTransferDeadlineUs);
    recordDurationResult(durationCompletedUnits, startUs, measuredEndUs);

    const uint64_t drainDeadlineUs = timeNowUs() + 500'000;
    while (genericClientHasActiveStreams() && timeNowUs() < drainDeadlineUs)
    {
      advance(1);
    }

    genericStarted = false;
    sendGenericDurationDone();
    const uint64_t doneDeadlineUs = timeNowUs() + 100'000;
    while (timeNowUs() < doneDeadlineUs)
    {
      advance(1);
    }

    genericDurationMode = false;
  }

  void createConfiguredEngine(const char *ticketStoreFile)
  {
    if (engine != nullptr)
    {
      picoquic_free(engine);
      engine = nullptr;
      cnx = nullptr;
    }

    engine = picoquic_create(1000, tls_cert, tls_key, tls_chain, "perf", datain, this,
                             NULL, NULL, NULL, timeNowUs(), NULL, ticketStoreFile,
                             ticketEncryptionKey, sizeof(ticketEncryptionKey));
    if (engine == nullptr)
    {
      fprintf(stderr, "picoquic: failed to create engine\n");
      abort();
    }
    if (!benchmarkTlsVerifyPeer())
    {
      picoquic_set_verify_certificate_callback(engine, &noVerifyWithEd25519, nullptr);
    }

    picoquic_tp_t transportParams = *picoquic_get_default_tp(engine);
    transportParams.initial_max_stream_data_bidi_local = benchmarkStreamWindow;
    transportParams.initial_max_stream_data_bidi_remote = benchmarkStreamWindow;
    transportParams.initial_max_stream_data_uni = benchmarkStreamWindow;
    transportParams.initial_max_data = benchmarkConnectionWindow;
    transportParams.initial_max_stream_id_bidir = benchmarkMaxBidiStreams;
    transportParams.initial_max_stream_id_unidir = benchmarkMaxUniStreams;
    transportParams.max_idle_timeout = benchmarkIdleTimeoutMs;
    transportParams.max_packet_size = benchmarkUdpPayloadSize;
    transportParams.max_datagram_frame_size = benchmarkUdpPayloadSize;
    transportParams.max_ack_delay = benchmarkMaxAckDelayUs;
    transportParams.ack_delay_exponent = benchmarkAckDelayExponent;
    transportParams.migration_disabled = 1;
    transportParams.enable_bdp_frame = benchmarkPicoquicBdpFrameMode;
    picoquic_set_default_tp(engine, &transportParams);
    picoquic_set_default_idle_timeout(engine, benchmarkIdleTimeoutMs);
    picoquic_set_default_congestion_algorithm(engine, benchmarkPicoquicCongestionAlgorithm());
    picoquic_set_default_bdp_frame_option(engine, benchmarkPicoquicBdpFrameMode);
    picoquic_set_default_pmtud_policy(engine, picoquic_pmtud_blocked);
    picoquic_set_mtu_max(engine, benchmarkUdpPayloadSize);
    picoquic_set_max_data_control(engine, benchmarkConnectionWindow);
    // Packet-train mode is only enabled when picoquic emits native UDP_SEGMENT
    // buffers; the shared C++ path owns default coalescing otherwise.
    picoquic_set_packet_train_mode(engine, useUdpGso ? 1 : 0);
  }

public:

  ~Picoquic() override
  {
    if (engine != nullptr)
    {
      picoquic_free(engine);
      engine = nullptr;
      cnx = nullptr;
    }
    delete networkHub;
    networkHub = nullptr;
  }

  void instanceSetup(uint16_t localPort, int argc, char *argv[])
  {
    // printf("picoquic %s: instanceSetup\n", modeToString(mode));

    useUdpGso = benchmarkPicoquicPacketTrainMode && benchmarkUdpGsoEnabled();
    stallTrace = std::getenv("QUICPERF_PICO_STALL_DEBUG") != nullptr;
    nextStallTraceUs = timeNowUs();

    this->localPort = localPort;
    networkHub = new NetworkHub<mode>(localPort);
    const char *initialTicketStore = nullptr;
    if constexpr (mode & Mode::client)
    {
      ticketFile = makeTicketFileName("warmup");
      remove(ticketFile.c_str());
      initialTicketStore = ticketFile.c_str();
    }
    createConfiguredEngine(initialTicketStore);
    // picoquic_set_log_level(engine, 1);
    // picoquic_set_textlog(engine, "/dev/stdout");
    // picoquic_set_client_authentication(engine, 1);
  }

  void connectToServer(struct sockaddr *address)
  {
    // printf("picoquic %s: connect\n", modeToString(mode));

    // picoquic_cnx_t* picoquic_create_cnx(picoquic_quic_t* quic, picoquic_connection_id_t initial_cnx_id, picoquic_connection_id_t remote_cnx_id, const struct sockaddr* addr_to, uint64_t start_time, uint32_t preferred_version, char const* sni, char const* alpn, char client_mode);

    cnx = picoquic_create_cnx(engine, picoquic_null_connection_id, picoquic_null_connection_id, address, timeNowUs(), 0, "localhost", "perf", true);

    picoquic_set_callback(cnx, datain, this);
    picoquic_set_congestion_algorithm(cnx, benchmarkPicoquicCongestionAlgorithm());

    picoquic_start_client_cnx(cnx);

    do
    {
      advance(1);

    } while (ready == false);
    resumedObserved = resumedObserved || picoquic_tls_is_psk_handshake(cnx) != 0;
    zeroRttAcceptedObserved = zeroRttAcceptedObserved || cnx->zero_rtt_data_accepted != 0;
  }

  void connectToServerForZeroRtt(struct sockaddr *address) override
  {
    if constexpr (mode & Mode::client)
    {
      ready = false;
      cnx = picoquic_create_cnx(engine, picoquic_null_connection_id, picoquic_null_connection_id,
                                address, timeNowUs(), 0, "localhost", "perf", true);
      if (cnx == nullptr)
      {
        fprintf(stderr, "picoquic: failed to create 0-RTT connection\n");
        abort();
      }
      picoquic_set_callback(cnx, datain, this);
      picoquic_set_congestion_algorithm(cnx, benchmarkPicoquicCongestionAlgorithm());
      if (picoquic_start_client_cnx(cnx) != 0)
      {
        fprintf(stderr, "picoquic: failed to start 0-RTT client connection\n");
        abort();
      }
      zeroRttAttemptedObserved = picoquic_is_0rtt_available(cnx) != 0;
      advance(1);
    }
  }

  void openStream(void)
  {
    // printf("picoquic %s: openStream\n", modeToString(mode));

    // picoquic_mark_active_stream(cnx, 0, true, this);

    // do
    // {
    // 	advance(1);

    // } while (ready == false);

    // picoquic_mark_active_stream(cnx, 0, false, this);
  }

  void postPerfTest(void) override
  {
    if constexpr (mode & Mode::client)
    {
      if (durationModeActive())
      {
        return;
      }
      if (!benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) &&
          benchmarkScenario != BenchmarkScenario::datagram &&
          !durationTransferMode &&
          !benchmarkIsUpload() &&
          requestBytesWritten == requestBytes.size() &&
          !downloadCompletionAckRead)
      {
        picoquic_mark_active_stream(cnx, 0, true, this);
        while (!downloadDoneSignalSent || !downloadCompletionAckRead)
        {
          advance(1);
        }
      }
    }
  }

  void startPerfTest(uint64_t nBytes)
  {
    // printf("picoquic %s: startPerfTest\n", modeToString(mode));

    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        if (durationModeActive() && supportsGenericDurationMode(benchmarkScenario))
        {
          runClientGenericDuration(nBytes);
          return;
        }
        genericClientBytes = nBytes;
        genericRequestedStreams = 0;
        genericOpenedStreams = 0;
        genericCompletedStreams = 0;
        genericServerCompletedStreams = 0;
        genericActiveStreams = 0;
        genericStreams.clear();
        genericStreamById.clear();
        const uint64_t targetStreams = benchmarkGenericStreamsPerConnection();
        genericStreams.reserve(static_cast<size_t>(targetStreams));
        genericStreamById.reserve(static_cast<size_t>(targetStreams));
        genericStarted = true;
        openMoreGenericClientStreams();
        advance();
        if (benchmarkIsZeroRttReqResp())
        {
          while (!ready)
          {
            advance(1);
          }
          resumedObserved = resumedObserved || picoquic_tls_is_psk_handshake(cnx) != 0;
          zeroRttAcceptedObserved = zeroRttAcceptedObserved || cnx->zero_rtt_data_accepted != 0;
        }
        return;
      }
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        datagramClientSent = 0;
        datagramClientReceived = 0;
        datagramClientDrainDeadlineUs = 0;
        datagramStarted = true;
        datagramDoneSignalSent = false;
        datagramDoneStreamWritten = false;
        datagramClientSeen.assign(benchmarkDatagramSeenBytes(), 0);
        datagramScratch.fill(0);
        bytesInFlight = 0;
        const bool durationDatagram = datagramDurationModeActive();
        uint64_t durationStartUs = 0;
        if (durationDatagram)
        {
          durationCompletedUnits = 0;
          durationMeasuredSeconds = 0.0;
          durationTransferRunning = true;
          durationStartUs = timeNowUs();
          durationTransferDeadlineUs = durationDeadlineUs(durationStartUs);
        }
        sendClientDatagrams();
        advance();
        if (durationDatagram)
        {
          durationTransferRunning = false;
          const uint64_t measuredEndUs = std::min<uint64_t>(timeNowUs(), durationTransferDeadlineUs);
          recordDurationResult(datagramClientReceived, durationStartUs, measuredEndUs);
        }
        benchmarkRecordDatagramClientCounters(datagramClientSent, datagramClientReceived);
        return;
      }
      if (durationModeActive())
      {
        if (benchmarkIsUpload())
        {
          runClientUploadDuration();
        }
        else
        {
          runClientDownloadDuration();
        }
        return;
      }
      bytesInFlight = nBytes;
      clientDone = false;
      downloadDoneSignalSent = false;
      downloadCompletionAckRead = false;
      uint64_t request = bswap_64(nBytes);
      memcpy(requestBytes.data(), &request, requestBytes.size());
      requestBytesWritten = 0;
      picoquic_mark_active_stream(cnx, 0, true, this);
    }

    advance();
  }

  bool supportsSessionResumption(void) const override
  {
    return true;
  }

  bool supportsZeroRtt(void) const override
  {
    return true;
  }

  bool supportsDurationMode(BenchmarkScenario scenario) const override
  {
    return benchmarkTargetDurationMs > 0 &&
           (supportsSimpleDurationMode(scenario) ||
            supportsGenericDurationMode(scenario) ||
            scenario == BenchmarkScenario::datagram);
  }

  uint64_t completedUnitsForReport(uint64_t fallback) const override
  {
    return durationModeActive() ? durationCompletedUnits : fallback;
  }

  double measuredSecondsForReport(double fallback) const override
  {
    return durationModeActive() ? durationMeasuredSeconds : fallback;
  }

  bool exportResumptionState(BenchmarkResumptionState& state) override
  {
    if constexpr (mode & Mode::client)
    {
      if (ticketFile.empty())
      {
        ticketFile = makeTicketFileName("export");
      }
      std::vector<uint8_t> ticket;
      for (unsigned i = 0; i < 200; ++i)
      {
        if (picoquic_save_session_tickets(engine, ticketFile.c_str()) == 0 &&
            readFile(ticketFile, ticket) && !ticket.empty())
        {
          state.session = std::move(ticket);
          state.proofLabel = "picoquic_ticket_file_and_psk";
          return true;
        }
        advance(1);
      }
    }
    return false;
  }

  bool importResumptionState(const BenchmarkResumptionState& state, bool enableZeroRtt) override
  {
    if constexpr (mode & Mode::client)
    {
      if (state.session.empty())
      {
        return false;
      }
      ticketFile = makeTicketFileName("import");
      if (!writeFile(ticketFile, state.session))
      {
        return false;
      }
      importedResumption = true;
      importedZeroRtt = enableZeroRtt;
      resumedObserved = false;
      zeroRttAttemptedObserved = false;
      zeroRttAcceptedObserved = false;
      createConfiguredEngine(ticketFile.c_str());
      return true;
    }
    return false;
  }

  bool connectionWasResumed(void) const override
  {
    if constexpr (mode & Mode::client)
    {
      return importedResumption && (resumedObserved || (cnx != nullptr && picoquic_tls_is_psk_handshake(cnx) != 0));
    }
    return false;
  }

  bool zeroRttWasAttempted(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved;
  }

  bool zeroRttWasAccepted(void) const override
  {
    if constexpr (mode & Mode::client)
    {
      return importedZeroRtt && zeroRttAttemptedObserved &&
             (zeroRttAcceptedObserved || (cnx != nullptr && cnx->zero_rtt_data_accepted != 0));
    }
    return false;
  }

  bool zeroRttWasRejected(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved && !zeroRttWasAccepted() && ready;
  }

  const char *resumptionProofLabel(void) const override
  {
    return "picoquic_ticket_file_and_psk";
  }
};
