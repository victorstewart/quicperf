#include "tquic.h"

#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <unordered_map>
#include <vector>

#pragma once

template <Mode mode>
class Tquic : public QuicLibrary<mode> {
private:

  using QuicLibrary<mode>::networkHub;

  constexpr static int tquicErrDone = -100;

  quic_config_t *config = nullptr;
  quic_tls_config_t *tlsConfig = nullptr;
  SSL_CTX *sslCtx = nullptr;
  quic_endpoint_t *endpoint = nullptr;
  quic_conn_t *conn = nullptr;
  uint64_t connIndex = std::numeric_limits<uint64_t>::max();
  uint64_t streamId = std::numeric_limits<uint64_t>::max();
  int64_t bytesInFlight = -1;
  std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
  size_t requestBytesRead = 0;
  size_t requestBytesWritten = 0;
  bool connected = false;
  bool closed = false;
  bool importedResumption = false;
  bool importedZeroRtt = false;
  bool resumedObserved = false;
  bool zeroRttObserved = false;
  bool zeroRttRejectedObserved = false;
  std::vector<uint8_t> importedSession;
  std::vector<uint8_t> savedSession;
  bool clientDone = false;
  uint64_t serverDrainDeadlineUs = 0;
  bool requestParsed = false;
  bool uploadFinSent = false;
  uint32_t serverCompletedConnections = 0;
  bool durationTransferMode = false;
  bool durationTransferRunning = false;
  uint64_t durationTransferDeadlineUs = 0;
  uint64_t durationCompletedUnits = 0;
  double durationMeasuredSeconds = 0.0;
  bool genericDurationMode = false;
  bool genericDurationOpening = false;
  bool genericDurationDoneSent = false;
  uint64_t genericDurationControlStreamId = std::numeric_limits<uint64_t>::max();
  uint64_t datagramClientSent = 0;
  uint64_t datagramClientReceived = 0;
  uint64_t datagramClientDrainDeadlineUs = 0;
  bool datagramDoneSignalSent = false;
  bool datagramDoneStreamWritten = false;
  std::vector<uint8_t> datagramClientSeen;
  std::array<uint8_t, benchmarkAppChunkSize> datagramScratch = {};

  enum class GenericPhase : uint8_t {
    sendRequest,
    readRequest,
    sendPayload,
    readPayload,
    sendResponse,
    readResponse,
    complete
  };

  struct GenericStreamState {
    uint64_t streamId = std::numeric_limits<uint64_t>::max();
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
    bool writeClosed = false;
    bool complete = false;
  };

  struct ServerStreamState {
    Tquic<mode> *owner = nullptr;
    quic_conn_t *conn = nullptr;
    uint64_t streamId = std::numeric_limits<uint64_t>::max();
    int64_t bytesInFlight = -1;
    std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
    size_t requestBytesRead = 0;
    bool clientDone = false;
    uint64_t serverDrainDeadlineUs = 0;
    bool requestParsed = false;
    bool uploadFinSent = false;
    bool durationMode = false;
    bool closed = false;
    bool complete = false;
    uint64_t datagramReceived = 0;
    uint64_t datagramEchoed = 0;
    std::deque<uint64_t> datagramPendingEchoes;
    std::vector<uint8_t> datagramSeen;
    uint64_t datagramDrainDeadlineUs = 0;
    std::unordered_map<uint64_t, GenericStreamState> genericStreams;
    uint64_t genericCompletedStreams = 0;
    uint64_t genericDurationServerDeadlineUs = 0;
  };

  std::vector<std::unique_ptr<ServerStreamState>> serverStates;
  std::unordered_map<uint64_t, GenericStreamState> genericClientStreams;
  bool genericStarted = false;
  uint64_t genericClientBytes = 0;
  uint64_t genericRequestedStreams = 0;
  uint64_t genericOpenedStreams = 0;
  uint64_t genericCompletedStreams = 0;

  constexpr static std::array<uint8_t, 48> ticketKey = {
      0x71,
      0x75,
      0x69,
      0x63,
      0x70,
      0x65,
      0x72,
      0x66,
      0x2d,
      0x74,
      0x71,
      0x75,
      0x69,
      0x63,
      0x2d,
      0x30,
      0x72,
      0x74,
      0x74,
      0x2d,
      0x72,
      0x65,
      0x73,
      0x75,
      0x6d,
      0x65,
      0x2d,
      0x6c,
      0x6f,
      0x6f,
      0x70,
      0x62,
      0x61,
      0x63,
      0x6b,
      0x2d,
      0x74,
      0x69,
      0x63,
      0x6b,
      0x65,
      0x74,
      0x2d,
      0x6b,
      0x65,
      0x79,
      0x21,
      0x21,
  };

  static void appendU64BE(std::vector<uint8_t>& out, uint64_t value)
  {
    uint64_t swapped = bswap_64(value);
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&swapped);
    out.insert(out.end(), bytes, bytes + sizeof(swapped));
  }

  static int sslCtxSelfIndex(void)
  {
    static int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
  }

  static int saveSession(SSL *ssl, SSL_SESSION *session)
  {
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    auto self = ctx == nullptr
                    ? nullptr
                    : static_cast<Tquic<mode> *>(SSL_CTX_get_ex_data(ctx, sslCtxSelfIndex()));
    if (self == nullptr)
    {
      return 0;
    }

    uint8_t *sessionOut = nullptr;
    size_t sessionLen = 0;
    if (SSL_SESSION_to_bytes(session, &sessionOut, &sessionLen) == 0)
    {
      return 0;
    }
    std::vector<uint8_t> sessionBytes(sessionOut, sessionOut + sessionLen);
    OPENSSL_free(sessionOut);

    const uint8_t *transportParams = nullptr;
    size_t transportParamsLen = 0;
    SSL_get_peer_quic_transport_params(ssl, &transportParams, &transportParamsLen);

    std::vector<uint8_t> serialized;
    serialized.reserve(16 + sessionBytes.size() + transportParamsLen);
    appendU64BE(serialized, sessionBytes.size());
    serialized.insert(serialized.end(), sessionBytes.begin(), sessionBytes.end());
    appendU64BE(serialized, transportParamsLen);
    if (transportParams != nullptr && transportParamsLen > 0)
    {
      serialized.insert(serialized.end(), transportParams, transportParams + transportParamsLen);
    }
    self->savedSession = std::move(serialized);
    return 1;
  }

  bool perfComplete(void) const
  {
    if constexpr (mode & Mode::server)
    {
      if (benchmarkIsZeroRttReqResp())
      {
        return genericCompletedStreams >= benchmarkGenericServerTargetStreams();
      }
      return serverCompletedConnections >= benchmarkServerTargetConnections;
    }
    else
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        return genericCompletedStreams >= benchmarkGenericStreamsPerConnection() || closed;
      }
      if (benchmarkIsUpload())
      {
        return clientDone || closed;
      }
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        return (datagramClientSendBudgetReached() &&
                datagramDoneSignalSent &&
                datagramDoneStreamWritten &&
                datagramClientDrainDeadlineUs != 0 &&
                timeNowUs() >= datagramClientDrainDeadlineUs) ||
               closed;
      }
      return bytesInFlight == 0 || closed;
    }
  }

  static size_t copyPacketPayload(UDPContext *packet, const quic_packet_out_spec_t& spec)
  {
    size_t length = 0;
    for (size_t i = 0; i < spec.iovlen; ++i)
    {
      const size_t part = spec.iov[i].iov_len;
      if (length + part > MAX_IPV6_UDP_PACKET_SIZE)
      {
        return 0;
      }
      memcpy(packet->buffer() + length, spec.iov[i].iov_base, part);
      length += part;
    }
    return length;
  }

  ServerStreamState *serverStateFor(quic_conn_t *connection)
  {
    auto state = static_cast<ServerStreamState *>(quic_conn_context(connection));
    if (state != nullptr)
    {
      return state;
    }
    auto owned = std::make_unique<ServerStreamState>();
    owned->owner = this;
    owned->conn = connection;
    owned->durationMode = durationModeActive();
    if (owned->durationMode && benchmarkIsUpload())
    {
      owned->serverDrainDeadlineUs =
          timeNowUs() + benchmarkTargetDurationMs * 1000ULL + benchmarkDatagramDrainUs;
    }
    state = owned.get();
    serverStates.push_back(std::move(owned));
    quic_conn_set_context(connection, state);
    return state;
  }

  void markServerStateComplete(ServerStreamState *state)
  {
    if (state == nullptr || state->complete)
    {
      return;
    }
    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      if (!state->clientDone)
      {
        return;
      }
      if (state->datagramDrainDeadlineUs == 0)
      {
        state->datagramDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
        return;
      }
      if (!state->datagramPendingEchoes.empty() && timeNowUs() < state->datagramDrainDeadlineUs)
      {
        return;
      }
      state->datagramPendingEchoes.clear();
      state->complete = true;
      ++serverCompletedConnections;
      return;
    }
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if (state->durationMode && supportsGenericDurationMode(benchmarkScenario))
      {
        const uint64_t nowUs = timeNowUs();
        if (state->genericDurationServerDeadlineUs == 0)
        {
          state->genericDurationServerDeadlineUs =
              nowUs + benchmarkTargetDurationMs * 1000ULL + benchmarkDatagramDrainUs;
        }
        const bool deadlineElapsed = nowUs >= state->genericDurationServerDeadlineUs;
        if (!state->clientDone && !deadlineElapsed)
        {
          return;
        }
        bool allComplete = true;
        for (const auto& item : state->genericStreams)
        {
          if (!item.second.complete)
          {
            allComplete = false;
            break;
          }
        }
        if (!allComplete && !deadlineElapsed)
        {
          if (state->serverDrainDeadlineUs == 0)
          {
            state->serverDrainDeadlineUs = nowUs + benchmarkDatagramDrainUs;
            return;
          }
          if (nowUs < state->serverDrainDeadlineUs)
          {
            return;
          }
        }
        state->complete = true;
        ++serverCompletedConnections;
        return;
      }
      if (state->genericCompletedStreams < benchmarkGenericStreamsPerConnection())
      {
        return;
      }
      state->complete = true;
      ++serverCompletedConnections;
      return;
    }
    if (benchmarkIsUpload())
    {
      if (state->durationMode)
      {
        const bool deadlineElapsed =
            state->serverDrainDeadlineUs != 0 && timeNowUs() >= state->serverDrainDeadlineUs;
        if (!state->clientDone && !state->closed && !deadlineElapsed)
        {
          return;
        }
        if (state->serverDrainDeadlineUs == 0)
        {
          state->serverDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
          return;
        }
      }
      else
      {
        if (!state->closed &&
            (!state->uploadFinSent || state->serverDrainDeadlineUs == 0 || timeNowUs() < state->serverDrainDeadlineUs))
        {
          return;
        }
      }
    }
    else
    {
      if (!state->clientDone && !state->closed)
      {
        return;
      }
      if (state->durationMode && !state->closed && state->serverDrainDeadlineUs == 0)
      {
        state->serverDrainDeadlineUs = timeNowUs() + 100'000;
        return;
      }
      if (!state->closed &&
          (state->serverDrainDeadlineUs == 0 || timeNowUs() < state->serverDrainDeadlineUs))
      {
        return;
      }
    }
    state->complete = true;
    ++serverCompletedConnections;
  }

  size_t datagramPayloadSize(void) const
  {
    constexpr size_t sequenceBytes = sizeof(uint64_t);
    const size_t payloadSize = benchmarkDatagramPayloadBytesForNoMssApiLimit(
        benchmarkAppChunkSize,
        benchmarkUdpPayloadSize,
        sequenceBytes);
    if (payloadSize < sequenceBytes)
    {
      fprintf(stderr, "tquic DATAGRAM negotiated payload limit too small: %zu\n", payloadSize);
      abort();
    }
    return payloadSize;
  }

  static void encodeDatagramSequence(uint64_t sequence, uint8_t *out)
  {
    uint64_t swapped = bswap_64(sequence);
    memcpy(out, &swapped, sizeof(swapped));
  }

  static uint64_t decodeDatagramSequence(const uint8_t *data, size_t length)
  {
    if (length < sizeof(uint64_t))
    {
      return std::numeric_limits<uint64_t>::max();
    }
    uint64_t swapped = 0;
    memcpy(&swapped, data, sizeof(swapped));
    return bswap_64(swapped);
  }

  void fillDatagramPayload(uint64_t sequence)
  {
    const size_t payloadSize = datagramPayloadSize();
    memcpy(datagramScratch.data(), networkHub->junk, payloadSize);
    encodeDatagramSequence(sequence, datagramScratch.data());
  }

  static bool markDatagramSeen(std::vector<uint8_t>& seen, uint64_t sequence)
  {
    return benchmarkMarkDatagramSeen(seen, sequence);
  }

  bool sendClientDatagrams(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram ||
          conn == nullptr ||
          !connected ||
          closed)
      {
        return false;
      }
      if (!datagramClientSendBudgetOpen())
      {
        if (datagramClientSendBudgetReached())
        {
          quic_stream_wantwrite(conn, streamId, true);
        }
        return false;
      }

      const size_t payloadSize = datagramPayloadSize();
      const uint64_t burstLimit = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
      uint64_t sentThisCall = 0;
      bool progressed = false;
      while (datagramClientSendBudgetOpen() && sentThisCall < burstLimit)
      {
        fillDatagramPayload(datagramClientSent);
        ssize_t written = quic_datagram_write(
            conn,
            0,
            datagramScratch.data(),
            payloadSize,
            0);
        if (written == tquicErrDone)
        {
          break;
        }
        if (written <= 0)
        {
          break;
        }
        ++datagramClientSent;
        ++sentThisCall;
        progressed = true;
      }
      if (datagramClientSendBudgetReached())
      {
        quic_stream_wantwrite(conn, streamId, true);
      }
      return progressed;
    }
    return false;
  }

  void maybeStartDatagramClientDrain(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram ||
          !datagramClientSendBudgetReached() ||
          !datagramDoneStreamWritten)
      {
        return;
      }
      if (datagramClientReceived >= datagramClientSent)
      {
        datagramClientDrainDeadlineUs = timeNowUs();
      }
      else if (datagramClientDrainDeadlineUs == 0)
      {
        datagramClientDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
      }
    }
  }

  bool sendDatagramDoneSignal(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (datagramDoneSignalSent && datagramDoneStreamWritten)
      {
        return true;
      }
      if (conn == nullptr || streamId == std::numeric_limits<uint64_t>::max())
      {
        return false;
      }
      if (!datagramClientSendBudgetReached())
      {
        quic_stream_wantwrite(conn, streamId, false);
        return false;
      }
      datagramDoneSignalSent = true;
      uint8_t done = 0;
      ssize_t written = quic_stream_write(conn, streamId, &done, 0, true);
      if (written == tquicErrDone || written < 0)
      {
        quic_stream_wantwrite(conn, streamId, true);
        return false;
      }
      datagramDoneStreamWritten = true;
      quic_stream_wantwrite(conn, streamId, false);
      maybeStartDatagramClientDrain();
      drainIouringSends();
      return true;
    }
    return false;
  }

  bool flushServerDatagramEchoes(ServerStreamState *state)
  {
    if constexpr (mode & Mode::server)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram ||
          state == nullptr ||
          state->conn == nullptr)
      {
        return false;
      }
      const size_t payloadSize = datagramPayloadSize();
      bool progressed = false;
      while (!state->datagramPendingEchoes.empty())
      {
        fillDatagramPayload(state->datagramPendingEchoes.front());
        ssize_t written = quic_datagram_write(
            state->conn,
            0,
            datagramScratch.data(),
            payloadSize,
            0);
        if (written == tquicErrDone)
        {
          break;
        }
        if (written <= 0)
        {
          break;
        }
        state->datagramPendingEchoes.pop_front();
        ++state->datagramEchoed;
        progressed = true;
      }
      markServerStateComplete(state);
      return progressed;
    }
    return false;
  }

  bool flushServerDatagramEchoes(void)
  {
    if constexpr (mode & Mode::server)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram)
      {
        return false;
      }
      bool progressed = false;
      for (auto& state : serverStates)
      {
        progressed = flushServerDatagramEchoes(state.get()) || progressed;
      }
      return progressed;
    }
    return false;
  }

  void readDatagrams(quic_conn_t *connection)
  {
    std::array<uint8_t, benchmarkAppChunkSize> buffer = {};
    while (true)
    {
      ssize_t read = quic_datagram_read(connection, buffer.data(), buffer.size());
      if (read <= 0)
      {
        break;
      }
      if constexpr (mode & Mode::server)
      {
        auto state = serverStateFor(connection);
        const uint64_t sequence = decodeDatagramSequence(buffer.data(), static_cast<size_t>(read));
        if (markDatagramSeen(state->datagramSeen, sequence))
        {
          ++state->datagramReceived;
          state->datagramPendingEchoes.push_back(sequence);
        }
        flushServerDatagramEchoes(state);
      }
      else
      {
        const uint64_t sequence = decodeDatagramSequence(buffer.data(), static_cast<size_t>(read));
        if (markDatagramSeen(datagramClientSeen, sequence))
        {
          ++datagramClientReceived;
        }
        maybeStartDatagramClientDrain();
      }
    }
    if constexpr (mode & Mode::client)
    {
      sendClientDatagrams();
      if (datagramClientSendBudgetReached())
      {
        sendDatagramDoneSignal();
      }
    }
  }

  static void onDatagramReadable(void *context, quic_conn_t *connection)
  {
    auto self = static_cast<Tquic<mode> *>(context);
    self->readDatagrams(connection);
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

  void resetDurationTransferState(void)
  {
    durationTransferMode = true;
    durationTransferRunning = false;
    durationTransferDeadlineUs = 0;
    durationCompletedUnits = 0;
    durationMeasuredSeconds = 0.0;
    bytesInFlight = 0;
    requestBytesRead = 0;
    requestBytesWritten = 0;
    clientDone = false;
    uploadFinSent = false;
    requestParsed = false;
    encodeU64(durationTransferRequest(), requestBytes);
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

  GenericStreamState makeGenericClientStream(uint64_t activeStreamId)
  {
    GenericStreamState state = {};
    state.streamId = activeStreamId;
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
    return state;
  }

  static GenericStreamState makeGenericServerStream(uint64_t activeStreamId)
  {
    GenericStreamState state = {};
    state.streamId = activeStreamId;
    state.phase = GenericPhase::readRequest;
    return state;
  }

  GenericStreamState *registerGenericClientStream(uint64_t activeStreamId)
  {
    auto found = genericClientStreams.find(activeStreamId);
    if (found != genericClientStreams.end())
    {
      return &found->second;
    }
    auto inserted = genericClientStreams.emplace(activeStreamId, makeGenericClientStream(activeStreamId));
    return &inserted.first->second;
  }

  GenericStreamState *registerGenericServerStream(ServerStreamState& connState, uint64_t activeStreamId)
  {
    auto found = connState.genericStreams.find(activeStreamId);
    if (found != connState.genericStreams.end())
    {
      return &found->second;
    }
    auto inserted = connState.genericStreams.emplace(activeStreamId, makeGenericServerStream(activeStreamId));
    return &inserted.first->second;
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
    openMoreGenericClientStreams();
  }

  void markGenericServerComplete(ServerStreamState& connState, GenericStreamState *streamState)
  {
    if (streamState == nullptr || streamState->complete)
    {
      return;
    }
    streamState->complete = true;
    streamState->phase = GenericPhase::complete;
    ++connState.genericCompletedStreams;
    ++genericCompletedStreams;
    if (connState.durationMode && supportsGenericDurationMode(benchmarkScenario) && connState.clientDone)
    {
      connState.serverDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
    }
    markServerStateComplete(&connState);
  }

  bool genericClientCompletesOnTerminalFin(void) const
  {
    return benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario);
  }

  void openMoreGenericClientStreams(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (!genericStarted || !benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) || conn == nullptr)
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
          genericDurationMode ? std::numeric_limits<uint64_t>::max() : benchmarkGenericStreamsPerConnection();
      const uint64_t maxActive =
          benchmarkScenario == BenchmarkScenario::bidi
              ? 1
              : std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
      uint64_t active = 0;
      for (const auto& item : genericClientStreams)
      {
        if (!item.second.complete)
        {
          ++active;
        }
      }
      while (genericRequestedStreams < targetStreams && active < maxActive)
      {
        uint64_t activeStreamId = std::numeric_limits<uint64_t>::max();
        if (quic_stream_bidi_new(conn, 0, false, &activeStreamId) != 0)
        {
          break;
        }
        ++genericRequestedStreams;
        GenericStreamState *state = registerGenericClientStream(activeStreamId);
        quic_stream_set_context(conn, activeStreamId, state);
        quic_stream_wantread(conn, activeStreamId, true);
        quic_stream_wantwrite(conn, activeStreamId, true);
        ++active;
      }
    }
  }

  bool isClientGenericDurationControlStream(uint64_t id) const
  {
    if constexpr (mode & Mode::client)
    {
      return genericDurationControlStreamId != std::numeric_limits<uint64_t>::max() &&
             id == genericDurationControlStreamId;
    }
    return false;
  }

  bool genericClientHasActiveStreams(void) const
  {
    for (const auto& item : genericClientStreams)
    {
      if (!item.second.complete)
      {
        return true;
      }
    }
    return false;
  }

  void maybeCountGenericDurationUnit(GenericStreamState& state)
  {
    if (!genericDurationMode ||
        state.durationCounted ||
        state.responseRemaining != 0 ||
        !supportsSmallGenericDurationMode(benchmarkScenario) ||
        !durationTransferRunning ||
        durationTransferDeadlineUs == 0 ||
        timeNowUs() > durationTransferDeadlineUs)
    {
      return;
    }
    state.durationCounted = true;
    ++durationCompletedUnits;
  }

  static int sendPackets(void *context, quic_packet_out_spec_t *pkts, unsigned int count)
  {
    auto self = static_cast<Tquic<mode> *>(context);
    MultiUDPContext *batch = nullptr;
    unsigned int sent = 0;

    for (; sent < count; ++sent)
    {
      if (batch == nullptr)
      {
        batch = self->networkHub->sendPool.get();
        if (batch == nullptr)
        {
          break;
        }
      }

      UDPContext *packet = &batch->msgs[batch->count];
      const size_t length = copyPacketPayload(packet, pkts[sent]);
      if (length == 0 || pkts[sent].dst_addr == nullptr)
      {
        break;
      }

      packet->setLength(length);
      packet->copyInAddress(static_cast<const struct sockaddr *>(pkts[sent].dst_addr));
      ++batch->count;

      if (batch->isFull())
      {
        self->networkHub->sendBatch(batch);
        batch = nullptr;
      }
    }

    if (batch != nullptr)
    {
      if (batch->count > 0)
      {
        self->networkHub->sendBatch(batch);
      }
      else
      {
        batch->reset();
        self->networkHub->sendPool.relinquish(batch);
      }
    }

    return static_cast<int>(sent);
  }

  static void onConnCreated(void *context, quic_conn_t *connection)
  {
    auto self = static_cast<Tquic<mode> *>(context);
    if constexpr (mode & Mode::server)
    {
      self->serverStateFor(connection);
    }
    else
    {
      self->conn = connection;
    }
  }

  static void onConnEstablished(void *context, quic_conn_t *connection)
  {
    auto self = static_cast<Tquic<mode> *>(context);
    if constexpr (mode & Mode::server)
    {
      self->serverStateFor(connection);
    }
    else
    {
      self->conn = connection;
      self->connected = true;
      self->resumedObserved = quic_conn_is_resumed(connection);
      const uint8_t *reason = nullptr;
      size_t reasonLen = 0;
      if (quic_conn_early_data_reason_string(connection, &reason, &reasonLen) == 0 &&
          reason != nullptr && reasonLen > 0 &&
          (reasonLen != strlen("accepted") || memcmp(reason, "accepted", reasonLen) != 0))
      {
        self->zeroRttRejectedObserved = true;
      }
    }
  }

  static void onConnClosed(void *context, quic_conn_t *connection)
  {
    auto self = static_cast<Tquic<mode> *>(context);
    if constexpr (mode & Mode::server)
    {
      auto state = self->serverStateFor(connection);
      state->closed = true;
      self->markServerStateComplete(state);
    }
    else if (self->conn == connection)
    {
      const uint8_t *session = nullptr;
      size_t sessionLen = 0;
      quic_conn_session(connection, &session, &sessionLen);
      if (session != nullptr && sessionLen > 0)
      {
        self->savedSession.assign(session, session + sessionLen);
      }
      self->closed = true;
    }
  }

  static void onStreamCreated(void *context, quic_conn_t *connection, uint64_t id)
  {
    auto self = static_cast<Tquic<mode> *>(context);
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if constexpr (mode & Mode::server)
      {
        auto connState = self->serverStateFor(connection);
        auto streamState = self->registerGenericServerStream(*connState, id);
        quic_stream_set_context(connection, id, streamState);
      }
      else
      {
        self->conn = connection;
        if (self->isClientGenericDurationControlStream(id))
        {
          quic_stream_wantread(connection, id, false);
          quic_stream_wantwrite(connection, id, false);
          return;
        }
        if (self->genericStarted)
        {
          auto streamState = self->registerGenericClientStream(id);
          quic_stream_set_context(connection, id, streamState);
          quic_stream_wantwrite(connection, id, true);
        }
      }
      quic_stream_wantread(connection, id, true);
      return;
    }
    if constexpr (mode & Mode::server)
    {
      auto state = self->serverStateFor(connection);
      state->streamId = id;
    }
    else
    {
      self->conn = connection;
      self->streamId = id;
    }
    quic_stream_wantread(connection, id, true);
  }

  static void onStreamReadable(void *context, quic_conn_t *connection, uint64_t id)
  {
    auto self = static_cast<Tquic<mode> *>(context);
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if constexpr (mode & Mode::server)
      {
        auto connState = self->serverStateFor(connection);
        auto streamState = static_cast<GenericStreamState *>(quic_stream_context(connection, id));
        if (streamState == nullptr)
        {
          streamState = self->registerGenericServerStream(*connState, id);
          quic_stream_set_context(connection, id, streamState);
        }
        self->readServerGenericStream(*connState, *streamState, connection, id);
      }
      else
      {
        if (self->isClientGenericDurationControlStream(id))
        {
          quic_stream_wantread(connection, id, false);
          return;
        }
        auto streamState = static_cast<GenericStreamState *>(quic_stream_context(connection, id));
        if (streamState == nullptr)
        {
          streamState = self->registerGenericClientStream(id);
          quic_stream_set_context(connection, id, streamState);
        }
        self->readClientGenericStream(*streamState, connection, id);
      }
      return;
    }
    if constexpr (mode & Mode::server)
    {
      self->readServerStream(*self->serverStateFor(connection), connection, id);
    }
    else
    {
      self->readStream(connection, id);
    }
  }

  static void onStreamWritable(void *context, quic_conn_t *connection, uint64_t id)
  {
    auto self = static_cast<Tquic<mode> *>(context);
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if constexpr (mode & Mode::server)
      {
        auto connState = self->serverStateFor(connection);
        auto streamState = static_cast<GenericStreamState *>(quic_stream_context(connection, id));
        if (streamState == nullptr)
        {
          streamState = self->registerGenericServerStream(*connState, id);
          quic_stream_set_context(connection, id, streamState);
        }
        self->writeServerGenericStream(*connState, *streamState, connection, id);
      }
      else
      {
        if (self->isClientGenericDurationControlStream(id))
        {
          quic_stream_wantwrite(connection, id, false);
          return;
        }
        auto streamState = static_cast<GenericStreamState *>(quic_stream_context(connection, id));
        if (streamState == nullptr)
        {
          streamState = self->registerGenericClientStream(id);
          quic_stream_set_context(connection, id, streamState);
        }
        self->writeClientGenericStream(*streamState, connection, id);
      }
      return;
    }
    if constexpr (mode & Mode::server)
    {
      self->writeServerStream(*self->serverStateFor(connection), connection, id);
    }
    else
    {
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        self->sendDatagramDoneSignal();
        return;
      }
      self->writeStream(connection, id);
    }
  }

  static void onStreamClosed(void *context, quic_conn_t *connection, uint64_t id)
  {
    auto self = static_cast<Tquic<mode> *>(context);
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      auto streamState = static_cast<GenericStreamState *>(quic_stream_context(connection, id));
      if constexpr (mode & Mode::server)
      {
        if (streamState != nullptr && streamState->ackBytesWritten >= 1)
        {
          self->markGenericServerComplete(*self->serverStateFor(connection), streamState);
        }
      }
      else
      {
        if (self->isClientGenericDurationControlStream(id))
        {
          return;
        }
        if (streamState != nullptr &&
            (streamState->ackBytesRead >= 1 ||
             (streamState->writeClosed && streamState->responseRemaining == 0)))
        {
          self->markGenericClientComplete(streamState);
        }
      }
      return;
    }
    if constexpr (mode & Mode::server)
    {
      auto state = self->serverStateFor(connection);
      if (state->streamId == id)
      {
        state->clientDone = true;
        self->markServerStateComplete(state);
      }
    }
    else if (self->streamId == id)
    {
      self->clientDone = true;
    }
  }

  void readClientGenericStream(GenericStreamState& state, quic_conn_t *connection, uint64_t id)
  {
    std::array<uint8_t, benchmarkAppChunkSize> buffer = {};

    while (true)
    {
      bool fin = false;
      ssize_t read = quic_stream_read(connection, id, buffer.data(), buffer.size(), &fin);
      if (read == tquicErrDone)
      {
        break;
      }
      if (read < 0)
      {
        break;
      }

      size_t consumed = 0;
      if (state.responseRemaining > 0)
      {
        const uint64_t copied = std::min<uint64_t>(
            state.responseRemaining, static_cast<uint64_t>(read));
        state.responseRemaining -= copied;
        consumed += static_cast<size_t>(copied);
        if (genericDurationMode &&
            supportsByteGenericDurationMode(benchmarkScenario) &&
            (benchmarkScenario == BenchmarkScenario::multistream_download ||
             benchmarkScenario == BenchmarkScenario::bidi) &&
            durationTransferRunning &&
            durationTransferDeadlineUs != 0 &&
            timeNowUs() <= durationTransferDeadlineUs)
        {
          durationCompletedUnits += copied;
        }
        if (state.responseRemaining == 0)
        {
          state.phase = GenericPhase::sendPayload;
          maybeCountGenericDurationUnit(state);
          quic_stream_wantwrite(connection, id, true);
        }
      }

      if (state.writeClosed && state.ackBytesRead < 1 && consumed < static_cast<size_t>(read))
      {
        const size_t copied = std::min<size_t>(
            1 - state.ackBytesRead, static_cast<size_t>(read) - consumed);
        state.ackBytesRead += copied;
        consumed += copied;
      }

      if (state.ackBytesRead >= 1)
      {
        quic_stream_wantread(connection, id, false);
        quic_stream_wantwrite(connection, id, false);
        markGenericClientComplete(&state);
      }

      if (fin)
      {
        if (state.writeClosed && state.responseRemaining == 0)
        {
          quic_stream_wantread(connection, id, false);
          quic_stream_wantwrite(connection, id, false);
          markGenericClientComplete(&state);
        }
        break;
      }
    }
  }

  void readServerGenericStream(ServerStreamState& connState, GenericStreamState& state, quic_conn_t *connection, uint64_t id)
  {
    if (state.complete)
    {
      return;
    }

    std::array<uint8_t, benchmarkAppChunkSize> buffer = {};

    while (true)
    {
      bool fin = false;
      ssize_t read = quic_stream_read(connection, id, buffer.data(), buffer.size(), &fin);
      if (read == tquicErrDone)
      {
        break;
      }
      if (read < 0)
      {
        break;
      }

      size_t consumed = 0;
      if (state.phase == GenericPhase::readRequest)
      {
        if (connState.durationMode &&
            supportsGenericDurationMode(benchmarkScenario) &&
            state.requestBytesRead == 0 &&
            fin &&
            ((read == 0) ||
             (read == 1 && buffer[0] == genericDurationDoneByte())))
        {
          state.controlStream = true;
          state.complete = true;
          state.phase = GenericPhase::complete;
          connState.clientDone = true;
          quic_stream_wantread(connection, id, false);
          quic_stream_wantwrite(connection, id, false);
          markServerStateComplete(&connState);
          break;
        }
        if (connState.durationMode && connState.clientDone && consumed > 0)
        {
          connState.serverDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
        }
        if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
        {
          if (state.requestBytesExpected == 0)
          {
            state.requestBytesExpected = benchmarkGenericReqRespRequestBytes();
          }
          const uint64_t copied = std::min<uint64_t>(
              state.requestBytesExpected - state.requestBytesRead,
              static_cast<uint64_t>(read));
          state.requestBytesRead += copied;
          consumed += static_cast<size_t>(copied);
          if (state.requestBytesRead == state.requestBytesExpected)
          {
            state.responseRemaining = benchmarkGenericReqRespResponseBytes();
            state.phase = GenericPhase::sendResponse;
            quic_stream_wantwrite(connection, id, true);
          }
        }
        else
        {
          while (state.requestBytesRead < state.requestBytes.size() && consumed < static_cast<size_t>(read))
          {
            state.requestBytes[state.requestBytesRead++] = buffer[consumed++];
          }
          if (state.requestBytesRead == state.requestBytes.size())
          {
            state.requestValue = decodeU64(state.requestBytes);
            state.payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                                      benchmarkScenario == BenchmarkScenario::bidi)
                                         ? state.requestValue
                                         : 0;
            state.responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : state.requestValue;
            state.phase = state.payloadRemaining > 0 ? GenericPhase::readPayload : GenericPhase::sendResponse;
            if (state.phase == GenericPhase::sendResponse)
            {
              quic_stream_wantwrite(connection, id, true);
            }
          }
        }
      }

      if ((benchmarkScenario == BenchmarkScenario::multistream_upload ||
           benchmarkScenario == BenchmarkScenario::bidi) &&
          consumed < static_cast<size_t>(read) && state.payloadRemaining > 0)
      {
        const uint64_t copied = std::min<uint64_t>(
            state.payloadRemaining,
            static_cast<uint64_t>(read) - consumed);
        state.payloadRemaining -= copied;
        consumed += static_cast<size_t>(copied);
        if (connState.durationMode && connState.clientDone && copied > 0)
        {
          connState.serverDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
        }
        if (state.payloadRemaining == 0)
        {
          state.phase = GenericPhase::sendResponse;
          quic_stream_wantwrite(connection, id, true);
        }
      }

      if (state.phase == GenericPhase::readResponse && consumed < static_cast<size_t>(read))
      {
        const size_t copied = std::min<size_t>(
            1 - state.doneBytesRead, static_cast<size_t>(read) - consumed);
        state.doneBytesRead += copied;
        consumed += copied;
        if (state.doneBytesRead >= 1)
        {
          quic_stream_wantwrite(connection, id, true);
        }
      }

      if (fin)
      {
        if (state.phase == GenericPhase::readResponse &&
            benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario) &&
            state.doneBytesRead == 0)
        {
          state.doneBytesRead = 1;
          quic_stream_wantwrite(connection, id, true);
        }
        break;
      }
    }
  }

  void writeClientGenericStream(GenericStreamState& state, quic_conn_t *connection, uint64_t id)
  {
    if constexpr (mode & Mode::client)
    {
      if (state.complete || state.writeClosed)
      {
        return;
      }

      while (state.requestBytesWritten < state.requestBytesExpected)
      {
        const size_t left = static_cast<size_t>(state.requestBytesExpected - state.requestBytesWritten);
        const uint8_t *source = nullptr;
        if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
        {
          source = reinterpret_cast<const uint8_t *>(networkHub->junk);
        }
        else
        {
          source = state.requestBytes.data() + state.requestBytesWritten;
        }
        const size_t chunk = std::min<size_t>(left, sizeof(networkHub->junk));
        ssize_t written = quic_stream_write(connection, id, source, chunk, false);
        if (written == tquicErrDone)
        {
          break;
        }
        if (written <= 0)
        {
          break;
        }
        state.requestBytesWritten += static_cast<uint64_t>(written);
      }
      if (state.requestBytesWritten < state.requestBytesExpected)
      {
        return;
      }

      while (state.payloadRemaining > 0)
      {
        const size_t chunk = static_cast<size_t>(
            std::min<uint64_t>(state.payloadRemaining, sizeof(networkHub->junk)));
        ssize_t written = quic_stream_write(connection, id, networkHub->junk, chunk, false);
        if (written == tquicErrDone)
        {
          break;
        }
        if (written <= 0)
        {
          break;
        }
        state.payloadRemaining -= static_cast<uint64_t>(written);
        if (genericDurationMode &&
            supportsByteGenericDurationMode(benchmarkScenario) &&
            (benchmarkScenario == BenchmarkScenario::multistream_upload ||
             benchmarkScenario == BenchmarkScenario::bidi) &&
            durationTransferRunning &&
            durationTransferDeadlineUs != 0 &&
            timeNowUs() <= durationTransferDeadlineUs)
        {
          durationCompletedUnits += static_cast<uint64_t>(written);
        }
      }
      if (state.payloadRemaining > 0)
      {
        return;
      }

      if (state.responseRemaining == 0 && state.doneBytesWritten == 0)
      {
        uint8_t done = 0;
        ssize_t written = quic_stream_write(connection, id, &done, sizeof(done), true);
        if (written > 0)
        {
          state.doneBytesWritten += static_cast<size_t>(written);
          state.writeClosed = true;
          quic_stream_wantwrite(connection, id, false);
          if (genericClientCompletesOnTerminalFin() ||
              benchmarkScenario == BenchmarkScenario::multistream_upload)
          {
            drainIouringSends();
            markGenericClientComplete(&state);
          }
        }
        return;
      }

      quic_stream_wantwrite(connection, id, false);
    }
  }

  void writeServerGenericStream(ServerStreamState& connState, GenericStreamState& state, quic_conn_t *connection, uint64_t id)
  {
    if (state.complete)
    {
      return;
    }
    if (state.phase == GenericPhase::readResponse && state.doneBytesRead > 0 && state.ackBytesWritten < 1)
    {
      uint8_t ack = 0;
      ssize_t written = quic_stream_write(connection, id, &ack, sizeof(ack), true);
      if (written > 0)
      {
        state.ackBytesWritten += static_cast<size_t>(written);
        quic_stream_wantwrite(connection, id, false);
        if (connState.durationMode && connState.clientDone)
        {
          connState.serverDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
        }
        drainIouringSends();
        markGenericServerComplete(connState, &state);
      }
      return;
    }
    if (state.phase != GenericPhase::sendResponse)
    {
      return;
    }

    while (state.responseRemaining > 0)
    {
      const size_t chunk = static_cast<size_t>(
          std::min<uint64_t>(state.responseRemaining, sizeof(networkHub->junk)));
      ssize_t written = quic_stream_write(connection, id, networkHub->junk, chunk, false);
      if (written == tquicErrDone)
      {
        break;
      }
      if (written <= 0)
      {
        break;
      }
      state.responseRemaining -= static_cast<uint64_t>(written);
      if (connState.durationMode && connState.clientDone)
      {
        connState.serverDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
      }
    }

    if (state.responseRemaining == 0)
    {
      state.writeClosed = true;
      state.phase = GenericPhase::readResponse;
      quic_stream_wantwrite(connection, id, false);
      quic_stream_wantread(connection, id, true);
    }
  }

  void readStream(quic_conn_t *connection, uint64_t id)
  {
    std::array<uint8_t, benchmarkAppChunkSize> buffer = {};

    while (true)
    {
      bool fin = false;
      ssize_t read = quic_stream_read(connection, id, buffer.data(), buffer.size(), &fin);
      if (read == tquicErrDone)
      {
        break;
      }
      if (read < 0)
      {
        break;
      }

      if constexpr (mode & Mode::client)
      {
        if (benchmarkIsUpload())
        {
          if (read > 0 || fin)
          {
            clientDone = true;
          }
        }
        if (durationTransferMode && !benchmarkIsUpload())
        {
          if (durationTransferRunning && read > 0)
          {
            durationCompletedUnits += static_cast<uint64_t>(read);
          }
          if (fin)
          {
            clientDone = true;
            break;
          }
          continue;
        }
        if (bytesInFlight > 0)
        {
          bytesInFlight -= std::min<int64_t>(bytesInFlight, read);
          if (bytesInFlight == 0)
          {
            uint8_t empty = 0;
            quic_stream_write(connection, id, &empty, 0, true);
            clientDone = true;
          }
        }
      }
      else
      {
        size_t consumed = 0;
        while (requestBytesRead < requestBytes.size() && consumed < static_cast<size_t>(read))
        {
          requestBytes[requestBytesRead++] = buffer[consumed++];
        }

        if (requestBytesRead == requestBytes.size() && bytesInFlight < 0)
        {
          const uint64_t requested = decodeU64(requestBytes);
          durationTransferMode = durationModeActive() && requested == durationTransferRequest();
          bytesInFlight = durationTransferMode
                              ? (benchmarkIsUpload() ? 0 : INT64_MAX)
                              : static_cast<int64_t>(requested);
          requestParsed = true;
          if (!benchmarkIsUpload())
          {
            quic_stream_wantwrite(connection, id, true);
          }
        }

        if (benchmarkIsUpload() && requestParsed && consumed < static_cast<size_t>(read))
        {
          if (!durationTransferMode)
          {
            bytesInFlight -= std::min<int64_t>(bytesInFlight, static_cast<int64_t>(read - consumed));
          }
          if (durationTransferMode || bytesInFlight == 0)
          {
            writeStream(connection, id);
          }
        }
      }

      if (fin)
      {
        clientDone = true;
        break;
      }
    }
  }

  void readServerStream(ServerStreamState& state, quic_conn_t *connection, uint64_t id)
  {
    std::array<uint8_t, benchmarkAppChunkSize> buffer = {};

    while (true)
    {
      bool fin = false;
      ssize_t read = quic_stream_read(connection, id, buffer.data(), buffer.size(), &fin);
      if (read == tquicErrDone)
      {
        break;
      }
      if (read < 0)
      {
        break;
      }

      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        if (read > 0 || fin)
        {
          state.clientDone = true;
        }
        if (fin)
        {
          quic_stream_wantread(connection, id, false);
          markServerStateComplete(&state);
          break;
        }
        markServerStateComplete(&state);
        continue;
      }

      size_t consumed = 0;
      while (state.requestBytesRead < state.requestBytes.size() && consumed < static_cast<size_t>(read))
      {
        state.requestBytes[state.requestBytesRead++] = buffer[consumed++];
      }

      if (state.requestBytesRead == state.requestBytes.size() && state.bytesInFlight < 0)
      {
        const uint64_t requested = decodeU64(state.requestBytes);
        state.durationMode = durationModeActive() && requested == durationTransferRequest();
        state.bytesInFlight = state.durationMode
                                  ? (benchmarkIsUpload() ? 0 : INT64_MAX)
                                  : static_cast<int64_t>(requested);
        state.requestParsed = true;
        if (benchmarkIsUpload() && state.durationMode && state.serverDrainDeadlineUs == 0)
        {
          state.serverDrainDeadlineUs =
              timeNowUs() + benchmarkTargetDurationMs * 1000ULL + benchmarkDatagramDrainUs;
        }
        if (!benchmarkIsUpload())
        {
          quic_stream_wantwrite(connection, id, true);
        }
      }

      if (benchmarkIsUpload() && state.requestParsed && consumed < static_cast<size_t>(read))
      {
        if (!state.durationMode)
        {
          state.bytesInFlight -= std::min<int64_t>(state.bytesInFlight, static_cast<int64_t>(read - consumed));
        }
        if (state.durationMode || state.bytesInFlight == 0)
        {
          writeServerStream(state, connection, id);
        }
      }

      if (fin)
      {
        state.clientDone = true;
        if (benchmarkIsUpload() && state.durationMode)
        {
          quic_stream_wantwrite(connection, id, true);
          writeServerStream(state, connection, id);
        }
        markServerStateComplete(&state);
        break;
      }
    }
  }

  void writeStream(quic_conn_t *connection, uint64_t id)
  {
    if constexpr (mode & Mode::client)
    {
      while (requestBytesWritten < requestBytes.size())
      {
        ssize_t written = quic_stream_write(
            connection,
            id,
            requestBytes.data() + requestBytesWritten,
            requestBytes.size() - requestBytesWritten,
            false);

        if (written == tquicErrDone)
        {
          break;
        }
        if (written < 0)
        {
          break;
        }

        requestBytesWritten += static_cast<size_t>(written);
      }

      if (requestBytesWritten == requestBytes.size())
      {
        if (durationTransferMode)
        {
          const uint64_t burstLimit =
              static_cast<uint64_t>(sizeof(networkHub->junk)) * benchmarkUdpBatchSize;
          uint64_t sentThisCall = 0;
          if (benchmarkIsUpload() && durationTransferRunning)
          {
            while (bytesInFlight > 0 && sentThisCall < burstLimit)
            {
              const size_t sendLength = static_cast<size_t>(
                  std::min<int64_t>(bytesInFlight, sizeof(networkHub->junk)));

              ssize_t written = quic_stream_write(
                  connection,
                  id,
                  networkHub->junk,
                  sendLength,
                  false);

              if (written == tquicErrDone)
              {
                break;
              }
              if (written <= 0)
              {
                break;
              }

              bytesInFlight -= written;
              durationCompletedUnits += static_cast<uint64_t>(written);
              sentThisCall += static_cast<uint64_t>(written);
            }
            return;
          }

          if (durationTransferDeadlineUs != 0 && !durationTransferRunning)
          {
            if (benchmarkIsUpload() && !uploadFinSent)
            {
              uint8_t empty = 0;
              ssize_t written = quic_stream_write(connection, id, &empty, 0, true);
              if (written != tquicErrDone && written >= 0)
              {
                uploadFinSent = true;
                quic_stream_wantwrite(connection, id, false);
              }
              return;
            }
            if (!benchmarkIsUpload() && !clientDone)
            {
              uint8_t empty = 0;
              ssize_t written = quic_stream_write(connection, id, &empty, 0, true);
              if (written != tquicErrDone && written >= 0)
              {
                clientDone = true;
                quic_stream_wantwrite(connection, id, false);
              }
              return;
            }
          }

          if (!durationTransferRunning)
          {
            quic_stream_wantwrite(connection, id, false);
          }
          return;
        }

        if (benchmarkIsUpload())
        {
          while (bytesInFlight > 0)
          {
            const size_t sendLength = static_cast<size_t>(
                std::min<int64_t>(bytesInFlight, sizeof(networkHub->junk)));
            const bool fin = sendLength == static_cast<size_t>(bytesInFlight);

            ssize_t written = quic_stream_write(
                connection,
                id,
                networkHub->junk,
                sendLength,
                fin);

            if (written == tquicErrDone)
            {
              break;
            }
            if (written < 0)
            {
              break;
            }

            bytesInFlight -= written;
            if (written == 0)
            {
              break;
            }
          }
        }

        if (!benchmarkIsUpload() || bytesInFlight == 0)
        {
          quic_stream_wantwrite(connection, id, false);
        }
      }
    }
  }

  void writeServerStream(ServerStreamState& state, quic_conn_t *connection, uint64_t id)
  {
    if (benchmarkIsUpload())
    {
      if (state.requestParsed &&
          ((state.durationMode && state.clientDone) ||
           (!state.durationMode && state.bytesInFlight == 0)) &&
          !state.uploadFinSent)
      {
        uint8_t ack = 0;
        ssize_t written = quic_stream_write(connection, id, &ack, sizeof(ack), true);
        if (written > 0)
        {
          state.uploadFinSent = true;
          quic_stream_wantwrite(connection, id, false);
          if (state.serverDrainDeadlineUs == 0)
          {
            state.serverDrainDeadlineUs = timeNowUs() + 100'000;
          }
          markServerStateComplete(&state);
        }
      }
      return;
    }

    if (state.durationMode)
    {
      if (state.clientDone)
      {
        quic_stream_wantwrite(connection, id, false);
        markServerStateComplete(&state);
        return;
      }
      const uint64_t burstLimit =
          static_cast<uint64_t>(sizeof(networkHub->junk)) * benchmarkUdpBatchSize;
      uint64_t sentThisCall = 0;
      while (sentThisCall < burstLimit)
      {
        const size_t sendLength = sizeof(networkHub->junk);
        ssize_t written = quic_stream_write(
            connection,
            id,
            networkHub->junk,
            sendLength,
            false);

        if (written == tquicErrDone)
        {
          break;
        }
        if (written <= 0)
        {
          break;
        }
        sentThisCall += static_cast<uint64_t>(written);
      }
      return;
    }

    while (state.bytesInFlight > 0)
    {
      const size_t sendLength = static_cast<size_t>(
          std::min<int64_t>(state.bytesInFlight, sizeof(networkHub->junk)));
      const bool fin = sendLength == static_cast<size_t>(state.bytesInFlight);

      ssize_t written = quic_stream_write(
          connection,
          id,
          networkHub->junk,
          sendLength,
          fin);

      if (written == tquicErrDone)
      {
        break;
      }
      if (written < 0)
      {
        break;
      }

      state.bytesInFlight -= written;
      if (written == 0)
      {
        break;
      }
    }

    if (state.bytesInFlight == 0)
    {
      quic_stream_wantwrite(connection, id, false);
      if (state.serverDrainDeadlineUs == 0)
      {
        state.serverDrainDeadlineUs = timeNowUs() + 100'000;
      }
      markServerStateComplete(&state);
    }
  }

  void drainIouringSends(void)
  {
    if constexpr (mode & Mode::iouring)
    {
      networkHub->flush();
      networkHub->drainSendCompletions();
    }
  }

  void configureTransport(void)
  {
    config = quic_config_new();
    quic_config_set_max_idle_timeout(config, benchmarkIdleTimeoutMs);
    quic_config_set_max_handshake_timeout(config, benchmarkIdleTimeoutMs);
    quic_config_set_recv_udp_payload_size(config, benchmarkUdpPayloadSize);
    enable_dplpmtud(config, false);
    quic_config_set_send_udp_payload_size(config, benchmarkUdpPayloadSize);
    quic_config_set_max_connection_window(config, benchmarkConnectionWindow);
    quic_config_set_max_stream_window(config, benchmarkStreamWindow);
    quic_config_set_initial_max_data(config, benchmarkConnectionWindow);
    quic_config_set_initial_max_stream_data_bidi_local(config, benchmarkStreamWindow);
    quic_config_set_initial_max_stream_data_bidi_remote(config, benchmarkStreamWindow);
    quic_config_set_initial_max_stream_data_uni(config, benchmarkStreamWindow);
    quic_config_set_initial_max_streams_bidi(config, benchmarkMaxBidiStreams);
    quic_config_set_initial_max_streams_uni(config, benchmarkMaxUniStreams);
    quic_config_set_ack_delay_exponent(config, benchmarkAckDelayExponent);
    quic_config_set_max_ack_delay(config, benchmarkMaxAckDelayMs);
    quic_config_set_congestion_control_algorithm(config,
                                                 benchmarkCongestionProfileUsesCubic()
                                                     ? QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC
                                                     : QUIC_CONGESTION_CONTROL_ALGORITHM_BBR);
    if (benchmarkCongestionProfileIsAggressive())
    {
      quic_config_set_initial_congestion_window(config, 32);
    }
    quic_config_enable_pacing(config, true);
    quic_config_set_max_concurrent_conns(config, benchmarkServerTargetConnections);
    quic_config_set_send_batch_size(config, benchmarkUdpBatchSize);
    quic_config_set_max_datagram_frame_size(config, benchmarkUdpPayloadSize);
    quic_config_set_max_datagram_send_queue_size(config, benchmarkDatagramQueueSlots);
    quic_config_set_max_datagram_recv_queue_size(config, benchmarkDatagramQueueSlots);

    const char *protos[] = {"perf"};
    sslCtx = SSL_CTX_new(TLS_method());
    if (sslCtx == nullptr ||
        SSL_CTX_set_min_proto_version(sslCtx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set1_sigalgs_list(sslCtx, "ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256") != 1 ||
        SSL_CTX_set_tlsext_ticket_keys(sslCtx, ticketKey.data(), ticketKey.size()) != 1)
    {
      fprintf(stderr, "tquic: failed to configure benchmark SSL_CTX\n");
      abort();
    }
    SSL_CTX_set_session_cache_mode(sslCtx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(sslCtx, saveSession);
    SSL_CTX_set_early_data_enabled(sslCtx, 1);
    SSL_CTX_set_session_psk_dhe_timeout(sslCtx, benchmarkIdleTimeoutSeconds);
    SSL_CTX_set_num_tickets(sslCtx, 2);
    SSL_CTX_set_ex_data(sslCtx, sslCtxSelfIndex(), this);
    tlsConfig = quic_tls_config_new_with_ssl_ctx(sslCtx);
    if (tlsConfig == nullptr)
    {
      fprintf(stderr, "tquic: failed to wrap benchmark SSL_CTX\n");
      abort();
    }
    if (quic_tls_config_set_application_protos(tlsConfig, protos, 1) != 0)
    {
      fprintf(stderr, "tquic: failed to set ALPN\n");
      abort();
    }
    quic_tls_config_set_early_data_enabled(tlsConfig, true);
    quic_tls_config_set_session_timeout(tlsConfig, benchmarkIdleTimeoutSeconds);
    if constexpr (mode & Mode::server)
    {
      if (quic_tls_config_set_ticket_key(tlsConfig, ticketKey.data(), ticketKey.size()) != 0)
      {
        fprintf(stderr, "tquic: failed to configure session ticket key\n");
        abort();
      }
      if (quic_tls_config_set_certificate_file(tlsConfig, tls_cert) != 0 ||
          quic_tls_config_set_private_key_file(tlsConfig, tls_key) != 0)
      {
        fprintf(stderr, "tquic: failed to load TLS certificate cert=%s key=%s\n", tls_cert, tls_key);
        abort();
      }
    }
    else
    {
      quic_tls_config_set_verify(tlsConfig, benchmarkTlsVerifyPeer());
      if (benchmarkTlsVerifyPeer())
      {
        quic_tls_config_set_ca_certs(tlsConfig, tls_chain);
      }
    }
    quic_config_set_tls_config(config, tlsConfig);
  }

  void advance(int32_t count = 0)
  {
    do
    {
      if constexpr (mode & Mode::client)
      {
        if (conn != nullptr && quic_conn_is_in_early_data(conn))
        {
          zeroRttObserved = true;
        }
      }
      quic_endpoint_process_connections(endpoint);

      const bool sentDatagrams = sendClientDatagrams();
      const bool flushedDatagrams = flushServerDatagramEchoes();
      uint64_t timeoutMs = quic_endpoint_timeout(endpoint);
      if (timeoutMs == 0)
      {
        quic_endpoint_on_timeout(endpoint);
      }

      int64_t timeoutUs = 100'000;
      if (timeoutMs != std::numeric_limits<uint64_t>::max())
      {
        timeoutUs = std::min<uint64_t>(timeoutMs * 1000, 100'000);
      }
      if (sentDatagrams || flushedDatagrams)
      {
        timeoutUs = 0;
      }
      if constexpr (mode & Mode::client)
      {
        if (benchmarkScenario == BenchmarkScenario::datagram &&
            datagramClientDrainDeadlineUs != 0)
        {
          const uint64_t nowUs = timeNowUs();
          timeoutUs = datagramClientDrainDeadlineUs > nowUs
                          ? std::min<int64_t>(timeoutUs, static_cast<int64_t>(datagramClientDrainDeadlineUs - nowUs))
                          : 0;
        }
        if (durationTransferRunning && durationTransferDeadlineUs != 0)
        {
          const uint64_t nowUs = timeNowUs();
          timeoutUs = durationTransferDeadlineUs > nowUs
                          ? std::min<int64_t>(timeoutUs, static_cast<int64_t>(durationTransferDeadlineUs - nowUs))
                          : 0;
        }
      }

      bool timedout = networkHub->recvmsgWithTimeout(timeoutUs, [&](UDPContext *msg) -> void {
        quic_packet_info_t info = {
            .src = msg->address(),
            .src_len = sizeof(struct sockaddr_in6),
            .dst = networkHub->socket.address(),
            .dst_len = networkHub->socket.addressLen,
        };
        quic_endpoint_recv(endpoint, msg->buffer(), msg->msg_len, &info);
      });

      if (timedout)
      {
        quic_endpoint_on_timeout(endpoint);
      }
      if constexpr (mode & Mode::server)
      {
        for (auto& state : serverStates)
        {
          markServerStateComplete(state.get());
        }
      }
    } while (!perfComplete() && (count == 0 || --count > 0));
  }

  void ensureClientStream(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (streamId != std::numeric_limits<uint64_t>::max())
      {
        return;
      }
      quic_stream_bidi_new(conn, 0, false, &streamId);
      quic_stream_wantread(conn, streamId, true);
    }
  }

  void sendDurationRequest(void)
  {
    ensureClientStream();
    quic_stream_wantwrite(conn, streamId, true);
    while (requestBytesWritten < requestBytes.size())
    {
      advance(1);
    }
  }

  void drainDurationCleanup(uint64_t drainUs)
  {
    const uint64_t deadlineUs = timeNowUs() + drainUs;
    while (timeNowUs() < deadlineUs)
    {
      advance(1);
    }
  }

  void sendGenericDurationDone(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (genericDurationDoneSent)
      {
        return;
      }
      uint64_t activeStreamId = std::numeric_limits<uint64_t>::max();
      if (quic_stream_bidi_new(conn, 0, false, &activeStreamId) != 0)
      {
        return;
      }
      genericDurationControlStreamId = activeStreamId;
      const uint8_t done = genericDurationDoneByte();
      for (uint32_t attempt = 0; attempt < 128 && !genericDurationDoneSent; ++attempt)
      {
        ssize_t written = quic_stream_write(conn, activeStreamId, &done, sizeof(done), true);
        if (written > 0)
        {
          genericDurationDoneSent = true;
          quic_stream_wantread(conn, activeStreamId, false);
          quic_stream_wantwrite(conn, activeStreamId, false);
          networkHub->flush();
          break;
        }
        if (written != tquicErrDone && written < 0)
        {
          break;
        }
        advance(1);
      }
    }
  }

  void runClientGenericDuration(uint64_t nBytes)
  {
    genericClientBytes = nBytes;
    genericRequestedStreams = 0;
    genericOpenedStreams = 0;
    genericCompletedStreams = 0;
    genericClientStreams.clear();
    genericStarted = true;
    genericDurationMode = true;
    genericDurationOpening = true;
    genericDurationDoneSent = false;
    genericDurationControlStreamId = std::numeric_limits<uint64_t>::max();
    durationTransferRunning = true;
    durationTransferDeadlineUs = 0;
    durationCompletedUnits = 0;
    durationMeasuredSeconds = 0.0;

    const uint64_t startUs = timeNowUs();
    durationTransferDeadlineUs = durationDeadlineUs(startUs);
    while (timeNowUs() < durationTransferDeadlineUs)
    {
      openMoreGenericClientStreams();
      for (auto& item : genericClientStreams)
      {
        writeClientGenericStream(item.second, conn, item.first);
      }
      advance(1);
    }

    durationTransferRunning = false;
    genericDurationOpening = false;
    const uint64_t measuredEndUs = std::min<uint64_t>(timeNowUs(), durationTransferDeadlineUs);
    recordDurationResult(durationCompletedUnits, startUs, measuredEndUs);

    const uint64_t drainDeadlineUs = timeNowUs() + 500'000;
    while (genericClientHasActiveStreams() && timeNowUs() < drainDeadlineUs)
    {
      for (auto& item : genericClientStreams)
      {
        writeClientGenericStream(item.second, conn, item.first);
      }
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

  void runClientDownloadDuration(void)
  {
    resetDurationTransferState();
    sendDurationRequest();

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

    quic_stream_wantwrite(conn, streamId, true);
    const uint64_t doneDeadlineUs = timeNowUs() + 100'000;
    while (!clientDone && timeNowUs() < doneDeadlineUs)
    {
      advance(1);
    }
    drainDurationCleanup(100'000);
    durationTransferMode = false;
    bytesInFlight = 0;
  }

  void runClientUploadDuration(void)
  {
    resetDurationTransferState();
    sendDurationRequest();

    const uint64_t startUs = timeNowUs();
    durationTransferDeadlineUs = durationDeadlineUs(startUs);
    bytesInFlight = INT64_MAX;
    quic_stream_wantwrite(conn, streamId, true);
    durationTransferRunning = true;
    while (timeNowUs() < durationTransferDeadlineUs)
    {
      advance(1);
    }
    durationTransferRunning = false;
    bytesInFlight = 0;
    const uint64_t measuredEndUs = std::min<uint64_t>(timeNowUs(), durationTransferDeadlineUs);
    recordDurationResult(durationCompletedUnits, startUs, measuredEndUs);

    quic_stream_wantwrite(conn, streamId, true);
    const uint64_t drainDeadlineUs = timeNowUs() + 1'000'000;
    while (!clientDone && timeNowUs() < drainDeadlineUs)
    {
      advance(1);
    }
    durationTransferMode = false;
    bytesInFlight = 0;
  }

public:

  void instanceSetup(uint16_t localPort, int argc, char *argv[])
  {
    networkHub = new NetworkHub<mode>(localPort);
    configureTransport();

    static quic_transport_methods_t transportMethods = {
        .on_conn_created = onConnCreated,
        .on_conn_established = onConnEstablished,
        .on_conn_closed = onConnClosed,
        .on_stream_created = onStreamCreated,
        .on_stream_readable = onStreamReadable,
        .on_stream_writable = onStreamWritable,
        .on_stream_closed = onStreamClosed,
        .on_new_token = nullptr,
        .on_datagram_readable = onDatagramReadable,
        .on_datagram_lost = nullptr,
        .on_datagram_acked = nullptr,
    };
    static quic_packet_send_methods_t sendMethods = {
        .on_packets_send = sendPackets,
    };

    endpoint = quic_endpoint_new(
        config,
        mode & Mode::server,
        &transportMethods,
        this,
        &sendMethods,
        this);
  }

  void startClientConnection(struct sockaddr *address)
  {
    if constexpr (mode & Mode::client)
    {
      quic_endpoint_connect(
          endpoint,
          networkHub->socket.address(),
          networkHub->socket.addressLen,
          address,
          sizeof(struct sockaddr_in6),
          benchmarkTlsHostname,
          importedResumption ? importedSession.data() : nullptr,
          importedResumption ? importedSession.size() : 0,
          nullptr,
          0,
          nullptr,
          &connIndex);

      conn = quic_endpoint_get_connection(endpoint, connIndex);
    }
  }

  void connectToServer(struct sockaddr *address)
  {
    if constexpr (mode & Mode::client)
    {
      startClientConnection(address);
      while (!connected && !closed)
      {
        advance(1);
      }
    }
  }

  void connectToServerForZeroRtt(struct sockaddr *address) override
  {
    if constexpr (mode & Mode::client)
    {
      startClientConnection(address);
      if (conn != nullptr && quic_conn_is_in_early_data(conn))
      {
        zeroRttObserved = true;
      }
      quic_endpoint_process_connections(endpoint);
      networkHub->flush();
    }
  }

  void openStream(void)
  {
    if constexpr (mode & Mode::client)
    {
      while (!connected && !closed)
      {
        advance(1);
      }
      quic_stream_bidi_new(conn, 0, false, &streamId);
      quic_stream_wantread(conn, streamId, true);
    }
  }

  void startPerfTest(uint64_t nBytes = 0)
  {
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
        genericClientStreams.clear();
        genericStarted = true;
        openMoreGenericClientStreams();
        for (auto& item : genericClientStreams)
        {
          writeClientGenericStream(item.second, conn, item.first);
        }
        advance();
        return;
      }
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        datagramClientSent = 0;
        datagramClientReceived = 0;
        datagramClientDrainDeadlineUs = 0;
        datagramDoneSignalSent = false;
        datagramDoneStreamWritten = false;
        datagramClientSeen.assign(benchmarkDatagramSeenBytes(), 0);
        const bool durationDatagram = datagramDurationModeActive();
        uint64_t durationStartUs = 0;
        if (streamId == std::numeric_limits<uint64_t>::max())
        {
          quic_stream_bidi_new(conn, 0, false, &streamId);
          quic_stream_wantread(conn, streamId, true);
        }
        if (durationDatagram)
        {
          durationCompletedUnits = 0;
          durationMeasuredSeconds = 0.0;
          durationTransferRunning = true;
          durationStartUs = timeNowUs();
          durationTransferDeadlineUs = durationDeadlineUs(durationStartUs);
        }
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
      bytesInFlight = static_cast<int64_t>(nBytes);
      uint64_t swapped = bswap_64(nBytes);
      memcpy(requestBytes.data(), &swapped, requestBytes.size());
      quic_stream_wantwrite(conn, streamId, true);
    }

    advance();
  }

  void postPerfTest() override
  {
    if constexpr (mode & Mode::client)
    {
      if (!benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) || !genericStarted)
      {
        return;
      }

      for (uint32_t i = 0; i < 3; ++i)
      {
        quic_endpoint_process_connections(endpoint);
        drainIouringSends();
      }
    }
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
    return supportsSimpleDurationMode(scenario) ||
           supportsGenericDurationMode(scenario) ||
           scenario == BenchmarkScenario::datagram;
  }

  uint64_t completedUnitsForReport(uint64_t fallback) const override
  {
    return durationMeasuredSeconds > 0.0 ? durationCompletedUnits : fallback;
  }

  double measuredSecondsForReport(double fallback) const override
  {
    return durationMeasuredSeconds > 0.0 ? durationMeasuredSeconds : fallback;
  }

  bool exportResumptionState(BenchmarkResumptionState& state) override
  {
    if constexpr (mode & Mode::client)
    {
      auto captureSession = [&]() -> bool {
        if (savedSession.empty())
        {
          return false;
        }
        state.session = savedSession;
        state.proofLabel = "quic_conn_session_on_close";
        return true;
      };
      if (captureSession())
      {
        return true;
      }
      for (int i = 0; i < 100; ++i)
      {
        const uint8_t *session = nullptr;
        size_t sessionLen = 0;
        if (conn != nullptr)
        {
          quic_conn_session(conn, &session, &sessionLen);
        }
        if (session != nullptr && sessionLen > 0)
        {
          state.session.assign(session, session + sessionLen);
          state.proofLabel = "quic_conn_session";
          return true;
        }
        advance(1);
      }
      if (conn != nullptr && !closed)
      {
        static const uint8_t reason[] = "resumption-state";
        quic_conn_close(conn, true, 0, reason, sizeof(reason) - 1);
      }
      for (int i = 0; i < 200; ++i)
      {
        if (captureSession())
        {
          return true;
        }
        advance(1);
      }
    }
    return false;
  }

  bool importResumptionState(const BenchmarkResumptionState& state, bool enableZeroRtt) override
  {
    if (state.session.empty())
    {
      return false;
    }
    importedSession = state.session;
    importedResumption = true;
    importedZeroRtt = enableZeroRtt;
    return true;
  }

  bool connectionWasResumed(void) const override
  {
    return resumedObserved || (conn != nullptr && quic_conn_is_resumed(conn));
  }

  bool zeroRttWasAttempted(void) const override
  {
    return importedZeroRtt && zeroRttObserved;
  }

  bool zeroRttWasAccepted(void) const override
  {
    return importedZeroRtt && zeroRttObserved && connectionWasResumed() && !zeroRttRejectedObserved;
  }

  bool zeroRttWasRejected(void) const override
  {
    return importedZeroRtt && zeroRttRejectedObserved;
  }

  const char *resumptionProofLabel(void) const override
  {
    return "tquic_session_and_is_resumed";
  }
};
