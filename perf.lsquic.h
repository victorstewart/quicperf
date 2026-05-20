#include "lsquic.h"

#include <array>
#include <cerrno>
#include <cstdlib>
#include <memory>
#include <vector>

#pragma once

struct lsquic_conn_ctx {};
struct lsquic_stream_ctx {};

template <Mode mode>
class Lsquic : public QuicLibrary<mode> {
private:

  using QuicLibrary<mode>::networkHub;

  int64_t bytesInFlight = -1;
  struct ssl_ctx_st *tlsCtx = nullptr;
  lsquic_conn_t *connection = nullptr;
  lsquic_stream_t *stream = nullptr;
  lsquic_engine_t *engine = nullptr;
  lsquic_engine_settings settings = {};
  lsquic_stream_if streamConfig = {};
  std::vector<uint8_t> savedSession;
  std::vector<uint8_t> importedSession;
  bool importedResumption = false;
  bool importedZeroRtt = false;
  bool handshakeComplete = false;
  bool resumedObserved = false;
  bool zeroRttAttemptedObserved = false;
  bool zeroRttRejectedObserved = false;
  uint64_t serverDrainDeadlineUs = 0;
  std::array<unsigned char, sizeof(uint64_t)> requestBytes = {};
  size_t requestBytesRead = 0;
  size_t requestBytesWritten = 0;
  bool requestParsed = false;
  bool clientDone = false;
  uint32_t serverCompletedConnections = 0;

  struct ServerStreamState {
    Lsquic<mode> *owner = nullptr;
    lsquic_stream_t *stream = nullptr;
    int64_t bytesInFlight = -1;
    uint64_t serverDrainDeadlineUs = 0;
    std::array<unsigned char, sizeof(uint64_t)> requestBytes = {};
    size_t requestBytesRead = 0;
    bool requestParsed = false;
    bool clientDone = false;
    bool complete = false;
  };

  enum class GenericPhase : uint8_t {
    sendRequest,
    readRequest,
    sendPayload,
    readPayload,
    sendResponse,
    readResponse,
    readDone,
    complete
  };

  struct GenericStreamState {
    Lsquic<mode> *owner = nullptr;
    lsquic_stream_t *stream = nullptr;
    GenericPhase phase = GenericPhase::sendRequest;
    std::array<unsigned char, sizeof(uint64_t)> requestBytes = {};
    uint64_t requestValue = 0;
    uint64_t requestBytesExpected = 0;
    uint64_t requestBytesRead = 0;
    uint64_t requestBytesWritten = 0;
    uint64_t payloadRemaining = 0;
    uint64_t responseRemaining = 0;
    uint64_t serverDrainDeadlineUs = 0;
    uint8_t done = 0;
    size_t doneRead = 0;
    bool writeClosed = false;
    bool complete = false;
  };

  std::vector<std::unique_ptr<ServerStreamState>> serverStreams;
  std::vector<std::unique_ptr<GenericStreamState>> genericStreams;
  bool genericStarted = false;
  uint64_t genericRequestedStreams = 0;
  uint64_t genericOpenedStreams = 0;
  uint64_t genericCompletedStreams = 0;
  uint64_t genericClientBytes = 0;
  struct DatagramConnState {
    Lsquic<mode> *owner = nullptr;
    lsquic_conn_t *conn = nullptr;
    uint64_t received = 0;
    uint64_t echoed = 0;
    uint64_t pendingEchoes = 0;
    uint64_t drainDeadlineUs = 0;
    bool complete = false;
  };
  std::vector<std::unique_ptr<DatagramConnState>> datagramServerConns;
  uint64_t datagramClientSent = 0;
  uint64_t datagramClientReceived = 0;
  uint64_t datagramClientDrainDeadlineUs = 0;
  bool datagramStarted = false;
  bool datagramHandshakeDone = false;

  constexpr static std::array<unsigned char, 48> ticketKey = {
      0x71,
      0x75,
      0x69,
      0x63,
      0x70,
      0x65,
      0x72,
      0x66,
      0x2d,
      0x6c,
      0x73,
      0x71,
      0x75,
      0x69,
      0x63,
      0x2d,
      0x72,
      0x65,
      0x73,
      0x75,
      0x6d,
      0x65,
      0x2d,
      0x30,
      0x72,
      0x74,
      0x74,
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
  };

  static int sslCtxSelfIndex(void)
  {
    static int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
  }

  static int saveSession(SSL *ssl, SSL_SESSION *session)
  {
    if constexpr (mode & Mode::client)
    {
      SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
      auto self = ctx == nullptr
                      ? nullptr
                      : static_cast<Lsquic<mode> *>(SSL_CTX_get_ex_data(ctx, sslCtxSelfIndex()));
      if (self == nullptr)
      {
        return 0;
      }

      unsigned char *buffer = nullptr;
      size_t bufferSize = 0;
      if (lsquic_ssl_sess_to_resume_info(ssl, session, &buffer, &bufferSize) != 0)
      {
        return 0;
      }
      self->savedSession.assign(buffer, buffer + bufferSize);
      free(buffer);
    }
    return 0;
  }

  static SSL_CTX *getTLSCtx(void *peer_ctx, const struct sockaddr *address)
  {
    auto self = static_cast<Lsquic<mode> *>(peer_ctx);
    if (self != nullptr && self->tlsCtx != nullptr)
    {
      return self->tlsCtx;
    }
    return TLS::getTLSCtx(peer_ctx, address);
  }

  void configureTLS(void)
  {
    tlsCtx = TLS::getTLSCtx(this, nullptr);
    if (tlsCtx == nullptr)
    {
      fprintf(stderr, "lsquic: failed to create benchmark SSL_CTX\n");
      abort();
    }
    if (SSL_CTX_set_tlsext_ticket_keys(tlsCtx, ticketKey.data(), ticketKey.size()) != 1)
    {
      fprintf(stderr, "lsquic: failed to configure session ticket key\n");
      abort();
    }
    SSL_CTX_set_early_data_enabled(tlsCtx, 1);
    SSL_CTX_set_session_psk_dhe_timeout(tlsCtx, benchmarkIdleTimeoutSeconds);
    SSL_CTX_set_num_tickets(tlsCtx, 2);
    SSL_CTX_set_ex_data(tlsCtx, sslCtxSelfIndex(), this);
    if constexpr (mode & Mode::client)
    {
      SSL_CTX_set_session_cache_mode(tlsCtx, SSL_SESS_CACHE_CLIENT);
      SSL_CTX_sess_set_new_cb(tlsCtx, saveSession);
    }
  }

  bool perfComplete(void) const
  {
    if constexpr (mode & Mode::server)
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        return genericCompletedStreams >= static_cast<uint64_t>(benchmarkServerTargetConnections) * benchmarkGenericStreamsPerConnection();
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
        return datagramClientReceived >= benchmarkScenarioOperations &&
               datagramClientDrainDeadlineUs != 0 &&
               timeNowUs() >= datagramClientDrainDeadlineUs;
      }
      return benchmarkIsUpload() ? clientDone : bytesInFlight == 0;
    }
  }

  ServerStreamState *newServerStreamState(lsquic_stream_t *activeStream)
  {
    auto state = std::make_unique<ServerStreamState>();
    state->owner = this;
    state->stream = activeStream;
    ServerStreamState *raw = state.get();
    serverStreams.push_back(std::move(state));
    return raw;
  }

  void markServerStateComplete(ServerStreamState *state)
  {
    if (state == nullptr || state->complete)
    {
      return;
    }
    if (benchmarkIsUpload())
    {
      if (!state->requestParsed || state->bytesInFlight != 0 ||
          state->serverDrainDeadlineUs == 0 || timeNowUs() < state->serverDrainDeadlineUs)
      {
        return;
      }
    }
    else if (!state->clientDone && (state->serverDrainDeadlineUs == 0 || timeNowUs() < state->serverDrainDeadlineUs))
    {
      return;
    }
    state->complete = true;
    ++serverCompletedConnections;
  }

  static void encodeU64(uint64_t value, std::array<unsigned char, sizeof(uint64_t)>& out)
  {
    uint64_t swapped = bswap_64(value);
    memcpy(out.data(), &swapped, out.size());
  }

  static uint64_t decodeU64(const std::array<unsigned char, sizeof(uint64_t)>& in)
  {
    uint64_t value = 0;
    memcpy(&value, in.data(), in.size());
    return bswap_64(value);
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

  void markGenericStreamComplete(GenericStreamState *state)
  {
    if (state == nullptr || state->complete)
    {
      return;
    }
    state->complete = true;
    state->phase = GenericPhase::complete;
    ++genericCompletedStreams;
  }

  void drainIouringSends(void)
  {
    if constexpr (mode & Mode::iouring)
    {
      networkHub->flush();
      networkHub->drainSendCompletions();
    }
  }

  void finishServerGenericIfReady(GenericStreamState& state)
  {
    if (state.phase != GenericPhase::sendResponse && state.phase != GenericPhase::readDone)
    {
      return;
    }
    if (state.responseRemaining != 0 || state.payloadRemaining != 0)
    {
      return;
    }
    if (benchmarkScenario == BenchmarkScenario::multistream_download &&
        state.doneRead != sizeof(state.done))
    {
      return;
    }
    if (!state.writeClosed)
    {
      lsquic_stream_shutdown(state.stream, 1);
      state.writeClosed = true;
      lsquic_stream_flush(state.stream);
    }
    drainIouringSends();
    if (state.serverDrainDeadlineUs == 0)
    {
      state.serverDrainDeadlineUs = timeNowUs() + 100'000;
    }
    if (timeNowUs() < state.serverDrainDeadlineUs)
    {
      return;
    }
    markGenericStreamComplete(&state);
  }

  GenericStreamState *newGenericStreamState(lsquic_stream_t *activeStream)
  {
    auto state = std::make_unique<GenericStreamState>();
    state->owner = this;
    state->stream = activeStream;
    if constexpr (mode & Mode::client)
    {
      const uint64_t index = genericOpenedStreams++;
      if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
      {
        state->requestBytesExpected = benchmarkGenericReqRespRequestBytes();
        state->responseRemaining = benchmarkGenericReqRespResponseBytes();
      }
      else
      {
        const uint64_t streamBytes = genericTransferBytesForStream(index);
        state->requestValue = streamBytes;
        encodeU64(streamBytes, state->requestBytes);
        state->requestBytesExpected = state->requestBytes.size();
        state->payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                                   benchmarkScenario == BenchmarkScenario::bidi)
                                      ? streamBytes
                                      : 0;
        state->responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : streamBytes;
      }
    }
    else
    {
      state->phase = GenericPhase::readRequest;
    }
    GenericStreamState *raw = state.get();
    genericStreams.push_back(std::move(state));
    return raw;
  }

  void openMoreGenericClientStreams(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (!genericStarted || !benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) || connection == nullptr)
      {
        return;
      }
      const uint64_t targetStreams = benchmarkGenericStreamsPerConnection();
      const uint64_t maxActive = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
      uint64_t active = genericRequestedStreams - genericOpenedStreams;
      for (const auto& state : genericStreams)
      {
        if (!state->complete)
        {
          ++active;
        }
      }
      while (genericRequestedStreams < targetStreams && active < maxActive)
      {
        if (importedZeroRtt && !handshakeComplete)
        {
          zeroRttAttemptedObserved = true;
        }
        lsquic_conn_make_stream(connection);
        ++genericRequestedStreams;
        ++active;
      }
    }
  }

  DatagramConnState *newDatagramServerState(lsquic_conn_t *activeConnection)
  {
    auto state = std::make_unique<DatagramConnState>();
    state->owner = this;
    state->conn = activeConnection;
    DatagramConnState *raw = state.get();
    datagramServerConns.push_back(std::move(state));
    return raw;
  }

  DatagramConnState *datagramServerStateFor(lsquic_conn_t *activeConnection)
  {
    auto *ctx = (DatagramConnState *)lsquic_conn_get_ctx(activeConnection);
    if (ctx != nullptr)
    {
      return ctx;
    }
    auto *state = newDatagramServerState(activeConnection);
    lsquic_conn_set_ctx(activeConnection, (lsquic_conn_ctx_t *)state);
    return state;
  }

  void markDatagramServerComplete(DatagramConnState *state)
  {
    if (state == nullptr || state->complete)
    {
      return;
    }
    if (state->echoed < benchmarkScenarioOperations)
    {
      return;
    }
    if (state->drainDeadlineUs == 0)
    {
      state->drainDeadlineUs = timeNowUs() + 100'000;
    }
    if (timeNowUs() < state->drainDeadlineUs)
    {
      return;
    }
    state->complete = true;
    ++serverCompletedConnections;
  }

  uint64_t datagramMaxAttempts(void) const
  {
    const uint64_t maxInFlight = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    return benchmarkScenarioOperations +
           (std::max<uint64_t>(benchmarkScenarioOperations, maxInFlight) * 64ULL);
  }

  bool datagramClientCanSend(void) const
  {
    if (connection == nullptr || !datagramStarted || !datagramHandshakeDone ||
        datagramClientReceived >= benchmarkScenarioOperations)
    {
      return false;
    }
    const uint64_t maxInFlight = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    return datagramClientSent < datagramMaxAttempts() &&
           datagramClientSent - datagramClientReceived < maxInFlight;
  }

  void scheduleClientDatagramWrite(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram || connection == nullptr)
      {
        return;
      }
      if (datagramClientSent >= datagramMaxAttempts() &&
          datagramClientReceived < benchmarkScenarioOperations)
      {
        fprintf(stderr, "lsquic datagram delivery target not reached received=%" PRIu64 " sent=%" PRIu64 " target=%" PRIu64 "\n",
                datagramClientReceived, datagramClientSent, benchmarkScenarioOperations);
        abort();
      }
      if (datagramClientCanSend())
      {
        lsquic_conn_want_datagram_write(connection, 1);
      }
    }
  }

  void processClientGenericRead(GenericStreamState& state, size_t len, int fin)
  {
    if (state.responseRemaining > 0)
    {
      const uint64_t consumed = std::min<uint64_t>(state.responseRemaining, len);
      state.responseRemaining -= consumed;
    }
    if (benchmarkScenario == BenchmarkScenario::multistream_download &&
        state.responseRemaining == 0 && !state.writeClosed)
    {
      unsigned char done = 0;
      ssize_t written = lsquic_stream_write(state.stream, &done, sizeof(done));
      if (written == static_cast<ssize_t>(sizeof(done)))
      {
        lsquic_stream_shutdown(state.stream, 1);
        state.writeClosed = true;
        lsquic_stream_flush(state.stream);
      }
    }
    if (state.responseRemaining == 0 && fin)
    {
      lsquic_stream_shutdown(state.stream, 0);
      markGenericStreamComplete(&state);
      openMoreGenericClientStreams();
    }
  }

  void processServerGenericRead(GenericStreamState& state, const unsigned char *data, size_t len)
  {
    size_t consumed = 0;
    if (state.phase == GenericPhase::readRequest)
    {
      if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
      {
        if (state.requestBytesExpected == 0)
        {
          state.requestBytesExpected = benchmarkGenericReqRespRequestBytes();
        }
        const uint64_t copied = std::min<uint64_t>(state.requestBytesExpected - state.requestBytesRead, len);
        state.requestBytesRead += copied;
        consumed += static_cast<size_t>(copied);
        if (state.requestBytesRead == state.requestBytesExpected)
        {
          state.responseRemaining = benchmarkGenericReqRespResponseBytes();
          state.phase = GenericPhase::sendResponse;
          lsquic_stream_wantwrite(state.stream, 1);
        }
      }
      else
      {
        while (state.requestBytesRead < state.requestBytes.size() && consumed < len)
        {
          state.requestBytes[state.requestBytesRead++] = data[consumed++];
        }
        if (state.requestBytesRead == state.requestBytes.size())
        {
          state.requestValue = decodeU64(state.requestBytes);
          state.payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                                    benchmarkScenario == BenchmarkScenario::bidi)
                                       ? state.requestValue
                                       : 0;
          state.responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : state.requestValue;
          state.phase = benchmarkScenario == BenchmarkScenario::multistream_upload ? GenericPhase::readPayload : GenericPhase::sendResponse;
          if (state.phase == GenericPhase::sendResponse)
          {
            lsquic_stream_wantwrite(state.stream, 1);
          }
        }
      }
    }

    if ((benchmarkScenario == BenchmarkScenario::multistream_upload ||
         benchmarkScenario == BenchmarkScenario::bidi) &&
        consumed < len && state.payloadRemaining > 0)
    {
      const uint64_t copied = std::min<uint64_t>(state.payloadRemaining, len - consumed);
      state.payloadRemaining -= copied;
      if (state.payloadRemaining == 0)
      {
        if (state.responseRemaining > 0)
        {
          state.phase = GenericPhase::sendResponse;
          lsquic_stream_wantwrite(state.stream, 1);
        }
        else
        {
          finishServerGenericIfReady(state);
        }
      }
    }

    if (benchmarkScenario == BenchmarkScenario::multistream_download &&
        state.phase == GenericPhase::readDone && consumed < len)
    {
      const size_t copied = std::min<size_t>(sizeof(state.done) - state.doneRead, len - consumed);
      state.doneRead += copied;
      if (state.doneRead == sizeof(state.done))
      {
        finishServerGenericIfReady(state);
      }
    }
  }

  void processServerGenericFin(GenericStreamState& state)
  {
    lsquic_stream_wantread(state.stream, 0);
    if ((benchmarkScenario == BenchmarkScenario::multistream_upload ||
         benchmarkScenario == BenchmarkScenario::bidi) &&
        state.payloadRemaining != 0)
    {
      return;
    }
    if (state.responseRemaining > 0)
    {
      state.phase = GenericPhase::sendResponse;
      lsquic_stream_wantwrite(state.stream, 1);
      return;
    }
    if (state.responseRemaining == 0)
    {
      finishServerGenericIfReady(state);
    }
  }

  void readGenericStream(GenericStreamState& state)
  {
    NetworkHub<mode> *hub = networkHub;
    uint64_t readBudget = 16ULL * 1024ULL * 1024ULL;
    while (readBudget > 0)
    {
      const size_t chunk = static_cast<size_t>(std::min<uint64_t>(sizeof(hub->junk), readBudget));
      ssize_t read = lsquic_stream_read(state.stream, hub->junk, chunk);
      if (read > 0)
      {
        readBudget -= static_cast<uint64_t>(read);
        if constexpr (mode & Mode::client)
        {
          processClientGenericRead(state, static_cast<size_t>(read), 0);
        }
        else
        {
          processServerGenericRead(state, hub->junk, static_cast<size_t>(read));
        }
        continue;
      }
      if (read == 0)
      {
        if constexpr (mode & Mode::client)
        {
          processClientGenericRead(state, 0, 1);
        }
        else
        {
          processServerGenericFin(state);
        }
        return;
      }
      if (errno == EWOULDBLOCK || errno == EAGAIN)
      {
        return;
      }
      return;
    }
    lsquic_stream_wantread(state.stream, 1);
  }

  void writeClientGeneric(GenericStreamState& state)
  {
    NetworkHub<mode> *hub = networkHub;
    while (state.requestBytesWritten < state.requestBytesExpected)
    {
      const size_t left = static_cast<size_t>(state.requestBytesExpected - state.requestBytesWritten);
      const unsigned char *source = nullptr;
      if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
      {
        source = reinterpret_cast<const unsigned char *>(hub->junk);
      }
      else
      {
        source = state.requestBytes.data() + state.requestBytesWritten;
      }
      const size_t chunk = std::min<size_t>(left, sizeof(hub->junk));
      ssize_t written = lsquic_stream_write(state.stream, source, chunk);
      if (written <= 0)
      {
        lsquic_stream_flush(state.stream);
        return;
      }
      state.requestBytesWritten += static_cast<uint64_t>(written);
    }

    while (state.payloadRemaining > 0)
    {
      const size_t chunk = static_cast<size_t>(std::min<uint64_t>(state.payloadRemaining, sizeof(hub->junk)));
      ssize_t written = lsquic_stream_write(state.stream, hub->junk, chunk);
      if (written <= 0)
      {
        lsquic_stream_flush(state.stream);
        return;
      }
      state.payloadRemaining -= static_cast<uint64_t>(written);
    }

    if (benchmarkScenario == BenchmarkScenario::multistream_download)
    {
      state.phase = GenericPhase::readResponse;
      lsquic_stream_wantwrite(state.stream, 0);
      lsquic_stream_flush(state.stream);
      return;
    }

    if (!state.writeClosed)
    {
      lsquic_stream_shutdown(state.stream, 1);
      state.writeClosed = true;
      state.phase = GenericPhase::readResponse;
    }
    lsquic_stream_wantwrite(state.stream, 0);
    lsquic_stream_flush(state.stream);
    if (state.responseRemaining == 0)
    {
      markGenericStreamComplete(&state);
      openMoreGenericClientStreams();
    }
  }

  void writeServerGeneric(GenericStreamState& state)
  {
    NetworkHub<mode> *hub = networkHub;
    const uint64_t responseFloor = (benchmarkScenario == BenchmarkScenario::bidi && state.payloadRemaining > 0)
                                       ? 1
                                       : 0;
    while (state.responseRemaining > responseFloor)
    {
      const uint64_t writable = state.responseRemaining - responseFloor;
      const size_t chunk = static_cast<size_t>(std::min<uint64_t>(writable, sizeof(hub->junk)));
      ssize_t written = lsquic_stream_write(state.stream, hub->junk, chunk);
      if (written <= 0)
      {
        lsquic_stream_flush(state.stream);
        return;
      }
      state.responseRemaining -= static_cast<uint64_t>(written);
    }

    if (state.responseRemaining > 0 && state.payloadRemaining > 0)
    {
      lsquic_stream_wantwrite(state.stream, 0);
      lsquic_stream_flush(state.stream);
      return;
    }

    if (benchmarkScenario == BenchmarkScenario::multistream_download &&
        state.payloadRemaining == 0 && state.responseRemaining == 0)
    {
      state.phase = GenericPhase::readDone;
      lsquic_stream_wantwrite(state.stream, 0);
      lsquic_stream_flush(state.stream);
      return;
    }

    if (!state.writeClosed && state.payloadRemaining == 0)
    {
      lsquic_stream_shutdown(state.stream, 1);
      state.writeClosed = true;
    }
    lsquic_stream_wantwrite(state.stream, 0);
    lsquic_stream_flush(state.stream);
    finishServerGenericIfReady(state);
  }

  static lsquic_conn_ctx_t *connectionOpen(void *stream_if_ctx, lsquic_conn_t *connection)
  {
    // printf("lsquic %s: connectionOpen\n", modeToString(mode));

    if constexpr (mode & Mode::client)
    {
      ((Lsquic<mode> *)stream_if_ctx)->connection = connection;
    }
    else
    {
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        auto self = (Lsquic<mode> *)stream_if_ctx;
        return (lsquic_conn_ctx_t *)self->newDatagramServerState(connection);
      }
    }

    return (lsquic_conn_ctx_t *)stream_if_ctx;
  }

  static void connectionClose(lsquic_conn_t *conn)
  {
    // printf("lsquic %s: connectionClose\n", modeToString(mode));
    if constexpr (mode & Mode::server)
    {
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        auto *state = (DatagramConnState *)lsquic_conn_get_ctx(conn);
        if (state != nullptr)
        {
          state->owner->markDatagramServerComplete(state);
        }
      }
    }
  }

  static void handshakeDone(lsquic_conn_t *conn, enum lsquic_hsk_status status)
  {
    if constexpr (mode & Mode::client)
    {
      auto *self = (Lsquic<mode> *)lsquic_conn_get_ctx(conn);
      if (self == nullptr)
      {
        return;
      }
      self->handshakeComplete = true;
      self->resumedObserved = status == LSQ_HSK_RESUMED_OK;
      self->zeroRttRejectedObserved = self->importedZeroRtt && status != LSQ_HSK_RESUMED_OK;
      if (status != LSQ_HSK_OK && status != LSQ_HSK_RESUMED_OK)
      {
        return;
      }
      self->datagramHandshakeDone = true;
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        const size_t payloadSize = std::min<size_t>(
            benchmarkScenarioMessageBytes, sizeof(self->networkHub->junk));
        lsquic_conn_set_min_datagram_size(conn, payloadSize);
        self->scheduleClientDatagramWrite();
      }
    }
  }

  static lsquic_stream_ctx_t *streamOpen(void *stream_if_ctx, lsquic_stream_t *stream)
  {
    // printf("lsquic %s: streamOpen\n", modeToString(mode));

    if constexpr (mode & Mode::client)
    {
      auto self = (Lsquic<mode> *)stream_if_ctx;
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        auto state = self->newGenericStreamState(stream);
        lsquic_stream_set_ctx(stream, (lsquic_stream_ctx_t *)state);
        lsquic_stream_wantread(stream, 1);
        lsquic_stream_wantwrite(stream, 1);
        return (lsquic_stream_ctx_t *)state;
      }
      self->stream = stream;
      lsquic_stream_set_ctx(stream, (lsquic_stream_ctx_t *)self);
      lsquic_stream_wantread(stream, 1);
      return (lsquic_stream_ctx_t *)self;
    }
    else
    {
      auto self = (Lsquic<mode> *)stream_if_ctx;
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        auto state = self->newGenericStreamState(stream);
        lsquic_stream_set_ctx(stream, (lsquic_stream_ctx_t *)state);
        lsquic_stream_wantread(stream, 1);
        return (lsquic_stream_ctx_t *)state;
      }
      auto state = self->newServerStreamState(stream);
      lsquic_stream_set_ctx(stream, (lsquic_stream_ctx_t *)state);
      lsquic_stream_wantread(stream, 1);
      return (lsquic_stream_ctx_t *)state;
    }
  }

  static ssize_t datagramWrite(lsquic_conn_t *conn, void *buf, size_t sz)
  {
    if constexpr (mode & Mode::client)
    {
      auto *self = (Lsquic<mode> *)lsquic_conn_get_ctx(conn);
      if (self == nullptr || benchmarkScenario != BenchmarkScenario::datagram ||
          !self->datagramClientCanSend())
      {
        lsquic_conn_want_datagram_write(conn, 0);
        return 0;
      }
      const size_t payloadSize = std::min<size_t>(
          benchmarkScenarioMessageBytes, sizeof(self->networkHub->junk));
      if (sz < payloadSize)
      {
        return -1;
      }
      memcpy(buf, self->networkHub->junk, payloadSize);
      ++self->datagramClientSent;
      lsquic_conn_want_datagram_write(conn, self->datagramClientCanSend() ? 1 : 0);
      return static_cast<ssize_t>(payloadSize);
    }
    else
    {
      auto *state = (DatagramConnState *)lsquic_conn_get_ctx(conn);
      if (state == nullptr || state->pendingEchoes == 0)
      {
        lsquic_conn_want_datagram_write(conn, 0);
        return 0;
      }
      const size_t payloadSize = std::min<size_t>(
          benchmarkScenarioMessageBytes, sizeof(state->owner->networkHub->junk));
      if (sz < payloadSize)
      {
        return -1;
      }
      memcpy(buf, state->owner->networkHub->junk, payloadSize);
      --state->pendingEchoes;
      ++state->echoed;
      lsquic_conn_want_datagram_write(conn, state->pendingEchoes > 0 ? 1 : 0);
      state->owner->markDatagramServerComplete(state);
      return static_cast<ssize_t>(payloadSize);
    }
  }

  static void datagramRead(lsquic_conn_t *conn, const void *buf, size_t bufsz)
  {
    (void)buf;
    (void)bufsz;
    if constexpr (mode & Mode::client)
    {
      auto *self = (Lsquic<mode> *)lsquic_conn_get_ctx(conn);
      if (self == nullptr || benchmarkScenario != BenchmarkScenario::datagram)
      {
        return;
      }
      ++self->datagramClientReceived;
      if (self->datagramClientReceived >= benchmarkScenarioOperations)
      {
        if (self->datagramClientDrainDeadlineUs == 0)
        {
          self->datagramClientDrainDeadlineUs = timeNowUs() + 100'000;
        }
        lsquic_conn_want_datagram_write(conn, 0);
        lsquic_conn_close(conn);
      }
      else
      {
        self->scheduleClientDatagramWrite();
      }
    }
    else
    {
      if (benchmarkScenario != BenchmarkScenario::datagram)
      {
        return;
      }
      auto *state = (DatagramConnState *)lsquic_conn_get_ctx(conn);
      if (state == nullptr)
      {
        return;
      }
      ++state->received;
      ++state->pendingEchoes;
      lsquic_conn_want_datagram_write(conn, 1);
    }
  }

  static void streamClose(lsquic_stream_t *stream, lsquic_stream_ctx_t *context)
  {
    // printf("lsquic %s: streamClose\n", modeToString(mode));
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      auto state = (GenericStreamState *)lsquic_stream_get_ctx(stream);
      if (state == nullptr)
      {
        state = (GenericStreamState *)context;
      }
      if constexpr (mode & Mode::server)
      {
        if (state != nullptr)
        {
          state->owner->finishServerGenericIfReady(*state);
        }
      }
      return;
    }
    if constexpr (mode & Mode::server)
    {
      auto state = (ServerStreamState *)context;
      state->clientDone = true;
      state->owner->markServerStateComplete(state);
    }
  }

  static size_t streamRead(void *context, const unsigned char *data, size_t len, int fin)
  {
    // printf("lsquic %s: streamRead\n", modeToString(mode));

    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        auto state = (GenericStreamState *)context;
        state->owner->processClientGenericRead(*state, len, fin);
        return len;
      }
      // throw away the bytes
      ((Lsquic<mode> *)context)->bytesInFlight -= len;
      if (((Lsquic<mode> *)context)->bytesInFlight <= 0)
      {
        ((Lsquic<mode> *)context)->bytesInFlight = 0;
      }
      if (fin)
      {
        ((Lsquic<mode> *)context)->clientDone = true;
      }
    }
    else
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        auto state = (GenericStreamState *)context;
        state->owner->processServerGenericRead(*state, data, len);
        return len;
      }
      auto state = (ServerStreamState *)context;
      auto self = state->owner;
      size_t consumed = 0;

      while (state->requestBytesRead < state->requestBytes.size() && consumed < len)
      {
        state->requestBytes[state->requestBytesRead++] = data[consumed++];
      }

      if (!state->requestParsed && state->requestBytesRead == state->requestBytes.size())
      {
        uint64_t requested = 0;
        memcpy(&requested, state->requestBytes.data(), state->requestBytes.size());
        state->bytesInFlight = static_cast<int64_t>(bswap_64(requested));
        state->requestParsed = true;
      }

      if (benchmarkIsUpload() && state->requestParsed && consumed < len)
      {
        state->bytesInFlight -= std::min<int64_t>(state->bytesInFlight, static_cast<int64_t>(len - consumed));
      }
      self->markServerStateComplete(state);
    }

    return len;
  }

  static void streamReadTrigger(lsquic_stream_t *stream, lsquic_stream_ctx_t *context)
  {
    // printf("lsquic %s: streamReadTrigger\n", modeToString(mode));

    auto activeContext = lsquic_stream_get_ctx(stream);
    if (activeContext == nullptr)
    {
      activeContext = context;
    }
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      auto state = (GenericStreamState *)activeContext;
      if constexpr (mode & Mode::client)
      {
        lsquic_stream_readf(stream, streamRead, activeContext);
        state->owner->openMoreGenericClientStreams();
      }
      else
      {
        state->owner->readGenericStream(*state);
      }
      return;
    }

    lsquic_stream_readf(stream, streamRead, activeContext);

    if constexpr (mode & Mode::client)
    {
      // printf("received = %.1f\n", (_1GB - ((Lsquic<mode> *)context)->bytesInFlight)/_1GB);

      // we're done
    }
    else
    {
      auto state = (ServerStreamState *)activeContext;
      auto self = state->owner;
      if (benchmarkIsUpload() && state->requestParsed && state->bytesInFlight == 0)
      {
        lsquic_stream_shutdown(stream, 1);
        if (state->serverDrainDeadlineUs == 0)
        {
          state->serverDrainDeadlineUs = timeNowUs() + 100'000;
        }
        self->markServerStateComplete(state);
      }
      // start sending the client bytes
      if (!benchmarkIsUpload())
      {
        lsquic_stream_wantwrite(stream, 1);
      }
    }
  }

  static void streamWrite(lsquic_stream_t *stream, lsquic_stream_ctx_t *context)
  {
    // printf("lsquic %s: streamWrite\n", modeToString(mode));

    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        auto state = (GenericStreamState *)lsquic_stream_get_ctx(stream);
        state->owner->writeClientGeneric(*state);
        return;
      }
      auto self = (Lsquic<mode> *)context;
      while (self->requestBytesWritten < self->requestBytes.size())
      {
        ssize_t written = lsquic_stream_write(
            stream,
            self->requestBytes.data() + self->requestBytesWritten,
            self->requestBytes.size() - self->requestBytesWritten);
        if (written <= 0)
        {
          lsquic_stream_flush(stream);
          return;
        }
        self->requestBytesWritten += static_cast<size_t>(written);
      }

      if (benchmarkIsUpload())
      {
        NetworkHub<mode> *networkHub = self->networkHub;
        while (self->bytesInFlight > 0)
        {
          size_t writeLength = static_cast<size_t>(std::min<int64_t>(self->bytesInFlight, sizeof(networkHub->junk)));
          ssize_t written = lsquic_stream_write(stream, networkHub->junk, writeLength);
          if (written <= 0)
          {
            lsquic_stream_flush(stream);
            return;
          }
          self->bytesInFlight -= written;
        }
      }

      lsquic_stream_wantwrite(stream, 0);
      lsquic_stream_flush(stream);
    }
    else
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        auto state = (GenericStreamState *)lsquic_stream_get_ctx(stream);
        state->owner->writeServerGeneric(*state);
        return;
      }
      auto state = (ServerStreamState *)context;
      auto self = state->owner;
      if (benchmarkIsUpload())
      {
        lsquic_stream_wantwrite(stream, 0);
        lsquic_stream_flush(stream);
        self->markServerStateComplete(state);
        return;
      }

      NetworkHub<mode> *networkHub = self->networkHub;
      int64_t& bytesToSend = state->bytesInFlight;
      while (bytesToSend > 0)
      {
        size_t writeLength = static_cast<size_t>(std::min<int64_t>(bytesToSend, sizeof(networkHub->junk)));
        ssize_t written = lsquic_stream_write(stream, networkHub->junk, writeLength);
        if (written <= 0)
        {
          lsquic_stream_flush(stream);
          return;
        }
        bytesToSend -= written;
      }

      if (unlikely(bytesToSend == 0))
      {
        // the server is done
        lsquic_stream_wantwrite(stream, 0);
        lsquic_stream_flush(stream);
        if (state->serverDrainDeadlineUs == 0)
        {
          state->serverDrainDeadlineUs = timeNowUs() + 100'000;
        }
        self->markServerStateComplete(state);
      }
    }
  }

  static int packetsOut(void *context, const struct lsquic_out_spec *specs, unsigned n_specs)
  {
    // printf("lsquic %s: packetsOut -> n_specs = %lu\n", modeToString(mode), n_specs);

    auto *self = (Lsquic<mode> *)context;
    NetworkHub<mode> *networkHub = self->networkHub;
    auto acquireBatch = [&]() -> MultiUDPContext * {
      MultiUDPContext *next = networkHub->sendPool.get();
      if (next == nullptr)
      {
        self->drainIouringSends();
        next = networkHub->sendPool.get();
      }
      return next;
    };

    MultiUDPContext *packets = acquireBatch();
    if (packets == nullptr)
    {
      errno = EAGAIN;
      return -1;
    }

    unsigned sent = 0;
    for (uint32_t index = 0; index < n_specs; index++)
    {
      const struct lsquic_out_spec& spec = specs[index];

      UDPContext *packet = packets->nextPacket();
      if (packet == NULL)
      {
        networkHub->sendBatch(packets);
        packets = acquireBatch();
        if (packets == nullptr)
        {
          errno = EAGAIN;
          return sent == 0 ? -1 : static_cast<int>(sent);
        }
        packet = packets->nextPacket();
      }

      packet->copyInAddress(spec.dest_sa);
      packet->copyInIovs(spec.iov, spec.iovlen);
      ++sent;
    }

    networkHub->sendBatch(packets);
    return static_cast<int>(sent);
  }

  void advance(int32_t count = 0)
  {
    // printf("lsquic %s: advance(%d)\n", modeToString(mode), count);

    do
    {
      if constexpr (mode & Mode::client)
      {
        openMoreGenericClientStreams();
        scheduleClientDatagramWrite();
      }
      lsquic_engine_process_conns(engine);
      drainIouringSends();

      int usTil = 0;
      lsquic_engine_earliest_adv_tick(engine, &usTil);
      usTil = std::min(usTil, 100'000);

      networkHub->recvmsgWithTimeout(usTil, [&](UDPContext *msg) -> void {
        lsquic_engine_packet_in(engine, (const unsigned char *)msg->buffer(), msg->msg_len, (const struct sockaddr *)networkHub->socket.address6, (const struct sockaddr *)msg->address(), this, 0);
      });

      if constexpr (mode & Mode::server)
      {
        for (auto& state : serverStreams)
        {
          markServerStateComplete(state.get());
        }
        for (auto& state : genericStreams)
        {
          finishServerGenericIfReady(*state);
        }
        for (auto& state : datagramServerConns)
        {
          markDatagramServerComplete(state.get());
        }
      }

    } while (!perfComplete() && (count == 0 || --count > 0));
  }

public:

  static int lslogger(void *ctx, const char *buf, size_t len)
  {
    printf("%.*s", len, buf);
    return 0;
  }

  static void globalSetup(void)
  {
    // printf("lsquic::globalSetup() \n");

    // static const struct lsquic_logger_if logger_if = { lslogger };
    // lsquic_logger_init(&logger_if, NULL, LLTS_HHMMSSUS);

    // lsquic_set_log_level("debug");

    if constexpr (mode & Mode::server)
    {
      lsquic_global_init(LSQUIC_GLOBAL_SERVER);
    }
    else
    {
      lsquic_global_init(LSQUIC_GLOBAL_CLIENT);
    }
  }

  void instanceSetup(uint16_t localPort, int argc, char *argv[])
  {
    networkHub = new NetworkHub<mode>(localPort);
    configureTLS();

    // printf("lsquic %s: setup\n", modeToString(mode));

    memset(&settings, 0, sizeof(struct lsquic_engine_settings));

    if constexpr (mode & Mode::server)
    {
      lsquic_engine_init_settings(&settings, LSENG_SERVER);
    }
    else
    {
      lsquic_engine_init_settings(&settings, 0);
    }

    settings.es_sfcw = static_cast<unsigned>(benchmarkStreamWindow);
    settings.es_cfcw = static_cast<unsigned>(benchmarkConnectionWindow);
    settings.es_max_sfcw = static_cast<unsigned>(benchmarkStreamWindow);
    settings.es_max_cfcw = static_cast<unsigned>(benchmarkConnectionWindow);
    settings.es_max_inchoate = 10'000;
    settings.es_versions = (1 << LSQVER_I001);
    settings.es_pace_packets = 1;
    settings.es_cc_algo = benchmarkCongestionProfileUsesCubic() ? 1 : 2;
    settings.es_idle_timeout = benchmarkIdleTimeoutSeconds;
    settings.es_ecn = 0;
    settings.es_ql_bits = 2;
    settings.es_spin = 1;
    settings.es_scid_len = 8;
    settings.es_delayed_acks = 1;
    settings.es_max_udp_payload_size_rx = benchmarkUdpPayloadSize;
    settings.es_dplpmtud = 0;
    settings.es_base_plpmtu = benchmarkUdpPayloadSize;
    settings.es_max_plpmtu = benchmarkUdpPayloadSize;
    settings.es_max_batch_size = 50;
    settings.es_init_max_data = static_cast<unsigned>(benchmarkConnectionWindow);
    settings.es_init_max_stream_data_bidi_local = static_cast<unsigned>(benchmarkStreamWindow);
    settings.es_init_max_stream_data_bidi_remote = static_cast<unsigned>(benchmarkStreamWindow);
    settings.es_init_max_stream_data_uni = static_cast<unsigned>(benchmarkStreamWindow);
    settings.es_init_max_streams_bidi = static_cast<unsigned>(benchmarkMaxBidiStreams);
    settings.es_init_max_streams_uni = static_cast<unsigned>(benchmarkMaxUniStreams);
    settings.es_datagrams = 1;

    memset(&streamConfig, 0, sizeof(streamConfig));
    streamConfig.on_new_conn = connectionOpen;
    streamConfig.on_conn_closed = connectionClose;
    streamConfig.on_new_stream = streamOpen;
    streamConfig.on_read = streamReadTrigger;
    streamConfig.on_write = streamWrite;
    streamConfig.on_close = streamClose;
    streamConfig.on_dg_write = datagramWrite;
    streamConfig.on_datagram = datagramRead;
    streamConfig.on_hsk_done = handshakeDone;

    struct lsquic_engine_api config = {};
    config.ea_settings = &settings;
    config.ea_stream_if = &streamConfig;
    config.ea_stream_if_ctx = this;
    config.ea_packets_out = packetsOut;
    config.ea_packets_out_ctx = this;
    config.ea_get_ssl_ctx = getTLSCtx;
    config.ea_verify_cert = TLS::verifyCert;
    config.ea_verify_ctx = this;
    config.ea_alpn = "perf";

    if constexpr (mode & Mode::server)
    {
      engine = lsquic_engine_new(LSENG_SERVER, &config);
    }
    else
    {
      engine = lsquic_engine_new(0, &config);
    }
  }

  void connectToServer(struct sockaddr *address)
  {
    // printf("lsquic %s: connect\n", modeToString(mode));

    const unsigned char *resume = importedResumption && !importedSession.empty()
                                      ? importedSession.data()
                                      : nullptr;
    const size_t resumeLen = resume == nullptr ? 0 : importedSession.size();
    connection = lsquic_engine_connect(engine, LSQVER_I001, networkHub->socket.address(), address, this, (lsquic_conn_ctx_t *)this, NULL, benchmarkUdpPayloadSize, resume, resumeLen, NULL, 0);

    do
    {
      advance(1);

    } while (connection == NULL);
  }

  void connectToServerForZeroRtt(struct sockaddr *address) override
  {
    if constexpr (mode & Mode::client)
    {
      const unsigned char *resume = importedResumption && !importedSession.empty()
                                        ? importedSession.data()
                                        : nullptr;
      const size_t resumeLen = resume == nullptr ? 0 : importedSession.size();
      connection = lsquic_engine_connect(engine, LSQVER_I001, networkHub->socket.address(), address, this, (lsquic_conn_ctx_t *)this, NULL, benchmarkUdpPayloadSize, resume, resumeLen, NULL, 0);
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        genericClientBytes = 0;
        genericRequestedStreams = 0;
        genericOpenedStreams = 0;
        genericCompletedStreams = 0;
        genericStreams.clear();
        genericStarted = true;
        openMoreGenericClientStreams();
      }
      advance(1);
    }
    else
    {
      connectToServer(address);
    }
  }

  void openStream(void)
  {
    // printf("lsquic %s: openStream\n", modeToString(mode));

    lsquic_conn_make_stream(connection);

    do
    {
      advance(1);

    } while (stream == NULL);
  }

  void startPerfTest(uint64_t nBytes)
  {
    // printf("lsquic %s: startPerfTest\n", modeToString(mode));

    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        if (importedZeroRtt && genericStarted)
        {
          genericClientBytes = nBytes;
          advance();
          return;
        }
        genericClientBytes = nBytes;
        genericRequestedStreams = 0;
        genericOpenedStreams = 0;
        genericCompletedStreams = 0;
        genericStreams.clear();
        genericStarted = true;
        openMoreGenericClientStreams();
        advance();
        return;
      }
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        datagramClientSent = 0;
        datagramClientReceived = 0;
        datagramClientDrainDeadlineUs = 0;
        datagramStarted = true;
        const size_t payloadSize = std::min<size_t>(
            benchmarkScenarioMessageBytes, sizeof(networkHub->junk));
        if (connection != nullptr)
        {
          lsquic_conn_set_min_datagram_size(connection, payloadSize);
        }
        scheduleClientDatagramWrite();
        advance();
        benchmarkRecordDatagramClientCounters(datagramClientSent, datagramClientReceived);
        return;
      }
      bytesInFlight = nBytes;
      uint64_t request = bswap_64(nBytes);
      memcpy(requestBytes.data(), &request, requestBytes.size());
      requestBytesWritten = 0;
      lsquic_stream_wantwrite(stream, 1);
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

  bool exportResumptionState(BenchmarkResumptionState& state) override
  {
    if constexpr (mode & Mode::client)
    {
      for (int i = 0; i < 100 && savedSession.empty(); ++i)
      {
        advance(1);
      }
      if (!savedSession.empty())
      {
        state.session = savedSession;
        state.proofLabel = "lsquic_ssl_sess_to_resume_info";
        return true;
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
    return resumedObserved;
  }

  bool zeroRttWasAttempted(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved;
  }

  bool zeroRttWasAccepted(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved && resumedObserved;
  }

  bool zeroRttWasRejected(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved && zeroRttRejectedObserved;
  }

  const char *resumptionProofLabel(void) const override
  {
    return "lsquic_resume_info_and_hsk_status";
  }
};
