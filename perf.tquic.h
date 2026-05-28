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
    bool closed = false;
    bool complete = false;
    uint64_t datagramReceived = 0;
    uint64_t datagramEchoed = 0;
    std::deque<uint64_t> datagramPendingEchoes;
    std::vector<uint8_t> datagramSeen;
    uint64_t datagramDrainDeadlineUs = 0;
    std::unordered_map<uint64_t, GenericStreamState> genericStreams;
    uint64_t genericCompletedStreams = 0;
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
        return (datagramClientSent >= benchmarkScenarioOperations &&
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
      if (!state->clientDone || !state->datagramPendingEchoes.empty())
      {
        return;
      }
      if (state->datagramDrainDeadlineUs == 0)
      {
        state->datagramDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
        return;
      }
      if (timeNowUs() < state->datagramDrainDeadlineUs)
      {
        return;
      }
      state->complete = true;
      ++serverCompletedConnections;
      return;
    }
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
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
      if (!state->closed &&
          (!state->uploadFinSent || state->serverDrainDeadlineUs == 0 || timeNowUs() < state->serverDrainDeadlineUs))
      {
        return;
      }
    }
    else
    {
      if (!state->clientDone && !state->closed)
      {
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
    if (sequence >= benchmarkScenarioOperations)
    {
      return false;
    }
    const size_t index = static_cast<size_t>(sequence >> 3);
    const uint8_t mask = static_cast<uint8_t>(1U << (sequence & 7U));
    if (seen.size() < ((benchmarkScenarioOperations + 7U) >> 3))
    {
      seen.assign(static_cast<size_t>((benchmarkScenarioOperations + 7U) >> 3), 0);
    }
    if ((seen[index] & mask) != 0)
    {
      return false;
    }
    seen[index] |= mask;
    return true;
  }

  bool sendClientDatagrams(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram ||
          conn == nullptr ||
          !connected ||
          closed ||
          datagramClientSent >= benchmarkScenarioOperations)
      {
        return false;
      }

      const size_t payloadSize = datagramPayloadSize();
      const uint64_t burstLimit = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
      uint64_t sentThisCall = 0;
      bool progressed = false;
      while (datagramClientSent < benchmarkScenarioOperations && sentThisCall < burstLimit)
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
      if (datagramClientSent >= benchmarkScenarioOperations)
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
          datagramClientSent < benchmarkScenarioOperations ||
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
      datagramDoneSignalSent = true;
      uint8_t done = 0;
      ssize_t written = quic_stream_write(conn, streamId, &done, sizeof(done), true);
      if (written == tquicErrDone || written <= 0)
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
      if (datagramClientSent >= benchmarkScenarioOperations)
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
      const uint64_t streamBytes = genericTransferBytesForStream(index);
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
      const uint64_t targetStreams = benchmarkGenericStreamsPerConnection();
      const uint64_t maxActive = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
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
        if (state.responseRemaining == 0)
        {
          state.phase = GenericPhase::sendPayload;
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
          uint64_t requested = 0;
          memcpy(&requested, requestBytes.data(), requestBytes.size());
          bytesInFlight = static_cast<int64_t>(bswap_64(requested));
          requestParsed = true;
          if (!benchmarkIsUpload())
          {
            quic_stream_wantwrite(connection, id, true);
          }
        }

        if (benchmarkIsUpload() && requestParsed && consumed < static_cast<size_t>(read))
        {
          bytesInFlight -= std::min<int64_t>(bytesInFlight, static_cast<int64_t>(read - consumed));
          if (bytesInFlight == 0)
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
        uint64_t requested = 0;
        memcpy(&requested, state.requestBytes.data(), state.requestBytes.size());
        state.bytesInFlight = static_cast<int64_t>(bswap_64(requested));
        state.requestParsed = true;
        if (!benchmarkIsUpload())
        {
          quic_stream_wantwrite(connection, id, true);
        }
      }

      if (benchmarkIsUpload() && state.requestParsed && consumed < static_cast<size_t>(read))
      {
        state.bytesInFlight -= std::min<int64_t>(state.bytesInFlight, static_cast<int64_t>(read - consumed));
        if (state.bytesInFlight == 0)
        {
          writeServerStream(state, connection, id);
        }
      }

      if (fin)
      {
        state.clientDone = true;
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
      if (state.requestParsed && state.bytesInFlight == 0 && !state.uploadFinSent)
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
          "localhost",
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
        if (streamId == std::numeric_limits<uint64_t>::max())
        {
          quic_stream_bidi_new(conn, 0, false, &streamId);
          quic_stream_wantread(conn, streamId, true);
        }
        advance();
        benchmarkRecordDatagramClientCounters(datagramClientSent, datagramClientReceived);
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
