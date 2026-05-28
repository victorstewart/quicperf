#include "quiche.h"

#include <array>
#include <cinttypes>
#include <deque>
#include <memory>
#include <unordered_map>
#include <vector>

#pragma once

#define LOCAL_CONN_ID_LEN 16

#define MAX_TOKEN_LEN                   \
  sizeof("quiche") - 1 +                \
      sizeof(struct sockaddr_storage) + \
      LOCAL_CONN_ID_LEN

template <Mode mode>
class Quiche : public QuicLibrary<mode> {
private:

  using QuicLibrary<mode>::networkHub;

  int64_t bytesInFlight = -1;
  quiche_config *config = nullptr;
  quiche_conn *conn = nullptr;
  struct sockaddr_in6 *peerAddress = nullptr;
  bool connected = false;
  bool clientDone = false;
  bool importedResumption = false;
  bool importedZeroRtt = false;
  bool resumedObserved = false;
  bool zeroRttObserved = false;
  std::vector<uint8_t> importedSession;
  std::vector<uint8_t> savedSession;
  uint64_t serverDrainDeadlineUs = 0;
  std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
  size_t requestBytesRead = 0;
  bool requestParsed = false;
  bool uploadFinSent = false;
  uint32_t serverCompletedConnections = 0;

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
    bool writeClosed = false;
    bool complete = false;
  };

  struct ServerConn {
    quiche_conn *conn = nullptr;
    struct sockaddr_in6 peerAddress = {};
    int64_t bytesInFlight = -1;
    bool clientDone = false;
    uint64_t serverDrainDeadlineUs = 0;
    std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
    size_t requestBytesRead = 0;
    bool requestParsed = false;
    bool uploadFinSent = false;
    bool complete = false;
    uint64_t datagramReceived = 0;
    uint64_t datagramEchoed = 0;
    std::deque<uint64_t> datagramPendingEchoes;
    std::vector<uint8_t> datagramSeen;
    std::unordered_map<uint64_t, GenericStreamState> genericStreams;
    uint64_t genericCompletedStreams = 0;
  };

  std::vector<std::unique_ptr<ServerConn>> serverConns;
  std::unordered_map<std::string, ServerConn *> serverConnsByPeer;
  std::unordered_map<uint64_t, GenericStreamState> genericClientStreams;
  bool genericStarted = false;
  uint64_t genericClientBytes = 0;
  uint64_t genericRequestedStreams = 0;
  uint64_t genericOpenedStreams = 0;
  uint64_t genericCompletedStreams = 0;
  uint64_t datagramClientSent = 0;
  uint64_t datagramClientReceived = 0;
  uint64_t datagramClientDrainDeadlineUs = 0;
  std::vector<uint8_t> datagramClientSeen;
  std::array<uint8_t, benchmarkAppChunkSize> datagramScratch = {};

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
      0x71,
      0x75,
      0x69,
      0x63,
      0x68,
      0x65,
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

  static void appendU64BE(std::vector<uint8_t>& out, uint64_t value)
  {
    uint64_t swapped = bswap_64(value);
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&swapped);
    out.insert(out.end(), bytes, bytes + sizeof(swapped));
  }

  static int saveSession(SSL *ssl, SSL_SESSION *session)
  {
    auto self = static_cast<Quiche<mode> *>(SSL_get_app_data(ssl));
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
    return 0;
  }

  SSL *newBenchmarkSsl(void)
  {
    SSL_CTX *ctx = TLS::getTLSCtx();
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(ctx, saveSession);
    SSL_CTX_set_early_data_enabled(ctx, 1);
    SSL_CTX_set_session_psk_dhe_timeout(ctx, benchmarkIdleTimeoutSeconds);
    SSL_CTX_set_num_tickets(ctx, 2);
    if (SSL_CTX_set_tlsext_ticket_keys(ctx, ticketKey.data(), ticketKey.size()) != 1)
    {
      fprintf(stderr, "quiche: failed to configure benchmark TLS ticket keys\n");
      abort();
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_app_data(ssl, this);
    return ssl;
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
        return genericCompletedStreams >= benchmarkGenericStreamsPerConnection();
      }
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        return datagramClientSent >= benchmarkScenarioOperations &&
               clientDone &&
               datagramClientDrainDeadlineUs != 0 &&
               timeNowUs() >= datagramClientDrainDeadlineUs;
      }
      if (benchmarkIsUpload())
      {
        return clientDone;
      }
      return bytesInFlight == 0;
    }
  }

  void markServerConnComplete(ServerConn& state)
  {
    if (state.complete)
    {
      return;
    }
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if (state.genericCompletedStreams < benchmarkGenericStreamsPerConnection())
      {
        return;
      }
      state.complete = true;
      ++serverCompletedConnections;
      return;
    }
    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      if (!state.clientDone || !state.datagramPendingEchoes.empty())
      {
        return;
      }
      if (state.serverDrainDeadlineUs == 0)
      {
        state.serverDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
        return;
      }
      if (timeNowUs() < state.serverDrainDeadlineUs)
      {
        return;
      }
      state.complete = true;
      ++serverCompletedConnections;
      return;
    }
    if (benchmarkIsUpload())
    {
      if (!state.uploadFinSent || state.serverDrainDeadlineUs == 0 || timeNowUs() < state.serverDrainDeadlineUs)
      {
        return;
      }
    }
    else if (!state.clientDone || state.serverDrainDeadlineUs == 0 || timeNowUs() < state.serverDrainDeadlineUs)
    {
      return;
    }
    state.complete = true;
    ++serverCompletedConnections;
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

  GenericStreamState makeGenericClientStream(uint64_t streamID)
  {
    GenericStreamState state = {};
    state.streamId = streamID;
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

  static GenericStreamState makeGenericServerStream(uint64_t streamID)
  {
    GenericStreamState state = {};
    state.streamId = streamID;
    state.phase = GenericPhase::readRequest;
    return state;
  }

  void markGenericClientComplete(GenericStreamState& state)
  {
    if (state.complete)
    {
      return;
    }
    state.complete = true;
    state.phase = GenericPhase::complete;
    ++genericCompletedStreams;
  }

  ServerConn& serverConnFor(UDPContext *msg)
  {
    std::string key = benchmarkPeerKey(msg->address());
    auto found = serverConnsByPeer.find(key);
    if (found != serverConnsByPeer.end())
    {
      return *found->second;
    }

    auto owned = std::make_unique<ServerConn>();
    memcpy(&owned->peerAddress, msg->address(), sizeof(struct sockaddr_in6));
    uint8_t serverscid[8];
    RAND_bytes(serverscid, sizeof(serverscid));
    owned->conn = quiche_conn_new_with_tls(serverscid, sizeof(serverscid), nullptr, 0,
                                           networkHub->socket.address(), networkHub->socket.addressLen,
                                           msg->address(), sizeof(struct sockaddr_in6),
                                           config, newBenchmarkSsl(), true);
    ServerConn *raw = owned.get();
    serverConns.push_back(std::move(owned));
    serverConnsByPeer.emplace(std::move(key), raw);
    return *raw;
  }

  void signalClientDone(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (!clientDone)
      {
        uint64_t streamError = 0;
        quiche_conn_stream_send(conn, 0, nullptr, 0, true, &streamError);
        clientDone = true;
      }
    }
  }

  void maybeStartDatagramClientDrain(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram ||
          datagramClientSent < benchmarkScenarioOperations ||
          !clientDone)
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

  void processClientDatagramReadable(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (conn == nullptr)
      {
        return;
      }
      bool receivedAny = false;
      while (true)
      {
        static uint8_t buf[65'535];
        ssize_t received = quiche_conn_dgram_recv(conn, buf, sizeof(buf));
        if (received <= 0)
        {
          break;
        }
        receivedAny = true;
        const uint64_t sequence = benchmarkDecodeDatagramSequence(buf, static_cast<size_t>(received));
        if (benchmarkMarkDatagramSeen(datagramClientSeen, sequence))
        {
          ++datagramClientReceived;
        }
        maybeStartDatagramClientDrain();
      }
      if (receivedAny && datagramClientSent < benchmarkScenarioOperations)
      {
        processClientDatagramWritable();
      }
    }
  }

  void processClientDatagramWritable(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (conn == nullptr || datagramClientSent >= benchmarkScenarioOperations)
      {
        return;
      }
      const uint64_t maxInFlight = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
      const ssize_t writableLen = quiche_conn_dgram_max_writable_len(conn);
      const size_t payloadSize = benchmarkDatagramPayloadBytesForPayloadLimit(
          sizeof(networkHub->junk),
          writableLen > 0 ? static_cast<uint64_t>(writableLen) : 0);
      if (payloadSize == 0)
      {
        return;
      }
      uint64_t sentThisRound = 0;
      while (sentThisRound < maxInFlight &&
             datagramClientSent < benchmarkScenarioOperations)
      {
        benchmarkFillDatagramPayload(datagramScratch.data(), payloadSize, networkHub->junk, datagramClientSent);
        ssize_t sent = quiche_conn_dgram_send(conn, datagramScratch.data(), payloadSize);
        if (sent <= 0)
        {
          break;
        }
        ++datagramClientSent;
        ++sentThisRound;
      }
      if (datagramClientSent >= benchmarkScenarioOperations)
      {
        signalClientDone();
        maybeStartDatagramClientDrain();
      }
    }
  }

  void processServerDatagramReadable(ServerConn& state)
  {
    while (true)
    {
      static uint8_t buf[65'535];
      ssize_t received = quiche_conn_dgram_recv(state.conn, buf, sizeof(buf));
      if (received <= 0)
      {
        break;
      }
      const uint64_t sequence = benchmarkDecodeDatagramSequence(buf, static_cast<size_t>(received));
      if (benchmarkMarkDatagramSeen(state.datagramSeen, sequence))
      {
        ++state.datagramReceived;
        state.datagramPendingEchoes.push_back(sequence);
      }
    }
    uint64_t streamID = 0;
    quiche_stream_iter *readable = quiche_conn_readable(state.conn);
    while (quiche_stream_iter_next(readable, &streamID))
    {
      while (true)
      {
        static uint8_t buf[65'535];
        bool fin = false;
        uint64_t streamError = 0;
        ssize_t recv_len = quiche_conn_stream_recv(state.conn, streamID, buf, sizeof(buf), &fin, &streamError);
        if (recv_len < 0)
        {
          break;
        }
        if (fin)
        {
          state.clientDone = true;
        }
        if (recv_len == 0 || fin)
        {
          break;
        }
      }
    }
    quiche_stream_iter_free(readable);
  }

  void processServerDatagramWritable(ServerConn& state)
  {
    const ssize_t writableLen = quiche_conn_dgram_max_writable_len(state.conn);
    const size_t payloadSize = benchmarkDatagramPayloadBytesForPayloadLimit(
        sizeof(networkHub->junk),
        writableLen > 0 ? static_cast<uint64_t>(writableLen) : 0);
    if (payloadSize == 0)
    {
      markServerConnComplete(state);
      return;
    }
    while (!state.datagramPendingEchoes.empty())
    {
      benchmarkFillDatagramPayload(datagramScratch.data(), payloadSize, networkHub->junk, state.datagramPendingEchoes.front());
      ssize_t sent = quiche_conn_dgram_send(state.conn, datagramScratch.data(), payloadSize);
      if (sent <= 0)
      {
        break;
      }
      state.datagramPendingEchoes.pop_front();
      ++state.datagramEchoed;
    }
    if (state.datagramEchoed > 0)
    {
      flushPackets(state);
    }
    markServerConnComplete(state);
  }

  void sendUploadAck(void)
  {
    if (!benchmarkIsUpload() || !requestParsed || bytesInFlight != 0 || uploadFinSent)
    {
      return;
    }

    uint8_t ack = 0;
    uint64_t streamError = 0;
    ssize_t sent = quiche_conn_stream_send(conn, 0, &ack, sizeof(ack), true, &streamError);
    if (sent > 0)
    {
      uploadFinSent = true;
      serverDrainDeadlineUs = timeNowUs() + 100'000;
      flushPackets();
    }
  }

  void sendUploadAck(ServerConn& state)
  {
    if (!benchmarkIsUpload() || !state.requestParsed || state.bytesInFlight != 0 || state.uploadFinSent)
    {
      return;
    }

    uint8_t ack = 0;
    uint64_t streamError = 0;
    ssize_t sent = quiche_conn_stream_send(state.conn, 0, &ack, sizeof(ack), true, &streamError);
    if (sent > 0)
    {
      state.uploadFinSent = true;
      state.serverDrainDeadlineUs = timeNowUs() + 100'000;
      flushPackets(state);
      markServerConnComplete(state);
    }
  }

  void markGenericServerComplete(ServerConn& connState, GenericStreamState& streamState)
  {
    if (streamState.complete)
    {
      return;
    }
    streamState.complete = true;
    streamState.phase = GenericPhase::complete;
    ++connState.genericCompletedStreams;
    markServerConnComplete(connState);
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
      uint64_t active = genericRequestedStreams - genericOpenedStreams;
      for (const auto& item : genericClientStreams)
      {
        if (!item.second.complete)
        {
          ++active;
        }
      }
      while (genericRequestedStreams < targetStreams && active < maxActive)
      {
        const uint64_t streamID = genericRequestedStreams * 4;
        auto inserted = genericClientStreams.emplace(streamID, makeGenericClientStream(streamID));
        if (inserted.second)
        {
          ++genericRequestedStreams;
          ++active;
        }
        else
        {
          break;
        }
      }
    }
  }

  void processClientGenericReadable(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (!genericStarted)
      {
        return;
      }
      uint64_t streamID = 0;
      quiche_stream_iter *readable = quiche_conn_readable(conn);
      while (quiche_stream_iter_next(readable, &streamID))
      {
        auto found = genericClientStreams.find(streamID);
        if (found == genericClientStreams.end())
        {
          continue;
        }
        auto& state = found->second;
        if (state.responseRemaining > 0)
        {
          while (state.responseRemaining > 0)
          {
            static uint8_t buf[65'535];
            bool fin = false;
            uint64_t streamError = 0;
            ssize_t received = quiche_conn_stream_recv(conn, streamID, buf, sizeof(buf), &fin, &streamError);
            if (received <= 0)
            {
              break;
            }
            const uint64_t consumed = std::min<uint64_t>(state.responseRemaining, static_cast<uint64_t>(received));
            state.responseRemaining -= consumed;
            if (state.responseRemaining == 0 || fin)
            {
              break;
            }
          }
          if (state.responseRemaining == 0)
          {
            state.phase = GenericPhase::sendPayload;
          }
        }
        else if (state.writeClosed && state.ackBytesRead < 1)
        {
          uint8_t ack = 0;
          bool fin = false;
          uint64_t streamError = 0;
          ssize_t received = quiche_conn_stream_recv(conn, streamID, &ack, sizeof(ack), &fin, &streamError);
          if (received > 0)
          {
            state.ackBytesRead += static_cast<size_t>(received);
          }
          if (state.ackBytesRead >= 1)
          {
            markGenericClientComplete(state);
          }
        }
      }
      quiche_stream_iter_free(readable);
      processClientGenericWritable();
      openMoreGenericClientStreams();
    }
  }

  void processServerGenericReadable(ServerConn& connState)
  {
    uint64_t streamID = 0;
    quiche_stream_iter *readable = quiche_conn_readable(connState.conn);
    while (quiche_stream_iter_next(readable, &streamID))
    {
      auto [it, inserted] = connState.genericStreams.emplace(streamID, makeGenericServerStream(streamID));
      auto& state = it->second;
      while (true)
      {
        static uint8_t buf[65'535];
        bool fin = false;
        uint64_t streamError = 0;
        ssize_t received = quiche_conn_stream_recv(connState.conn, streamID, buf, sizeof(buf), &fin, &streamError);
        if (received <= 0)
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
                static_cast<uint64_t>(received));
            state.requestBytesRead += copied;
            consumed += static_cast<size_t>(copied);
            if (state.requestBytesRead == state.requestBytesExpected)
            {
              state.responseRemaining = benchmarkGenericReqRespResponseBytes();
              state.phase = GenericPhase::sendResponse;
            }
          }
          else
          {
            while (state.requestBytesRead < state.requestBytes.size() && consumed < static_cast<size_t>(received))
            {
              state.requestBytes[state.requestBytesRead++] = buf[consumed++];
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
            }
          }
        }

        if ((benchmarkScenario == BenchmarkScenario::multistream_upload ||
             benchmarkScenario == BenchmarkScenario::bidi) &&
            consumed < static_cast<size_t>(received) && state.payloadRemaining > 0)
        {
          const uint64_t copied = std::min<uint64_t>(
              state.payloadRemaining,
              static_cast<uint64_t>(received - consumed));
          state.payloadRemaining -= copied;
          if (state.payloadRemaining == 0)
          {
            state.phase = GenericPhase::sendResponse;
          }
        }

        if (state.phase == GenericPhase::readResponse && consumed < static_cast<size_t>(received))
        {
          const size_t copied = std::min<size_t>(1 - state.doneBytesRead, static_cast<size_t>(received) - consumed);
          state.doneBytesRead += copied;
          consumed += copied;
        }

        if (fin)
        {
          break;
        }
      }
    }
    quiche_stream_iter_free(readable);
  }

  void processClientGenericWritable(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (!genericStarted)
      {
        return;
      }
      openMoreGenericClientStreams();
      for (auto& item : genericClientStreams)
      {
        auto& state = item.second;
        if (state.complete || state.writeClosed)
        {
          continue;
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
          uint64_t streamError = 0;
          ssize_t sent = quiche_conn_stream_send(conn, state.streamId, source, chunk, false, &streamError);
          if (sent <= 0)
          {
            break;
          }
          state.requestBytesWritten += static_cast<uint64_t>(sent);
        }
        if (state.requestBytesWritten < state.requestBytesExpected)
        {
          continue;
        }
        while (state.payloadRemaining > 0)
        {
          const size_t chunk = static_cast<size_t>(std::min<uint64_t>(state.payloadRemaining, sizeof(networkHub->junk)));
          uint64_t streamError = 0;
          ssize_t sent = quiche_conn_stream_send(conn, state.streamId, (const uint8_t *)networkHub->junk, chunk, false, &streamError);
          if (sent <= 0)
          {
            break;
          }
          state.payloadRemaining -= static_cast<uint64_t>(sent);
        }
        if (state.payloadRemaining == 0 && state.responseRemaining == 0)
        {
          uint8_t done = 0;
          uint64_t streamError = 0;
          ssize_t sent = quiche_conn_stream_send(conn, state.streamId, &done, sizeof(done), true, &streamError);
          if (sent > 0)
          {
            state.writeClosed = true;
          }
        }
      }
    }
  }

  void processServerGenericWritable(ServerConn& connState)
  {
    for (auto& item : connState.genericStreams)
    {
      auto& state = item.second;
      if (state.complete)
      {
        continue;
      }
      if (state.phase == GenericPhase::readResponse && state.doneBytesRead > 0 && state.ackBytesWritten < 1)
      {
        uint8_t ack = 0;
        uint64_t streamError = 0;
        ssize_t sent = quiche_conn_stream_send(connState.conn, state.streamId, &ack, sizeof(ack), true, &streamError);
        if (sent > 0)
        {
          state.ackBytesWritten += static_cast<size_t>(sent);
          flushPackets(connState);
          drainIouringSends();
          markGenericServerComplete(connState, state);
        }
        continue;
      }
      if (state.phase != GenericPhase::sendResponse)
      {
        continue;
      }
      while (state.responseRemaining > 0)
      {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(state.responseRemaining, sizeof(networkHub->junk)));
        uint64_t streamError = 0;
        ssize_t sent = quiche_conn_stream_send(connState.conn, state.streamId, (const uint8_t *)networkHub->junk, chunk, false, &streamError);
        if (sent <= 0)
        {
          break;
        }
        state.responseRemaining -= static_cast<uint64_t>(sent);
        if (state.responseRemaining == 0)
        {
          state.writeClosed = true;
          flushPackets(connState);
          state.phase = GenericPhase::readResponse;
          if (state.doneBytesRead > 0)
          {
            markGenericServerComplete(connState, state);
          }
        }
      }
    }
  }

  uint64_t flushPackets(quiche_conn *activeConn, struct sockaddr_in6 *activePeerAddress)
  {
    if (unlikely(activeConn == NULL))
    {
      return 0;
    }

    MultiUDPContext *packets = nullptr;
    UDPContext *packet;

    do
    {
      if (packets == nullptr)
      {
        packets = networkHub->sendPool.get();
        if (unlikely(packets == nullptr))
        {
          return 1000;
        }
      }

      packet = &packets->msgs[packets->count];

      quiche_send_info sendInfo = {};
      ssize_t written = quiche_conn_send(activeConn, packet->buffer(), MAX_IPV6_UDP_PACKET_SIZE, &sendInfo);

      if (written == QUICHE_ERR_DONE)
      {
        break;
      }
      if (written < 0)
      {
        break;
      }

      packet->setLength(written);
      packet->copyInAddress(sendInfo.to_len > 0 ? (struct sockaddr *)&sendInfo.to : (struct sockaddr *)activePeerAddress);

      packets->count++;

      if (packets->isFull())
      {
        networkHub->sendBatch(packets);
        packets = nullptr;

        // printf("networkHub->sendPool.howManyLeft() = %lu\n", networkHub->sendPool.howManyLeft());

        // packets = networkHub->sendPool.get();
        // if (unlikely(packets == NULL)) return 10000;
      }

    } while (true);

    if (packets != nullptr)
    {
      if (packets->count > 0)
      {
        networkHub->sendBatch(packets);
      }
      else
      {
        packets->reset();
        networkHub->sendPool.relinquish(packets);
      }
    }

    networkHub->flush();
    return quiche_conn_timeout_as_nanos(activeConn) / 1000;
  }

  uint64_t flushPackets(void)
  {
    return flushPackets(conn, peerAddress);
  }

  uint64_t flushPackets(ServerConn& state)
  {
    return flushPackets(state.conn, &state.peerAddress);
  }

  void drainIouringSends(void)
  {
    if constexpr (mode & Mode::iouring)
    {
      networkHub->drainSendCompletions();
    }
  }

  void processServerReadable(ServerConn& state)
  {
    if (!quiche_conn_is_established(state.conn))
    {
      return;
    }
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      processServerGenericReadable(state);
      return;
    }
    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      processServerDatagramReadable(state);
      return;
    }

    uint64_t streamID = 0;
    quiche_stream_iter *readable = quiche_conn_readable(state.conn);
    while (quiche_stream_iter_next(readable, &streamID))
    {
      while (true)
      {
        static uint8_t buf[65'535];
        bool fin = false;
        uint64_t streamError = 0;
        ssize_t recv_len = quiche_conn_stream_recv(state.conn, streamID, buf, sizeof(buf), &fin, &streamError);
        if (recv_len < 0)
        {
          break;
        }

        size_t consumed = 0;
        while (state.requestBytesRead < state.requestBytes.size() && consumed < static_cast<size_t>(recv_len))
        {
          state.requestBytes[state.requestBytesRead++] = buf[consumed++];
        }

        if (!state.requestParsed && state.requestBytesRead == state.requestBytes.size())
        {
          uint64_t requested = 0;
          memcpy(&requested, state.requestBytes.data(), state.requestBytes.size());
          state.bytesInFlight = static_cast<int64_t>(bswap_64(requested));
          state.requestParsed = true;
        }

        if (benchmarkIsUpload() && state.requestParsed && consumed < static_cast<size_t>(recv_len))
        {
          state.bytesInFlight -= std::min<int64_t>(state.bytesInFlight, static_cast<int64_t>(recv_len - consumed));
          sendUploadAck(state);
        }

        if (fin)
        {
          state.clientDone = true;
        }
        if (recv_len == 0 || fin)
        {
          break;
        }
      }
    }
    quiche_stream_iter_free(readable);
  }

  void processServerWritable(ServerConn& state)
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      processServerGenericWritable(state);
      return;
    }
    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      processServerDatagramWritable(state);
      return;
    }
    if (benchmarkIsUpload())
    {
      sendUploadAck(state);
      return;
    }
    if (state.bytesInFlight <= 0 || quiche_conn_stream_capacity(state.conn, 0) <= 0)
    {
      return;
    }

    do
    {
      size_t sendLength = static_cast<size_t>(
          std::min<int64_t>(state.bytesInFlight, sizeof(networkHub->junk)));
      bool fin = sendLength == static_cast<size_t>(state.bytesInFlight);
      uint64_t streamError = 0;
      ssize_t sent = quiche_conn_stream_send(state.conn, 0, (const uint8_t *)networkHub->junk, sendLength, fin, &streamError);

      if (sent > 0)
      {
        state.bytesInFlight -= sent;
      }
      else
      {
        break;
      }
    } while (true);

    if (state.bytesInFlight == 0)
    {
      flushPackets(state);
      if (state.serverDrainDeadlineUs == 0)
      {
        state.serverDrainDeadlineUs = timeNowUs() + 100'000;
      }
      markServerConnComplete(state);
    }
  }

  void advance(int32_t count = 0)
  {
    if constexpr (mode & Mode::server)
    {
      uint32_t completeDrainLoops = 0;
      do
      {
        const bool completeBeforePoll = perfComplete();
        if (completeBeforePoll)
        {
          if constexpr (mode & Mode::iouring)
          {
            if (completeDrainLoops++ >= 64)
            {
              break;
            }
          }
          else
          {
            break;
          }
        }
        uint64_t usTil = 100'000;
        for (auto& active : serverConns)
        {
          usTil = std::min<uint64_t>(usTil, flushPackets(*active));
        }
        usTil = std::min<uint64_t>(usTil, 100'000);
        if (completeBeforePoll)
        {
          usTil = 0;
        }

        bool timedout = networkHub->recvmsgWithTimeout(usTil, [&](UDPContext *msg) -> void {
          ServerConn& state = serverConnFor(msg);
          quiche_recv_info recvInfo = {
              .from = msg->address(),
              .from_len = sizeof(struct sockaddr_in6),
              .to = networkHub->socket.address(),
              .to_len = networkHub->socket.addressLen,
          };
          quiche_conn_recv(state.conn, msg->buffer(), msg->msg_len, &recvInfo);
          processServerReadable(state);
        });

        if (timedout)
        {
          for (auto& active : serverConns)
          {
            quiche_conn_on_timeout(active->conn);
          }
        }

        for (auto& active : serverConns)
        {
          processServerWritable(*active);
          markServerConnComplete(*active);
        }
        if (count != 0 && --count == 0)
        {
          break;
        }
      } while (true);
      return;
    }

    do
    {
      if constexpr (mode & Mode::client)
      {
        if (conn != nullptr && quiche_conn_is_in_early_data(conn))
        {
          zeroRttObserved = true;
        }
      }
      uint64_t usTil = conn == nullptr ? 100'000 : flushPackets();
      if (benchmarkScenario == BenchmarkScenario::datagram && connected)
      {
        usTil = std::min<uint64_t>(usTil, 1000);
      }
      usTil = std::min<uint64_t>(usTil, 100'000);

      bool timedout = networkHub->recvmsgWithTimeout(usTil, [&](UDPContext *msg) -> void {
        if constexpr (mode & Mode::server)
        {
          if (conn == NULL)
          {
            uint8_t serverscid[8];
            RAND_bytes(serverscid, sizeof(serverscid));

            peerAddress = (struct sockaddr_in6 *)malloc(sizeof(struct sockaddr_in6));
            memcpy(peerAddress, msg->address(), sizeof(struct sockaddr_in6));

            conn = quiche_conn_new_with_tls(serverscid, sizeof(serverscid), NULL, 0,
                                            networkHub->socket.address(), networkHub->socket.addressLen,
                                            msg->address(), sizeof(struct sockaddr_in6),
                                            config, newBenchmarkSsl(), true);
          }
        }

        quiche_recv_info recvInfo = {
            .from = msg->address(),
            .from_len = sizeof(struct sockaddr_in6),
            .to = networkHub->socket.address(),
            .to_len = networkHub->socket.addressLen,
        };
        quiche_conn_recv(conn, msg->buffer(), msg->msg_len, &recvInfo);

        if (quiche_conn_is_established(conn))
        {
          // printf("quiche_conn_stream_capacity = %lld\n", quiche_conn_stream_capacity(conn, 0));

          if constexpr (mode & Mode::client)
          {
            connected = true;
            resumedObserved = quiche_conn_is_resumed(conn);
            if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
            {
              processClientGenericReadable();
              return;
            }
            if (benchmarkScenario == BenchmarkScenario::datagram)
            {
              processClientDatagramReadable();
              return;
            }
          }

          uint64_t streamID = 0;
          quiche_stream_iter *readable = quiche_conn_readable(conn);

          while (quiche_stream_iter_next(readable, &streamID))
          {
            while (true)
            {
              static uint8_t buf[65'535];

              bool fin = false;
              uint64_t streamError = 0;
              ssize_t recv_len = quiche_conn_stream_recv(conn, streamID, buf, sizeof(buf), &fin, &streamError);

              if (recv_len < 0)
              {
                break;
              }

              if constexpr (mode & Mode::client)
              {
                if (benchmarkIsUpload())
                {
                  if (recv_len > 0 || fin || quiche_conn_stream_finished(conn, streamID))
                  {
                    clientDone = true;
                  }
                  if (recv_len == 0 || fin)
                  {
                    break;
                  }
                  continue;
                }

                // throw bytes away
                bytesInFlight -= recv_len;
                if (bytesInFlight <= 0)
                {
                  bytesInFlight = 0;
                  signalClientDone();
                }
                // printf("received %.1f%%\n", 100.0 * (double)(_1GB - bytesInFlight)/(double)_1GB);
              }
              else
              {
                size_t consumed = 0;
                while (requestBytesRead < requestBytes.size() && consumed < static_cast<size_t>(recv_len))
                {
                  requestBytes[requestBytesRead++] = buf[consumed++];
                }

                if (!requestParsed && requestBytesRead == requestBytes.size())
                {
                  uint64_t requested = 0;
                  memcpy(&requested, requestBytes.data(), requestBytes.size());
                  bytesInFlight = static_cast<int64_t>(bswap_64(requested));
                  requestParsed = true;
                }

                if (benchmarkIsUpload() && requestParsed && consumed < static_cast<size_t>(recv_len))
                {
                  bytesInFlight -= std::min<int64_t>(bytesInFlight, static_cast<int64_t>(recv_len - consumed));
                  sendUploadAck();
                }

                if (fin)
                {
                  clientDone = true;
                }
              }
              if (recv_len == 0 || fin)
              {
                break;
              }
            }
          }

          quiche_stream_iter_free(readable);
        }
      });

      if (timedout && conn != nullptr)
      {
        quiche_conn_on_timeout(conn);
      }

      if constexpr (mode & Mode::server)
      {
        if (conn == NULL)
        {
          continue;
        }

        if (benchmarkIsUpload())
        {
          sendUploadAck();
        }
        else if (bytesInFlight > 0 && quiche_conn_stream_capacity(conn, 0) > 0)
        {
          do
          {
            size_t sendLength = static_cast<size_t>(
                std::min<int64_t>(bytesInFlight, sizeof(networkHub->junk)));
            bool fin = sendLength == static_cast<size_t>(bytesInFlight);
            uint64_t streamError = 0;
            ssize_t sent = quiche_conn_stream_send(conn, 0, (const uint8_t *)networkHub->junk, sendLength, fin, &streamError);

            if (sent > 0)
            {
              bytesInFlight -= sent;
            }
            else
            {
              break;
            }

          } while (true);

          if (bytesInFlight == 0)
          {
            flushPackets();
            if (serverDrainDeadlineUs == 0)
            {
              serverDrainDeadlineUs = timeNowUs() + 100'000;
            }
          }
        }
      }
      else
      {
        if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
        {
          processClientGenericWritable();
          flushPackets();
        }
        else if (benchmarkScenario == BenchmarkScenario::datagram)
        {
          processClientDatagramReadable();
          processClientDatagramWritable();
          flushPackets();
        }
        else if (benchmarkIsUpload() && bytesInFlight > 0 && quiche_conn_stream_capacity(conn, 0) > 0)
        {
          do
          {
            size_t sendLength = static_cast<size_t>(
                std::min<int64_t>(bytesInFlight, sizeof(networkHub->junk)));
            bool fin = sendLength == static_cast<size_t>(bytesInFlight);
            uint64_t streamError = 0;
            ssize_t sent = quiche_conn_stream_send(conn, 0, (const uint8_t *)networkHub->junk, sendLength, fin, &streamError);

            if (sent > 0)
            {
              bytesInFlight -= sent;
            }
            else
            {
              break;
            }

          } while (true);

          if (bytesInFlight == 0)
          {
            flushPackets();
          }
        }

        if (clientDone)
        {
          flushPackets();
        }
      }
    } while (!perfComplete() && (count == 0 || --count > 0));
  }

public:

  // static void log(const char *line, void *argp)
  // {
  // 	printf("%s\n", line);
  // }

  void instanceSetup(uint16_t localPort, int argc, char *argv[])
  {
    networkHub = new NetworkHub<mode>(localPort);

    config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    const uint8_t alpn[] = {4, 'p', 'e', 'r', 'f'};
    if (quiche_config_set_application_protos(config, alpn, sizeof(alpn)) != 0)
    {
      fprintf(stderr, "quiche: failed to configure ALPN\n");
      abort();
    }
    quiche_config_verify_peer(config, benchmarkTlsVerifyPeer());
    if constexpr (mode & Mode::server)
    {
      if (quiche_config_load_cert_chain_from_pem_file(config, tls_cert) != 0 ||
          quiche_config_load_priv_key_from_pem_file(config, tls_key) != 0)
      {
        fprintf(stderr, "quiche: failed to load TLS certificate cert=%s key=%s\n", tls_cert, tls_key);
        abort();
      }
    }
    else if (benchmarkTlsVerifyPeer() &&
             quiche_config_load_verify_locations_from_file(config, tls_chain) != 0)
    {
      fprintf(stderr, "quiche: failed to load TLS trust chain=%s\n", tls_chain);
      abort();
    }

    quiche_config_set_max_idle_timeout(config, benchmarkIdleTimeoutMs);
    quiche_config_set_max_recv_udp_payload_size(config, benchmarkUdpPayloadSize);
    quiche_config_set_max_send_udp_payload_size(config, benchmarkUdpPayloadSize);
    quiche_config_set_initial_max_data(config, benchmarkConnectionWindow);
    quiche_config_set_initial_max_stream_data_bidi_local(config, benchmarkStreamWindow);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, benchmarkStreamWindow);
    quiche_config_set_initial_max_stream_data_uni(config, benchmarkStreamWindow);
    quiche_config_set_initial_max_streams_bidi(config, benchmarkMaxBidiStreams);
    quiche_config_set_initial_max_streams_uni(config, benchmarkMaxUniStreams);
    quiche_config_set_ack_delay_exponent(config, benchmarkAckDelayExponent);
    quiche_config_set_max_ack_delay(config, benchmarkMaxAckDelayMs);
    quiche_config_set_disable_active_migration(config, true);
    quiche_config_set_cc_algorithm(config,
                                   benchmarkCongestionProfileUsesCubic() ? QUICHE_CC_CUBIC : QUICHE_CC_BBR2_GCONGESTION);
    quiche_config_set_max_connection_window(config, benchmarkConnectionWindow);
    quiche_config_set_max_stream_window(config, benchmarkStreamWindow);
    quiche_config_enable_dgram(config, true,
                               benchmarkDatagramQueueBytes,
                               benchmarkDatagramQueueBytes);
    quiche_config_enable_early_data(config);
    if (quiche_config_set_ticket_key(config, ticketKey.data(), ticketKey.size()) != 0)
    {
      fprintf(stderr, "quiche: failed to configure session ticket key\n");
      abort();
    }
    // quiche_config_enable_hystart(config, true);

    // quiche_enable_debug_logging(log, NULL);
  }

  void createClientConnection(struct sockaddr *address)
  {
    peerAddress = (struct sockaddr_in6 *)address;

    uint8_t scid[8];
    RAND_bytes(scid, sizeof(scid));

    conn = quiche_conn_new_with_tls((const uint8_t *)scid, sizeof(scid), NULL, 0,
                                    networkHub->socket.address(), networkHub->socket.addressLen,
                                    address, sizeof(struct sockaddr_in6),
                                    config, newBenchmarkSsl(), false);
    if (conn == nullptr)
    {
      fprintf(stderr, "quiche: failed to create client connection\n");
      abort();
    }
    if (importedResumption)
    {
      if (quiche_conn_set_session(conn, importedSession.data(), importedSession.size()) != 0)
      {
        fprintf(stderr, "quiche: failed to set resumption session\n");
        abort();
      }
    }
  }

  void connectToServer(struct sockaddr *address)
  {
    createClientConnection(address);

    do
    {
      advance(1);

    } while (connected == false);
  }

  void connectToServerForZeroRtt(struct sockaddr *address) override
  {
    createClientConnection(address);
    zeroRttObserved = quiche_conn_is_in_early_data(conn);
    flushPackets();
  }

  void openStream(void)
  {
    // just nop this for now

    // do
    // {
    // 	advance(1);

    // } while (ready == false);
  }

  void startPerfTest(uint64_t nBytes)
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
        processClientGenericWritable();
        flushPackets();
        advance();
        return;
      }
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        datagramClientSent = 0;
        datagramClientReceived = 0;
        datagramClientDrainDeadlineUs = 0;
        datagramClientSeen.assign(benchmarkDatagramSeenBytes(), 0);
        datagramScratch.fill(0);
        clientDone = false;
        processClientDatagramWritable();
        flushPackets();
        advance();
        benchmarkRecordDatagramClientCounters(datagramClientSent, datagramClientReceived);
        return;
      }
      bytesInFlight = nBytes;

      uint64_t swappedBytes = bswap_64(bytesInFlight);
      uint64_t streamError = 0;
      quiche_conn_stream_send(conn, 0, (const uint8_t *)&swappedBytes, 8, false, &streamError);
    }

    advance();
  }

  void postPerfTest() override
  {
    if constexpr (mode & Mode::client)
    {
      if (!benchmarkIsLossRecovery() || benchmarkIsUpload() || !clientDone)
      {
        return;
      }

      const uint64_t deadlineUs = timeNowUs() + 100'000;
      do
      {
        advance(1);
      } while (timeNowUs() < deadlineUs);
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
      if (!savedSession.empty())
      {
        state.session = savedSession;
        state.proofLabel = "quiche_boringssl_new_session";
        return true;
      }
      for (int i = 0; i < 100; ++i)
      {
        const uint8_t *session = nullptr;
        size_t sessionLen = 0;
        quiche_conn_session(conn, &session, &sessionLen);
        if (session != nullptr && sessionLen > 0)
        {
          state.session.assign(session, session + sessionLen);
          state.proofLabel = "quiche_conn_session";
          return true;
        }
        advance(1);
        if (!savedSession.empty())
        {
          state.session = savedSession;
          state.proofLabel = "quiche_boringssl_new_session";
          return true;
        }
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
    (void)importedZeroRtt;
    return true;
  }

  bool connectionWasResumed(void) const override
  {
    return resumedObserved || (conn != nullptr && quiche_conn_is_resumed(conn));
  }

  bool zeroRttWasAttempted(void) const override
  {
    return importedZeroRtt && zeroRttObserved;
  }

  bool zeroRttWasAccepted(void) const override
  {
    return importedZeroRtt && zeroRttObserved && connectionWasResumed();
  }

  bool zeroRttWasRejected(void) const override
  {
    return importedZeroRtt && zeroRttObserved && !connectionWasResumed();
  }

  const char *resumptionProofLabel(void) const override
  {
    return "quiche_session_and_is_resumed";
  }
};
