#include <cassert>
#include <array>
#include <deque>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <openssl/rand.h>

#pragma once

template <Mode mode> class Ngtcp2 : public QuicLibrary<mode> {
private:

  using QuicLibrary<mode>::networkHub;

  SSL_CTX *ssl_ctx = nullptr;
  SSL *ssl = nullptr;
  ngtcp2_conn *conn = nullptr;
  struct sockaddr_in6 clientPeerAddress = {};
  std::vector<uint8_t> savedSession;
  std::vector<uint8_t> savedTransportParams;
  std::vector<uint8_t> importedSession;
  std::vector<uint8_t> importedTransportParams;
  bool importedResumption = false;
  bool importedZeroRtt = false;
  bool resumedObserved = false;
  bool zeroRttAttemptedObserved = false;
  bool zeroRttAcceptedObserved = false;
  bool zeroRttRejectedObserved = false;
  uint8_t alert = 0;
  int64_t bytesInFlight = -1;
  bool data_ready = false;
  std::array<uint8_t, sizeof(int64_t)> reqsizebuf;
  size_t reqsizebuflen = 0;
  size_t reqsizebufoffset = 0;
  bool stream_opened = false;
  bool requestParsed = false;
  bool clientDone = false;
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

  enum class GenericSendKind : uint8_t {
    none,
    request,
    payload,
    done,
    response,
    ack
  };

  struct GenericStreamState {
    int64_t streamId = -1;
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
    bool complete = false;
  };

  struct ServerConnState {
    ngtcp2_conn *conn = nullptr;
    SSL *ssl = nullptr;
    uint8_t alert = 0;
    int64_t bytesInFlight = -1;
    bool data_ready = false;
    std::array<uint8_t, sizeof(int64_t)> reqsizebuf = {};
    size_t reqsizebuflen = 0;
    size_t reqsizebufoffset = 0;
    bool stream_opened = false;
    bool requestParsed = false;
    bool clientDone = false;
    bool uploadFinSent = false;
    bool complete = false;
    struct sockaddr_in6 peerAddress = {};
    uint64_t responseBytesTarget = 0;
    uint64_t responseBytesAcked = 0;
    std::unordered_map<int64_t, std::unique_ptr<GenericStreamState>> genericStreams;
    uint64_t genericCompletedStreams = 0;
    uint64_t datagramReceived = 0;
    uint64_t datagramEchoed = 0;
    std::deque<uint64_t> datagramPendingEchoes;
    std::vector<uint8_t> datagramSeen;
    uint64_t datagramDrainDeadlineUs = 0;
    bool datagramClientDone = false;
  };

  std::vector<std::unique_ptr<ServerConnState>> serverConns;
  std::unordered_map<std::string, ServerConnState *> serverConnsByPeer;
  ServerConnState *activeServerState = nullptr;
  std::vector<std::unique_ptr<GenericStreamState>> genericClientStreams;
  bool genericStarted = false;
  uint64_t genericClientBytes = 0;
  uint64_t genericRequestedStreams = 0;
  uint64_t genericOpenedStreams = 0;
  uint64_t genericCompletedStreams = 0;
  GenericStreamState *activeGenericSend = nullptr;
  GenericSendKind activeGenericSendKind = GenericSendKind::none;
  uint64_t datagramClientSent = 0;
  uint64_t datagramClientReceived = 0;
  uint64_t datagramClientDrainDeadlineUs = 0;
  bool datagramStarted = false;
  bool datagramDoneSignalSent = false;
  bool datagramDoneStreamWritten = false;
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
      0x6e,
      0x67,
      0x74,
      0x63,
      0x70,
      0x32,
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
                      : static_cast<Ngtcp2<mode> *>(SSL_CTX_get_ex_data(ctx, sslCtxSelfIndex()));
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
      self->savedSession.assign(sessionOut, sessionOut + sessionLen);
      OPENSSL_free(sessionOut);
    }
    return 0;
  }

  void configureTLS(void)
  {
    ssl_ctx = TLS::getTLSCtx();
    if (ssl_ctx == nullptr)
    {
      fprintf(stderr, "ngtcp2: failed to create benchmark SSL_CTX\n");
      abort();
    }
    if (SSL_CTX_set_tlsext_ticket_keys(ssl_ctx, ticketKey.data(), ticketKey.size()) != 1)
    {
      fprintf(stderr, "ngtcp2: failed to configure session ticket key\n");
      abort();
    }
    SSL_CTX_set_early_data_enabled(ssl_ctx, 1);
    SSL_CTX_set_session_psk_dhe_timeout(ssl_ctx, benchmarkIdleTimeoutSeconds);
    SSL_CTX_set_num_tickets(ssl_ctx, 2);
    SSL_CTX_set_ex_data(ssl_ctx, sslCtxSelfIndex(), this);
    if constexpr (mode & Mode::client)
    {
      SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
      SSL_CTX_sess_set_new_cb(ssl_ctx, saveSession);
    }
    SSL_CTX_set_quic_method(ssl_ctx, &quic_method);
  }

  void captureTransportParams(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (conn == nullptr)
      {
        return;
      }
      std::array<uint8_t, 512> data = {};
      ngtcp2_ssize len = ngtcp2_conn_encode_0rtt_transport_params(conn, data.data(), data.size());
      if (len > 0)
      {
        savedTransportParams.assign(data.data(), data.data() + static_cast<size_t>(len));
      }
    }
  }

  bool perfComplete() const
  {
    if constexpr (mode & Mode::server)
    {
      return serverCompletedConnections >= benchmarkServerTargetConnections;
    }
    else if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      return genericCompletedStreams >= benchmarkGenericStreamsPerConnection();
    }
    else if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      return datagramClientSent >= benchmarkScenarioOperations &&
             datagramDoneSignalSent &&
             datagramDoneStreamWritten &&
             datagramClientDrainDeadlineUs != 0 &&
             timeNowUs() >= datagramClientDrainDeadlineUs;
    }
    else if (benchmarkIsUpload())
    {
      return clientDone;
    }

    return bytesInFlight == 0;
  }

  void loadServerState(ServerConnState& state)
  {
    activeServerState = &state;
    conn = state.conn;
    ssl = state.ssl;
    alert = state.alert;
    bytesInFlight = state.bytesInFlight;
    data_ready = state.data_ready;
    reqsizebuf = state.reqsizebuf;
    reqsizebuflen = state.reqsizebuflen;
    reqsizebufoffset = state.reqsizebufoffset;
    stream_opened = state.stream_opened;
    requestParsed = state.requestParsed;
    clientDone = state.clientDone;
    uploadFinSent = state.uploadFinSent;
  }

  void saveServerState(ServerConnState& state)
  {
    state.conn = conn;
    state.ssl = ssl;
    state.alert = alert;
    state.bytesInFlight = bytesInFlight;
    state.data_ready = data_ready;
    state.reqsizebuf = reqsizebuf;
    state.reqsizebuflen = reqsizebuflen;
    state.reqsizebufoffset = reqsizebufoffset;
    state.stream_opened = stream_opened;
    state.requestParsed = requestParsed;
    state.clientDone = clientDone;
    state.uploadFinSent = uploadFinSent;
  }

  void markServerStateComplete(ServerConnState& state)
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
      if (!state.datagramClientDone || !state.datagramPendingEchoes.empty())
      {
        return;
      }
      if (state.datagramDrainDeadlineUs == 0)
      {
        state.datagramDrainDeadlineUs = timeNowUs() + benchmarkDatagramDrainUs;
      }
      if (timeNowUs() < state.datagramDrainDeadlineUs)
      {
        return;
      }
      state.complete = true;
      ++serverCompletedConnections;
      return;
    }
    if (benchmarkIsUpload())
    {
      if (!state.uploadFinSent)
      {
        return;
      }
    }
    else if (benchmarkIsLossRecovery() && !state.clientDone)
    {
      return;
    }
    else if (state.bytesInFlight != 0 || state.responseBytesAcked < state.responseBytesTarget)
    {
      return;
    }
    state.complete = true;
    ++serverCompletedConnections;
  }

  ServerConnState& serverStateFor(UDPContext *msg)
  {
    std::string key = benchmarkPeerKey(msg->address());
    auto found = serverConnsByPeer.find(key);
    if (found != serverConnsByPeer.end())
    {
      return *found->second;
    }

    auto owned = std::make_unique<ServerConnState>();
    ServerConnState *raw = owned.get();
    memcpy(&raw->peerAddress, msg->address(), sizeof(raw->peerAddress));
    serverConns.push_back(std::move(owned));
    serverConnsByPeer.emplace(std::move(key), raw);
    loadServerState(*raw);
    init_conn_server(msg);
    saveServerState(*raw);
    return *raw;
  }

  ServerConnState *serverStateForConn(ngtcp2_conn *connection)
  {
    if (activeServerState != nullptr && activeServerState->conn == connection)
    {
      return activeServerState;
    }
    for (auto& state : serverConns)
    {
      if (state->conn == connection)
      {
        return state.get();
      }
    }
    return nullptr;
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

  void initializeGenericClientState(GenericStreamState& state)
  {
    state.phase = GenericPhase::sendRequest;
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
  }

  GenericStreamState *serverGenericStreamFor(int64_t streamId, void *streamUserData)
  {
    if (streamUserData != nullptr)
    {
      return static_cast<GenericStreamState *>(streamUserData);
    }
    if (activeServerState == nullptr)
    {
      return nullptr;
    }
    auto found = activeServerState->genericStreams.find(streamId);
    if (found != activeServerState->genericStreams.end())
    {
      return found->second.get();
    }
    auto state = std::make_unique<GenericStreamState>();
    state->streamId = streamId;
    state->phase = GenericPhase::readRequest;
    GenericStreamState *raw = state.get();
    activeServerState->genericStreams.emplace(streamId, std::move(state));
    ngtcp2_conn_set_stream_user_data(conn, streamId, raw);
    return raw;
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

  void markGenericServerComplete(GenericStreamState *state)
  {
    if (state == nullptr || state->complete || activeServerState == nullptr)
    {
      return;
    }
    state->complete = true;
    state->phase = GenericPhase::complete;
    ++activeServerState->genericCompletedStreams;
    ngtcp2_conn_extend_max_streams_bidi(conn, 1);
    markServerStateComplete(*activeServerState);
  }

  void openMoreGenericClientStreams()
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
      for (const auto& state : genericClientStreams)
      {
        if (!state->complete)
        {
          ++active;
        }
      }
      while (genericRequestedStreams < targetStreams && active < maxActive)
      {
        auto state = std::make_unique<GenericStreamState>();
        initializeGenericClientState(*state);
        int64_t streamId = -1;
        GenericStreamState *raw = state.get();
        int rv = ngtcp2_conn_open_bidi_stream(conn, &streamId, raw);
        if (rv != 0)
        {
          break;
        }
        raw->streamId = streamId;
        genericClientStreams.push_back(std::move(state));
        ++genericRequestedStreams;
        ++active;
      }
    }
  }

  size_t datagramPayloadSize() const
  {
    uint64_t maxFrameBytes = benchmarkUdpPayloadSize;
    if (conn != nullptr)
    {
      const ngtcp2_transport_params *remoteParams =
          ngtcp2_conn_get_remote_transport_params(conn);
      if (remoteParams != nullptr)
      {
        maxFrameBytes = remoteParams->max_datagram_frame_size;
      }
    }
    return benchmarkDatagramPayloadBytesForNoMssApiLimit(
        sizeof(networkHub->junk),
        maxFrameBytes);
  }

  void maybeStartDatagramClientDrain()
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

  bool datagramClientCanSend() const
  {
    if (benchmarkScenario != BenchmarkScenario::datagram || conn == nullptr ||
        !datagramStarted || datagramClientSent >= benchmarkScenarioOperations)
    {
      return false;
    }
    if (datagramPayloadSize() == 0)
    {
      return false;
    }
    return true;
  }

  void signalDatagramDoneWhenSendBudgetReached()
  {
    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenario == BenchmarkScenario::datagram &&
          datagramClientSent >= benchmarkScenarioOperations &&
          !datagramDoneSignalSent)
      {
        datagramDoneSignalSent = true;
        data_ready = true;
      }
    }
  }

  bool tryOpenClientStream()
  {
    if (stream_opened)
    {
      return true;
    }

    int64_t stream_id;
    if (auto rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, nullptr);
        rv != 0)
    {
      assert(NGTCP2_ERR_STREAM_ID_BLOCKED == rv);
      return false;
    }

    assert(0 == stream_id);
    stream_opened = true;

    return true;
  }

  static int set_read_secret(SSL *ssl, enum ssl_encryption_level_t ssl_level,
                             const SSL_CIPHER *cipher, const uint8_t *secret,
                             size_t secretlen)
  {
    auto c = static_cast<Ngtcp2<mode> *>(SSL_get_app_data(ssl));
    auto level = ngtcp2_crypto_boringssl_from_ssl_encryption_level(ssl_level);

    if (ngtcp2_crypto_derive_and_install_rx_key(
            c->conn, nullptr, nullptr, nullptr, level, secret, secretlen) != 0)
    {
      return 0;
    }

    return 1;
  }

  static int set_write_secret(SSL *ssl, enum ssl_encryption_level_t ssl_level,
                              const SSL_CIPHER *cipher, const uint8_t *secret,
                              size_t secretlen)
  {
    auto c = static_cast<Ngtcp2<mode> *>(SSL_get_app_data(ssl));
    auto level = ngtcp2_crypto_boringssl_from_ssl_encryption_level(ssl_level);

    if (ngtcp2_crypto_derive_and_install_tx_key(
            c->conn, nullptr, nullptr, nullptr, level, secret, secretlen) != 0)
    {
      return 0;
    }

    return 1;
  }

  static int add_handshake_data(SSL *ssl, enum ssl_encryption_level_t ssl_level,
                                const uint8_t *data, size_t len)
  {
    auto c = static_cast<Ngtcp2<mode> *>(SSL_get_app_data(ssl));
    auto level = ngtcp2_crypto_boringssl_from_ssl_encryption_level(ssl_level);

    if (auto rv = ngtcp2_conn_submit_crypto_data(c->conn, level, data, len);
        rv != 0)
    {
      std::cerr << "ngtcp2_conn_submit_crypto_data: " << ngtcp2_strerror(rv)
                << std::endl;
      assert(0);
      abort();
    }

    return 1;
  }

  constexpr static int flush_flight(SSL *ssl)
  {
    return 1;
  }

  static int send_alert(SSL *ssl, enum ssl_encryption_level_t level,
                        uint8_t alert)
  {
    auto c = static_cast<Ngtcp2<mode> *>(SSL_get_app_data(ssl));

    c->alert = alert;

    return 1;
  }

  constexpr static auto quic_method = SSL_QUIC_METHOD {
      set_read_secret,
      set_write_secret,
      add_handshake_data,
      flush_flight,
      send_alert,
  };

  static void rand(uint8_t *dest, size_t destlen,
                   const ngtcp2_rand_ctx *rand_ctx)
  {
    RAND_bytes(dest, static_cast<int>(destlen));
  }

  static int get_new_connection_id2(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    ngtcp2_stateless_reset_token *token,
                                    size_t cidlen, void *user_data)
  {
    if (cidlen > NGTCP2_MAX_CIDLEN)
    {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;

    if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1 ||
        RAND_bytes(token->data, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
    {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }

  static int extend_max_stream_data_server(ngtcp2_conn *conn, int64_t stream_id,
                                           uint64_t max_data, void *user_data,
                                           void *stream_user_data)
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      return 0;
    }
    if (stream_id != 0)
    {
      return 0;
    }

    auto c = static_cast<Ngtcp2<mode> *>(user_data);

    if (!benchmarkIsUpload() && c->bytesInFlight > 0)
    {
      c->data_ready = true;
    }

    return 0;
  }

  static int recv_stream_data_server(ngtcp2_conn *conn, uint32_t flags,
                                     int64_t stream_id, uint64_t offset,
                                     const uint8_t *data, size_t datalen,
                                     void *user_data, void *stream_user_data)
  {
    auto c = static_cast<Ngtcp2<mode> *>(user_data);

    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      ngtcp2_conn_extend_max_offset(conn, datalen);
      ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
      auto state = c->serverGenericStreamFor(stream_id, stream_user_data);
      if (state == nullptr)
      {
        return 0;
      }

      size_t consumed = 0;
      if (state->phase == GenericPhase::readRequest)
      {
        if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
        {
          if (state->requestBytesExpected == 0)
          {
            state->requestBytesExpected = benchmarkGenericReqRespRequestBytes();
          }
          const uint64_t copied = std::min<uint64_t>(
              state->requestBytesExpected - state->requestBytesRead, datalen);
          state->requestBytesRead += copied;
          consumed += static_cast<size_t>(copied);
          if (state->requestBytesRead == state->requestBytesExpected)
          {
            state->responseRemaining = benchmarkGenericReqRespResponseBytes();
            state->phase = GenericPhase::sendResponse;
          }
        }
        else
        {
          while (state->requestBytesRead < state->requestBytes.size() && consumed < datalen)
          {
            state->requestBytes[state->requestBytesRead++] = data[consumed++];
          }
          if (state->requestBytesRead == state->requestBytes.size())
          {
            state->requestValue = decodeU64(state->requestBytes);
            state->payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                                       benchmarkScenario == BenchmarkScenario::bidi)
                                          ? state->requestValue
                                          : 0;
            state->responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : state->requestValue;
            state->phase = state->payloadRemaining > 0 ? GenericPhase::readPayload : GenericPhase::sendResponse;
          }
        }
      }

      if ((benchmarkScenario == BenchmarkScenario::multistream_upload ||
           benchmarkScenario == BenchmarkScenario::bidi) &&
          consumed < datalen && state->payloadRemaining > 0)
      {
        const uint64_t copied = std::min<uint64_t>(state->payloadRemaining, datalen - consumed);
        state->payloadRemaining -= copied;
        consumed += static_cast<size_t>(copied);
        if (state->payloadRemaining == 0)
        {
          state->phase = GenericPhase::sendResponse;
        }
      }

      if (state->phase == GenericPhase::readResponse && consumed < datalen)
      {
        const size_t copied = std::min<size_t>(1 - state->doneBytesRead, datalen - consumed);
        state->doneBytesRead += copied;
      }

      return 0;
    }

    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      ngtcp2_conn_extend_max_offset(conn, datalen);
      ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
      if (c->activeServerState != nullptr && (datalen > 0 || (flags & NGTCP2_STREAM_DATA_FLAG_FIN)))
      {
        c->activeServerState->datagramClientDone = true;
        c->markServerStateComplete(*c->activeServerState);
      }
      return 0;
    }

    if (stream_id != 0)
    {
      return 0;
    }

    ngtcp2_conn_extend_max_offset(conn, datalen);
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);

    size_t consumed = 0;
    while (c->reqsizebuf.size() > c->reqsizebuflen && consumed < datalen)
    {
      auto n = std::min(c->reqsizebuf.size() - c->reqsizebuflen, datalen - consumed);
      std::copy_n(data + consumed, n, c->reqsizebuf.data() + c->reqsizebuflen);
      c->reqsizebuflen += n;
      consumed += n;
    }

    if (c->reqsizebuf.size() > c->reqsizebuflen)
    {
      return 0;
    }

    if (!c->requestParsed)
    {
      memcpy(&c->bytesInFlight, c->reqsizebuf.data(), c->reqsizebuf.size());
      c->bytesInFlight = bswap_64(c->bytesInFlight);
      c->requestParsed = true;

      if (!benchmarkIsUpload())
      {
        c->data_ready = true;
        if (c->activeServerState != nullptr)
        {
          c->activeServerState->responseBytesTarget = static_cast<uint64_t>(c->bytesInFlight);
          c->activeServerState->responseBytesAcked = 0;
        }
      }
    }

    if (benchmarkIsUpload() && consumed < datalen)
    {
      c->bytesInFlight -= std::min<int64_t>(c->bytesInFlight, static_cast<int64_t>(datalen - consumed));
    }

    if (!benchmarkIsUpload() && benchmarkIsLossRecovery() &&
        (flags & NGTCP2_STREAM_DATA_FLAG_FIN))
    {
      c->clientDone = true;
    }

    return 0;
  }

  static int recv_stream_data_client(ngtcp2_conn *conn, uint32_t flags,
                                     int64_t stream_id, uint64_t offset,
                                     const uint8_t *data, size_t datalen,
                                     void *user_data, void *stream_user_data)
  {
    auto c = static_cast<Ngtcp2<mode> *>(user_data);
    ngtcp2_conn_extend_max_offset(conn, datalen);

    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
      auto state = static_cast<GenericStreamState *>(stream_user_data);
      if (state == nullptr)
      {
        return 0;
      }
      size_t consumed = 0;
      if (state->responseRemaining > 0)
      {
        const uint64_t copied = std::min<uint64_t>(state->responseRemaining, datalen);
        state->responseRemaining -= copied;
        consumed += static_cast<size_t>(copied);
        if (state->responseRemaining == 0)
        {
          state->phase = GenericPhase::sendPayload;
        }
      }
      if (state->doneBytesWritten > 0 && state->ackBytesRead < 1 && consumed < datalen)
      {
        const size_t copied = std::min<size_t>(1 - state->ackBytesRead, datalen - consumed);
        state->ackBytesRead += copied;
      }
      if (state->ackBytesRead >= 1)
      {
        c->markGenericClientComplete(state);
      }
      return 0;
    }

    if (stream_id != 0)
    {
      return 0;
    }

    if (benchmarkIsUpload() && (flags & NGTCP2_STREAM_DATA_FLAG_FIN))
    {
      c->clientDone = true;
      return 0;
    }

    const auto received = static_cast<int64_t>(datalen);
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);

    if (c->bytesInFlight < received)
    {
      c->bytesInFlight = 0;
    }
    else
    {
      c->bytesInFlight -= received;
    }

    return 0;
  }

  static int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                      uint64_t offset, uint64_t datalen,
                                      void *user_data, void *stream_user_data)
  {
    (void)stream_user_data;
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) ||
        benchmarkIsUpload() || benchmarkScenario == BenchmarkScenario::datagram ||
        stream_id != 0)
    {
      return 0;
    }
    auto c = static_cast<Ngtcp2<mode> *>(user_data);
    if constexpr (mode & Mode::server)
    {
      if (auto state = c->serverStateForConn(conn); state != nullptr)
      {
        state->responseBytesAcked = std::max<uint64_t>(
            state->responseBytesAcked, offset + datalen);
      }
    }
    return 0;
  }

  static int recv_datagram(ngtcp2_conn *conn, uint32_t flags,
                           const uint8_t *data, size_t datalen,
                           void *user_data)
  {
    (void)conn;
    (void)flags;
    auto c = static_cast<Ngtcp2<mode> *>(user_data);
    if constexpr (mode & Mode::client)
    {
      const uint64_t sequence = benchmarkDecodeDatagramSequence(data, datalen);
      if (benchmarkMarkDatagramSeen(c->datagramClientSeen, sequence))
      {
        ++c->datagramClientReceived;
      }
      c->maybeStartDatagramClientDrain();
    }
    else
    {
      if (c->activeServerState != nullptr)
      {
        const uint64_t sequence = benchmarkDecodeDatagramSequence(data, datalen);
        if (benchmarkMarkDatagramSeen(c->activeServerState->datagramSeen, sequence))
        {
          ++c->activeServerState->datagramReceived;
          c->activeServerState->datagramPendingEchoes.push_back(sequence);
        }
      }
    }
    return 0;
  }

  static int extend_max_streams_bidi_client(ngtcp2_conn *conn,
                                            uint64_t max_streams,
                                            void *user_data)
  {
    auto c = static_cast<Ngtcp2<mode> *>(user_data);

    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      c->openMoreGenericClientStreams();
      return 0;
    }

    if (c->stream_opened)
    {
      return 0;
    }

    c->tryOpenClientStream();

    return 0;
  }

  static int handshake_completed(ngtcp2_conn *conn, void *user_data)
  {
    auto c = static_cast<Ngtcp2<mode> *>(user_data);
    if constexpr (mode & Mode::client)
    {
      c->resumedObserved = c->ssl != nullptr && SSL_session_reused(c->ssl);
      if (c->importedZeroRtt && c->ssl != nullptr)
      {
        c->zeroRttAcceptedObserved = SSL_early_data_accepted(c->ssl);
        c->zeroRttRejectedObserved = !c->zeroRttAcceptedObserved ||
                                     ngtcp2_conn_get_tls_early_data_rejected(conn);
        if (c->zeroRttRejectedObserved && !ngtcp2_conn_get_tls_early_data_rejected(conn))
        {
          int rv = ngtcp2_conn_tls_early_data_rejected(conn);
          if (rv != 0)
          {
            return NGTCP2_ERR_CALLBACK_FAILURE;
          }
        }
      }
      c->captureTransportParams();
    }
    return 0;
  }

  static int early_data_rejected(ngtcp2_conn *conn, void *user_data)
  {
    (void)conn;
    auto c = static_cast<Ngtcp2<mode> *>(user_data);
    if constexpr (mode & Mode::client)
    {
      c->zeroRttRejectedObserved = true;
      c->genericClientStreams.clear();
      c->genericRequestedStreams = 0;
      c->genericOpenedStreams = 0;
      c->genericCompletedStreams = 0;
    }
    return 0;
  }

  static ngtcp2_callbacks make_callbacks()
  {
    ngtcp2_callbacks callbacks = {};

    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.rand = rand;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.get_new_connection_id2 = get_new_connection_id2;
    callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    callbacks.handshake_completed = handshake_completed;
    callbacks.tls_early_data_rejected = early_data_rejected;

    return callbacks;
  }

  void init_conn_server(UDPContext *msg)
  {
    ngtcp2_pkt_hd hd;
    if (auto rv = ngtcp2_accept(&hd, msg->buffer(), msg->msg_len); rv != 0)
    {
      std::cerr << "ngtcp2_accept: " << rv << std::endl;
      assert(0);
      abort();
    }

    auto callbacks = make_callbacks();
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_stream_data = recv_stream_data_server;
    callbacks.extend_max_stream_data = extend_max_stream_data_server;
    callbacks.acked_stream_data_offset = acked_stream_data_offset;
    callbacks.recv_datagram = recv_datagram;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = timeNowUs() * NGTCP2_MICROSECONDS;
    settings.cc_algo = benchmarkCongestionProfileUsesCubic() ? NGTCP2_CC_ALGO_CUBIC : NGTCP2_CC_ALGO_BBR;
    settings.max_stream_window = benchmarkStreamWindow;
    settings.max_window = benchmarkConnectionWindow;
    settings.max_tx_udp_payload_size = benchmarkUdpPayloadSize;
    settings.no_tx_udp_payload_size_shaping = 1;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = benchmarkMaxBidiStreams;
    params.initial_max_streams_uni = benchmarkMaxUniStreams;
    params.initial_max_stream_data_bidi_local = benchmarkStreamWindow;
    params.initial_max_stream_data_bidi_remote = benchmarkStreamWindow;
    params.initial_max_stream_data_uni = benchmarkStreamWindow;
    params.initial_max_data = benchmarkConnectionWindow;
    params.max_idle_timeout = benchmarkIdleTimeoutMs * NGTCP2_MILLISECONDS;
    params.max_udp_payload_size = benchmarkUdpPayloadSize;
    params.max_datagram_frame_size = benchmarkUdpPayloadSize;
    params.ack_delay_exponent = benchmarkAckDelayExponent;
    params.max_ack_delay = benchmarkMaxAckDelayMs * NGTCP2_MILLISECONDS;
    params.original_dcid = hd.dcid;
    params.original_dcid_present = 1;

    auto path = ngtcp2_path {
        {reinterpret_cast<sockaddr *>(networkHub->socket.address6),
         sizeof(struct sockaddr_in6)                                                           },
        {msg->address(),                                            sizeof(struct sockaddr_in6)},
        nullptr
    };

    ngtcp2_cid scid;
    ngtcp2_cid_init(&scid, nullptr, 0);

    if (auto rv = ngtcp2_conn_server_new(&conn, &hd.scid, &scid, &path,
                                         hd.version, &callbacks, &settings,
                                         &params, nullptr, this);
        rv != 0)
    {
      std::cerr << "ngtcp2_conn_server_new: " << ngtcp2_strerror(rv)
                << std::endl;
      assert(0);
      abort();
    }

    ssl = SSL_new(ssl_ctx);
    SSL_set_app_data(ssl, this);
    SSL_set_accept_state(ssl);
    SSL_set_quic_use_legacy_codepoint(ssl, 0);
    {
      std::array<uint8_t, 512> earlyDataContext = {};
      ngtcp2_ssize len = ngtcp2_conn_encode_0rtt_transport_params(
          conn, earlyDataContext.data(), earlyDataContext.size());
      if (len <= 0 ||
          SSL_set_quic_early_data_context(
              ssl, earlyDataContext.data(), static_cast<size_t>(len)) != 1)
      {
        fprintf(stderr, "ngtcp2: failed to configure QUIC early-data context\n");
        abort();
      }
    }

    ngtcp2_conn_set_tls_native_handle(conn, ssl);
  }

  void init_conn_client(struct sockaddr *address)
  {
    memcpy(&clientPeerAddress, address, sizeof(clientPeerAddress));

    auto callbacks = make_callbacks();
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_stream_data = recv_stream_data_client;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.extend_max_local_streams_bidi = extend_max_streams_bidi_client;
    callbacks.recv_datagram = recv_datagram;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = timeNowUs() * NGTCP2_MICROSECONDS;
    settings.cc_algo = benchmarkCongestionProfileUsesCubic() ? NGTCP2_CC_ALGO_CUBIC : NGTCP2_CC_ALGO_BBR;
    settings.max_stream_window = benchmarkStreamWindow;
    settings.max_window = benchmarkConnectionWindow;
    settings.max_tx_udp_payload_size = benchmarkUdpPayloadSize;
    settings.no_tx_udp_payload_size_shaping = 1;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = benchmarkMaxBidiStreams;
    params.initial_max_streams_uni = benchmarkMaxUniStreams;
    params.initial_max_stream_data_bidi_local = benchmarkStreamWindow;
    params.initial_max_stream_data_bidi_remote = benchmarkStreamWindow;
    params.initial_max_stream_data_uni = benchmarkStreamWindow;
    params.initial_max_data = benchmarkConnectionWindow;
    params.max_idle_timeout = benchmarkIdleTimeoutMs * NGTCP2_MILLISECONDS;
    params.max_udp_payload_size = benchmarkUdpPayloadSize;
    params.max_datagram_frame_size = benchmarkUdpPayloadSize;
    params.ack_delay_exponent = benchmarkAckDelayExponent;
    params.max_ack_delay = benchmarkMaxAckDelayMs * NGTCP2_MILLISECONDS;

    auto path = ngtcp2_path {
        {reinterpret_cast<sockaddr *>(networkHub->socket.address6),
         sizeof(struct sockaddr_in6)                                                           },
        {address,                                                   sizeof(struct sockaddr_in6)},
        nullptr
    };

    ngtcp2_cid scid;
    ngtcp2_cid_init(&scid, nullptr, 0);

    ngtcp2_cid dcid;
    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    RAND_bytes(dcid.data, static_cast<int>(dcid.datalen));

    if (auto rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &path,
                                         NGTCP2_PROTO_VER_V1, &callbacks,
                                         &settings, &params, nullptr, this);
        rv != 0)
    {
      std::cerr << "ngtcp2_conn_client_new: " << ngtcp2_strerror(rv)
                << std::endl;
      assert(0);
      abort();
    }

    ssl = SSL_new(ssl_ctx);
    SSL_set_app_data(ssl, this);
    SSL_set_connect_state(ssl);
    SSL_set_quic_use_legacy_codepoint(ssl, 0);
    if (importedZeroRtt)
    {
      SSL_set_early_data_enabled(ssl, 1);
    }

    ngtcp2_conn_set_tls_native_handle(conn, ssl);

    if (importedResumption && !importedSession.empty())
    {
      SSL_SESSION *session = SSL_SESSION_from_bytes(
          importedSession.data(), importedSession.size(), ssl_ctx);
      if (session == nullptr)
      {
        fprintf(stderr, "ngtcp2: failed to parse imported TLS session\n");
        abort();
      }
      if (SSL_set_session(ssl, session) != 1)
      {
        SSL_SESSION_free(session);
        fprintf(stderr, "ngtcp2: failed to install imported TLS session\n");
        abort();
      }
      if (importedZeroRtt)
      {
        int rv = ngtcp2_conn_decode_and_set_0rtt_transport_params(
            conn, importedTransportParams.data(), importedTransportParams.size());
        if (rv != 0)
        {
          SSL_SESSION_free(session);
          fprintf(stderr, "ngtcp2: failed to decode imported 0-RTT transport params: %s\n",
                  ngtcp2_strerror(rv));
          abort();
        }
      }
      SSL_SESSION_free(session);
    }
  }

  std::tuple<int64_t, ngtcp2_vec, size_t, uint32_t> get_generic_stream_data_server()
  {
    activeGenericSend = nullptr;
    activeGenericSendKind = GenericSendKind::none;

    if (activeServerState == nullptr)
    {
      return {-1, ngtcp2_vec {}, 0, NGTCP2_WRITE_STREAM_FLAG_MORE};
    }

    for (auto& item : activeServerState->genericStreams)
    {
      auto& state = *item.second;
      if (state.complete)
      {
        continue;
      }
      if (state.phase == GenericPhase::sendResponse && state.responseRemaining > 0)
      {
        const size_t n = static_cast<size_t>(
            std::min<uint64_t>(state.responseRemaining, sizeof(networkHub->junk)));
        ngtcp2_vec vec {networkHub->junk, n};
        activeGenericSend = &state;
        activeGenericSendKind = GenericSendKind::response;
        return {state.streamId, vec, 1, NGTCP2_WRITE_STREAM_FLAG_MORE};
      }
      if (state.phase == GenericPhase::readResponse && state.doneBytesRead > 0 && state.ackBytesWritten == 0)
      {
        static uint8_t ack = 0;
        ngtcp2_vec vec {&ack, sizeof(ack)};
        activeGenericSend = &state;
        activeGenericSendKind = GenericSendKind::ack;
        return {state.streamId, vec, 1, NGTCP2_WRITE_STREAM_FLAG_FIN};
      }
    }

    return {-1, ngtcp2_vec {}, 0, NGTCP2_WRITE_STREAM_FLAG_MORE};
  }

  std::tuple<int64_t, ngtcp2_vec, size_t, uint32_t> get_generic_stream_data_client()
  {
    activeGenericSend = nullptr;
    activeGenericSendKind = GenericSendKind::none;

    for (auto& owned : genericClientStreams)
    {
      auto& state = *owned;
      if (state.complete)
      {
        continue;
      }
      if (state.requestBytesWritten < state.requestBytesExpected)
      {
        const size_t left = static_cast<size_t>(state.requestBytesExpected - state.requestBytesWritten);
        uint8_t *source = nullptr;
        if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
        {
          source = networkHub->junk;
        }
        else
        {
          source = state.requestBytes.data() + state.requestBytesWritten;
        }
        const size_t n = std::min<size_t>(left, sizeof(networkHub->junk));
        ngtcp2_vec vec {source, n};
        activeGenericSend = &state;
        activeGenericSendKind = GenericSendKind::request;
        return {state.streamId, vec, 1, NGTCP2_WRITE_STREAM_FLAG_MORE};
      }
      if (state.payloadRemaining > 0)
      {
        const size_t n = static_cast<size_t>(
            std::min<uint64_t>(state.payloadRemaining, sizeof(networkHub->junk)));
        ngtcp2_vec vec {networkHub->junk, n};
        activeGenericSend = &state;
        activeGenericSendKind = GenericSendKind::payload;
        return {state.streamId, vec, 1, NGTCP2_WRITE_STREAM_FLAG_MORE};
      }
      if (state.responseRemaining == 0 && state.doneBytesWritten == 0)
      {
        static uint8_t done = 0;
        ngtcp2_vec vec {&done, sizeof(done)};
        activeGenericSend = &state;
        activeGenericSendKind = GenericSendKind::done;
        return {state.streamId, vec, 1, NGTCP2_WRITE_STREAM_FLAG_FIN};
      }
    }

    return {-1, ngtcp2_vec {}, 0, NGTCP2_WRITE_STREAM_FLAG_MORE};
  }

  std::tuple<int64_t, ngtcp2_vec, size_t, uint32_t> get_stream_data_server()
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      return get_generic_stream_data_server();
    }
    int64_t stream_id = -1;
    size_t vcnt = 0;
    ngtcp2_vec vec {};
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

    if (benchmarkIsUpload())
    {
      if (requestParsed && bytesInFlight == 0 && !uploadFinSent)
      {
        stream_id = 0;
        vcnt = 0;
        flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
      }
    }
    else if (data_ready && bytesInFlight >= 0 && ngtcp2_conn_get_max_data_left(conn))
    {
      auto n = std::min(static_cast<int64_t>(sizeof(networkHub->junk)),
                        bytesInFlight);
      vec.len = n;
      vec.base = networkHub->junk;
      vcnt = 1;
      stream_id = 0;

      if (n == bytesInFlight)
      {
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
      }
    }

    return {stream_id, vec, vcnt, flags};
  }

  std::tuple<int64_t, ngtcp2_vec, size_t, uint32_t> get_stream_data_client()
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      return get_generic_stream_data_client();
    }
    int64_t stream_id = -1;
    size_t vcnt = 0;
    ngtcp2_vec vec {};
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      signalDatagramDoneWhenSendBudgetReached();
      if (datagramDoneSignalSent && !datagramDoneStreamWritten)
      {
        vec.len = 1;
        vec.base = datagramScratch.data();
        vcnt = 1;
        stream_id = 0;
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
      }
      return {stream_id, vec, vcnt, flags};
    }

    if (data_ready && ngtcp2_conn_get_max_data_left(conn))
    {
      if (benchmarkIsUpload() && reqsizebufoffset == reqsizebuflen)
      {
        auto n = std::min(static_cast<int64_t>(sizeof(networkHub->junk)), bytesInFlight);
        vec.len = n;
        vec.base = networkHub->junk;
        vcnt = n > 0 ? 1 : 0;
        stream_id = n > 0 ? 0 : -1;
        if (n == bytesInFlight)
        {
          flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
      }
      else
      {
        if (!benchmarkIsUpload() && benchmarkIsLossRecovery() &&
            reqsizebufoffset == reqsizebuflen && bytesInFlight == 0 && !clientDone)
        {
          vcnt = 0;
          stream_id = 0;
          flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
        else
        {
          vec.len = reqsizebuflen - reqsizebufoffset;
          vec.base = reqsizebuf.data() + reqsizebufoffset;
          vcnt = 1;
          stream_id = 0;
          if ((!benchmarkIsUpload() && !benchmarkIsLossRecovery()) ||
              (benchmarkIsUpload() && bytesInFlight == 0))
          {
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
          }
        }
      }
    }

    return {stream_id, vec, vcnt, flags};
  }

  std::tuple<int64_t, ngtcp2_vec, size_t, uint32_t> get_stream_data()
  {
    if constexpr (mode & Mode::server)
    {
      return get_stream_data_server();
    }
    else
    {
      return get_stream_data_client();
    }
  }

  void stream_data_sent_server(size_t datalen)
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if (activeGenericSend == nullptr)
      {
        return;
      }
      if (activeGenericSendKind == GenericSendKind::response)
      {
        activeGenericSend->responseRemaining -= std::min<uint64_t>(
            activeGenericSend->responseRemaining, datalen);
        if (activeGenericSend->responseRemaining == 0)
        {
          activeGenericSend->phase = GenericPhase::readResponse;
        }
      }
      else if (activeGenericSendKind == GenericSendKind::ack)
      {
        activeGenericSend->ackBytesWritten += datalen;
      }
      activeGenericSend = nullptr;
      activeGenericSendKind = GenericSendKind::none;
      return;
    }
    if (benchmarkIsUpload())
    {
      if (requestParsed && bytesInFlight == 0)
      {
        uploadFinSent = true;
      }
      return;
    }

    bytesInFlight -= datalen;
    if (bytesInFlight == 0)
    {
      data_ready = false;
    }
  }

  void stream_data_sent_client(size_t datalen)
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if (activeGenericSend == nullptr)
      {
        return;
      }
      switch (activeGenericSendKind)
      {
        case GenericSendKind::request:
          if (importedZeroRtt && !ngtcp2_conn_get_handshake_completed(conn))
          {
            zeroRttAttemptedObserved = true;
          }
          activeGenericSend->requestBytesWritten += datalen;
          break;
        case GenericSendKind::payload:
          activeGenericSend->payloadRemaining -= std::min<uint64_t>(
              activeGenericSend->payloadRemaining, datalen);
          break;
        case GenericSendKind::done:
          activeGenericSend->doneBytesWritten += datalen;
          break;
        default:
          break;
      }
      activeGenericSend = nullptr;
      activeGenericSendKind = GenericSendKind::none;
      return;
    }
    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      if (datagramDoneSignalSent && !datagramDoneStreamWritten && datalen > 0)
      {
        datagramDoneStreamWritten = true;
        data_ready = false;
        maybeStartDatagramClientDrain();
      }
      return;
    }
    if (benchmarkIsUpload() && reqsizebufoffset == reqsizebuflen)
    {
      bytesInFlight -= std::min<int64_t>(bytesInFlight, static_cast<int64_t>(datalen));
      if (bytesInFlight == 0)
      {
        data_ready = false;
      }
      return;
    }

    if (!benchmarkIsUpload() && benchmarkIsLossRecovery() &&
        reqsizebufoffset == reqsizebuflen && bytesInFlight == 0 && datalen == 0)
    {
      clientDone = true;
      data_ready = false;
      return;
    }

    reqsizebufoffset += datalen;
    if (reqsizebufoffset == reqsizebuflen && !benchmarkIsUpload())
    {
      data_ready = false;
    }
  }

  void stream_data_sent(size_t datalen)
  {
    if constexpr (mode & Mode::server)
    {
      return stream_data_sent_server(datalen);
    }
    else
    {
      return stream_data_sent_client(datalen);
    }
  }

  void send_packet(ngtcp2_tstamp ts)
  {
    auto packets = networkHub->sendPool.get();

    if (ts >= ngtcp2_conn_get_expiry(conn))
    {
      if (auto rv = ngtcp2_conn_handle_expiry(conn, ts); rv != 0)
      {
        std::cerr << "ngtcp2_conn_handle_expiry: " << ngtcp2_strerror(rv)
                  << std::endl;
        assert(0);
        abort();
      }
    }

    ngtcp2_ssize nwrite;

    do
    {
      auto packet = &packets->msgs[packets->count];
      const struct sockaddr *peerAddress = nullptr;
      if constexpr (mode & Mode::server)
      {
        if (activeServerState == nullptr)
        {
          break;
        }
        peerAddress = reinterpret_cast<const struct sockaddr *>(&activeServerState->peerAddress);
      }
      else
      {
        peerAddress = reinterpret_cast<const struct sockaddr *>(&clientPeerAddress);
      }
      packet->copyInAddress(peerAddress);
      auto remote_addr = packet->address();

      for (;;)
      {
        if (benchmarkScenario == BenchmarkScenario::datagram)
        {
          bool sendDatagram = false;
          if constexpr (mode & Mode::client)
          {
            sendDatagram = datagramClientCanSend();
          }
          else
          {
            sendDatagram = activeServerState != nullptr &&
                           !activeServerState->datagramPendingEchoes.empty();
          }

          if (sendDatagram)
          {
            auto path = ngtcp2_path {
                {reinterpret_cast<sockaddr *>(networkHub->socket.address6),
                 sizeof(struct sockaddr_in6)},
                {reinterpret_cast<sockaddr *>(remote_addr),
                 sizeof(struct sockaddr_in6)},
                nullptr
            };
            ngtcp2_pkt_info pi {};
            int accepted = 0;
            const size_t payloadSize = datagramPayloadSize();
            if (payloadSize == 0)
            {
              break;
            }
            const uint64_t datagramId = [&] {
              if constexpr (mode & Mode::client)
              {
                return datagramClientSent + 1;
              }
              else
              {
                return activeServerState != nullptr && !activeServerState->datagramPendingEchoes.empty()
                           ? activeServerState->datagramPendingEchoes.front() + 1
                           : 0;
              }
            }();
            const uint64_t sequence = [&] {
              if constexpr (mode & Mode::client)
              {
                return datagramClientSent;
              }
              else
              {
                return activeServerState != nullptr && !activeServerState->datagramPendingEchoes.empty()
                           ? activeServerState->datagramPendingEchoes.front()
                           : 0;
              }
            }();
            benchmarkFillDatagramPayload(datagramScratch.data(), payloadSize, networkHub->junk, sequence);

            nwrite = ngtcp2_conn_write_datagram(
                conn, &path, &pi, packet->buffer(), MAX_IPV6_UDP_PACKET_SIZE,
                &accepted, NGTCP2_WRITE_DATAGRAM_FLAG_NONE, datagramId,
                datagramScratch.data(), payloadSize, ts);
            if (nwrite < 0)
            {
              std::cerr << "ngtcp2_conn_write_datagram: "
                        << ngtcp2_strerror(static_cast<int>(nwrite)) << std::endl;
              assert(0);
              abort();
            }
            if (accepted)
            {
              if constexpr (mode & Mode::client)
              {
                ++datagramClientSent;
                signalDatagramDoneWhenSendBudgetReached();
              }
              else if (activeServerState != nullptr)
              {
                activeServerState->datagramPendingEchoes.pop_front();
                ++activeServerState->datagramEchoed;
              }
            }
            if (nwrite == 0)
            {
              break;
            }
            packet->msg_hdr.msg_iov[0].iov_len = nwrite;
            packet->msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
            ++packets->count;
            break;
          }
        }
        auto [stream_id, vec, vcnt, flags] = get_stream_data();
        auto path = ngtcp2_path {
            {reinterpret_cast<sockaddr *>(networkHub->socket.address6),
             sizeof(struct sockaddr_in6)},
            {reinterpret_cast<sockaddr *>(remote_addr),
             sizeof(struct sockaddr_in6)},
            nullptr
        };

        ngtcp2_ssize ndatalen;
        nwrite = ngtcp2_conn_writev_stream(
            conn, &path, nullptr, packet->buffer(), MAX_IPV6_UDP_PACKET_SIZE,
            &ndatalen, flags, stream_id, &vec, vcnt, ts);
        if (nwrite < 0)
        {
          switch (nwrite)
          {
            case NGTCP2_ERR_STREAM_DATA_BLOCKED:
            case NGTCP2_ERR_STREAM_SHUT_WR:
              data_ready = false;
              continue;
            case NGTCP2_ERR_WRITE_MORE:
              stream_data_sent(static_cast<size_t>(ndatalen));
              continue;
          }

          std::cerr << "ngtcp2_conn_writev_stream: "
                    << ngtcp2_strerror(static_cast<int>(nwrite)) << std::endl;
          assert(0);
          abort();
        }
        else if (ndatalen >= 0)
        {
          stream_data_sent(static_cast<size_t>(ndatalen));
        }

        if (nwrite == 0)
        {
          break;
        }

        packet->msg_hdr.msg_iov[0].iov_len = nwrite;
        packet->msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
        ++packets->count;

        break;
      }
    } while (nwrite > 0 && packets->count < MultiUDPContext::batchSize);

    if (packets->count > 0)
    {
      networkHub->sendBatch(packets);
    }
    else
    {
      networkHub->sendPool.relinquish(packets);
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

  void completeGenericServerStreams(ServerConnState& state)
  {
    if (!benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      return;
    }
    loadServerState(state);
    for (auto& item : state.genericStreams)
    {
      GenericStreamState *stream = item.second.get();
      if (stream->ackBytesWritten >= 1 && !stream->complete)
      {
        markGenericServerComplete(stream);
      }
    }
    saveServerState(state);
  }

  void advance(int32_t count = 0)
  {
    if constexpr (mode & Mode::server)
    {
      do
      {
        int64_t usTil = 100'000;
        auto now = timeNowUs() * NGTCP2_MICROSECONDS;
        for (auto& state : serverConns)
        {
          loadServerState(*state);
          if (conn)
          {
            send_packet(now);
            auto expiry = ngtcp2_conn_get_expiry(conn);
            if (expiry != std::numeric_limits<uint64_t>::max() && now < expiry)
            {
              usTil = std::min<int64_t>(usTil, static_cast<int64_t>(std::max(
                                                   (expiry - now) / NGTCP2_MICROSECONDS, static_cast<uint64_t>(1))));
            }
          }
          saveServerState(*state);
        }

        networkHub->recvmsgWithTimeout(usTil, [&](UDPContext *msg) -> void {
          ServerConnState& state = serverStateFor(msg);
          loadServerState(state);
          auto path = ngtcp2_path {
              {reinterpret_cast<sockaddr *>(networkHub->socket.address6),
               sizeof(struct sockaddr_in6)                                                           },
              {msg->address(),                                            sizeof(struct sockaddr_in6)},
              nullptr
          };
          auto pi = ngtcp2_pkt_info {};

          if (auto rv = ngtcp2_conn_read_pkt(conn, &path, &pi, msg->buffer(),
                                             msg->msg_len,
                                             timeNowUs() * NGTCP2_MICROSECONDS);
              rv != 0)
          {
            std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv)
                      << std::endl;
            assert(0);
            abort();
          }
          saveServerState(state);
          markServerStateComplete(state);
        });

        for (auto& state : serverConns)
        {
          loadServerState(*state);
          if (conn)
          {
            send_packet(timeNowUs() * NGTCP2_MICROSECONDS);
          }
          saveServerState(*state);
        }

        networkHub->flush();
        drainIouringSends();

        for (auto& state : serverConns)
        {
          completeGenericServerStreams(*state);
          markServerStateComplete(*state);
        }
      } while (!perfComplete() && (count == 0 || --count > 0));
      return;
    }

    do
    {
      int64_t usTil = 0;
      if (conn)
      {
        auto now = timeNowUs() * NGTCP2_MICROSECONDS;

        send_packet(now);
        drainIouringSends();

        auto expiry = ngtcp2_conn_get_expiry(conn);
        if (expiry != std::numeric_limits<uint64_t>::max() && now < expiry)
        {
          usTil = static_cast<int64_t>(std::max(
              (expiry - now) / NGTCP2_MICROSECONDS, static_cast<uint64_t>(1)));
        }
        if (benchmarkScenario == BenchmarkScenario::datagram &&
            datagramClientDrainDeadlineUs != 0)
        {
          const uint64_t nowUs = timeNowUs();
          const int64_t drainWaitUs = nowUs >= datagramClientDrainDeadlineUs
                                          ? 0
                                          : static_cast<int64_t>(datagramClientDrainDeadlineUs - nowUs);
          usTil = usTil <= 0 ? drainWaitUs : std::min(usTil, drainWaitUs);
        }
        if (count > 0 && usTil > 1000)
        {
          usTil = 1000;
        }
      }

      networkHub->recvmsgWithTimeout(usTil, [&](UDPContext *msg) -> void {
        if constexpr (mode & Mode::server)
        {
          if (!conn)
          {
            init_conn_server(msg);
          }
        }

        auto path = ngtcp2_path {
            {reinterpret_cast<sockaddr *>(networkHub->socket.address6),
             sizeof(struct sockaddr_in6)                                                           },
            {msg->address(),                                            sizeof(struct sockaddr_in6)},
            nullptr
        };
        auto pi = ngtcp2_pkt_info {};

        if (auto rv = ngtcp2_conn_read_pkt(conn, &path, &pi, msg->buffer(),
                                           msg->msg_len,
                                           timeNowUs() * NGTCP2_MICROSECONDS);
            rv != 0)
        {
          std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv)
                    << std::endl;
          assert(0);
          abort();
        }
      });
      if (conn)
      {
        send_packet(timeNowUs() * NGTCP2_MICROSECONDS);
      }
      drainIouringSends();
    } while (!perfComplete() && (count == 0 || --count > 0));
  }

public:

  void instanceSetup(uint16_t localPort, int argc, char *argv[])
  {
    networkHub = new NetworkHub<mode>(localPort);
    configureTLS();
  }

  void connectToServer(struct sockaddr *address)
  {
    init_conn_client(address);

    while (!ngtcp2_conn_get_handshake_completed(conn))
    {
      advance(1);
    }
  }

  void connectToServerForZeroRtt(struct sockaddr *address) override
  {
    if constexpr (mode & Mode::client)
    {
      init_conn_client(address);
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        genericClientBytes = 0;
        genericRequestedStreams = 0;
        genericOpenedStreams = 0;
        genericCompletedStreams = 0;
        genericClientStreams.clear();
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
    if constexpr (mode & Mode::client)
    {
      while (!tryOpenClientStream())
      {
        advance(1);
      }
    }
  }

  void startPerfTest(uint64_t nBytes)
  {
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
        genericClientStreams.clear();
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
        datagramDoneSignalSent = false;
        datagramDoneStreamWritten = false;
        datagramClientSeen.assign(benchmarkDatagramSeenBytes(), 0);
        datagramScratch.fill(0);
        datagramStarted = true;
        while (!tryOpenClientStream())
        {
          advance(1);
        }
        advance();
        benchmarkRecordDatagramClientCounters(datagramClientSent, datagramClientReceived);
        return;
      }
      bytesInFlight = nBytes;
      data_ready = true;

      auto n = bswap_64(bytesInFlight);
      reqsizebuflen = sizeof(n);
      memcpy(reqsizebuf.data(), &n, reqsizebuflen);
    }

    advance();
  }

  void postPerfTest() override
  {
    if constexpr (mode & Mode::client)
    {
      if (!benchmarkIsUpload() && !benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) &&
          benchmarkScenario != BenchmarkScenario::datagram)
      {
        const uint64_t deadlineUs = timeNowUs() + 100'000;
        do
        {
          advance(1);
        } while (timeNowUs() < deadlineUs);
      }

      if (!benchmarkIsLossRecovery() || benchmarkIsUpload() || clientDone)
      {
        return;
      }

      data_ready = true;
      const uint64_t deadlineUs = timeNowUs() + 100'000;
      do
      {
        advance(1);
      } while (!clientDone && timeNowUs() < deadlineUs);
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
      captureTransportParams();
      for (int i = 0; i < 100 && savedSession.empty(); ++i)
      {
        advance(1);
      }
      if (!savedSession.empty())
      {
        state.session = savedSession;
        state.transportParams = savedTransportParams;
        state.proofLabel = "ngtcp2_boringssl_session_and_transport_params";
        return true;
      }
    }
    return false;
  }

  bool importResumptionState(const BenchmarkResumptionState& state, bool enableZeroRtt) override
  {
    if (state.session.empty() || (enableZeroRtt && state.transportParams.empty()))
    {
      return false;
    }
    importedSession = state.session;
    importedTransportParams = state.transportParams;
    importedResumption = true;
    importedZeroRtt = enableZeroRtt;
    return true;
  }

  bool connectionWasResumed(void) const override
  {
    return resumedObserved || (ssl != nullptr && SSL_session_reused(ssl));
  }

  bool zeroRttWasAttempted(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved;
  }

  bool zeroRttWasAccepted(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved &&
           (zeroRttAcceptedObserved || (ssl != nullptr && SSL_early_data_accepted(ssl)));
  }

  bool zeroRttWasRejected(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved &&
           (zeroRttRejectedObserved || (conn != nullptr && ngtcp2_conn_get_tls_early_data_rejected(conn)));
  }

  const char *resumptionProofLabel(void) const override
  {
    return "ngtcp2_boringssl_session_tp_and_tls_status";
  }
};
