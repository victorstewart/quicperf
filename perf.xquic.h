#include "xquic/xqc_errno.h"
#include "xquic/xquic.h"

#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <vector>

#pragma once

extern "C" SSL_CTX *__real_SSL_CTX_new(const SSL_METHOD *method);

extern "C" SSL_CTX *__wrap_SSL_CTX_new(const SSL_METHOD *method)
{
  SSL_CTX *ctx = __real_SSL_CTX_new(method);
  if (ctx != nullptr &&
      SSL_CTX_set1_sigalgs_list(ctx, "ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256") != 1)
  {
    fprintf(stderr, "xquic: failed to set benchmark TLS signature algorithms\n");
    abort();
  }
  return ctx;
}

template <Mode mode>
class Xquic : public QuicLibrary<mode> {
private:

  using QuicLibrary<mode>::networkHub;

  xqc_engine_t *engine = nullptr;
  xqc_connection_t *conn = nullptr;
  xqc_stream_t *stream = nullptr;
  xqc_cid_t cid = {};
  int64_t bytesInFlight = -1;
  std::array<unsigned char, sizeof(uint64_t)> requestBytes = {};
  size_t requestBytesRead = 0;
  size_t requestBytesWritten = 0;
  xqc_usec_t nextWakeUs = 1000;
  bool connected = false;
  bool closed = false;
  bool importedResumption = false;
  bool importedZeroRtt = false;
  bool resumedObserved = false;
  bool zeroRttAttemptedObserved = false;
  bool zeroRttAcceptedObserved = false;
  bool zeroRttRejectedObserved = false;
  std::vector<char> savedSession;
  std::vector<char> savedTransportParams;
  std::vector<char> importedSession;
  std::vector<char> importedTransportParams;
  bool clientDone = false;
  uint64_t serverDrainDeadlineUs = 0;
  bool requestParsed = false;
  bool uploadFinSent = false;
  bool writeInProgress = false;
  bool datagramWriteInProgress = false;
  uint32_t serverCompletedConnections = 0;
  constexpr static uint64_t maxStreamWriteBurstBytes = 4ULL * 1024ULL * 1024ULL;

  struct ScopedWriteGuard {
    bool& flag;
    bool acquired;

    explicit ScopedWriteGuard(bool& activeFlag)
        : flag(activeFlag),
          acquired(!activeFlag)
    {
      if (acquired)
      {
        flag = true;
      }
    }

    ~ScopedWriteGuard()
    {
      if (acquired)
      {
        flag = false;
      }
    }

    explicit operator bool() const
    {
      return acquired;
    }
  };

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
    Xquic<mode> *owner = nullptr;
    xqc_stream_t *stream = nullptr;
    GenericPhase phase = GenericPhase::sendRequest;
    std::array<unsigned char, sizeof(uint64_t)> requestBytes = {};
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
    bool writeBlocked = false;
    bool writeInProgress = false;
    bool writeClosed = false;
    bool complete = false;
  };

  struct ServerStreamState {
    Xquic<mode> *owner = nullptr;
    xqc_stream_t *stream = nullptr;
    int64_t bytesInFlight = -1;
    std::array<unsigned char, sizeof(uint64_t)> requestBytes = {};
    size_t requestBytesRead = 0;
    bool connected = false;
    bool closed = false;
    bool clientDone = false;
    uint64_t serverDrainDeadlineUs = 0;
    bool requestParsed = false;
    bool uploadFinSent = false;
    bool writeInProgress = false;
    bool complete = false;
  };

  std::vector<std::unique_ptr<ServerStreamState>> serverStreams;
  std::vector<std::unique_ptr<GenericStreamState>> genericStreams;
  bool genericStarted = false;
  uint64_t genericClientBytes = 0;
  uint64_t genericRequestedStreams = 0;
  uint64_t genericOpenedStreams = 0;
  uint64_t genericCompletedStreams = 0;
  uint64_t genericServerCompletedStreams = 0;
  struct DatagramConnState {
    Xquic<mode> *owner = nullptr;
    xqc_connection_t *conn = nullptr;
    uint64_t received = 0;
    uint64_t echoed = 0;
    uint64_t pendingEchoes = 0;
    uint64_t drainDeadlineUs = 0;
    size_t mss = 0;
    bool writeInProgress = false;
    bool complete = false;
  };
  std::vector<std::unique_ptr<DatagramConnState>> datagramServerConns;
  uint64_t datagramClientSent = 0;
  uint64_t datagramClientReceived = 0;
  uint64_t datagramClientDrainDeadlineUs = 0;
  size_t datagramClientMss = 0;
  bool datagramStarted = false;

  bool perfComplete(void) const
  {
    if constexpr (mode & Mode::server)
    {
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
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
        return datagramClientReceived >= benchmarkScenarioOperations &&
               datagramClientDrainDeadlineUs != 0 &&
               timeNowUs() >= datagramClientDrainDeadlineUs;
      }
      if (benchmarkIsUpload())
      {
        return clientDone || closed;
      }
      return bytesInFlight == 0 || closed;
    }
  }

  static xqc_usec_t now(void)
  {
    return timeNowUs();
  }

  static void setTimer(xqc_usec_t wakeAfter, void *engineUserData)
  {
    auto self = static_cast<Xquic<mode> *>(engineUserData);
    self->nextWakeUs = wakeAfter;
  }

  static void ignoreLog(xqc_log_level_t lvl, const void *buf, size_t size, void *engineUserData)
  {
  }

  static void ignoreQlog(qlog_event_importance_t importance, const void *buf, size_t size, void *engineUserData)
  {
  }

  static void drainNetworkIouringSends(Xquic<mode> *self)
  {
    if constexpr (mode & Mode::iouring)
    {
      if (self->writeInProgress || self->datagramWriteInProgress)
      {
        return;
      }
      for (const auto& state : self->datagramServerConns)
      {
        if (state->writeInProgress)
        {
          return;
        }
      }
      self->networkHub->flush();
      self->networkHub->drainSendCompletions();
    }
    else
    {
      (void)self;
    }
  }

  static ssize_t sendOne(const unsigned char *buf, size_t size, const struct sockaddr *peerAddr, socklen_t peerAddrLen, void *userData)
  {
    auto self = static_cast<Xquic<mode> *>(userData);
    if (self == nullptr)
    {
      return XQC_SOCKET_ERROR;
    }

    MultiUDPContext *batch = self->networkHub->sendPool.get();
    if (batch == nullptr)
    {
      drainNetworkIouringSends(self);
      batch = self->networkHub->sendPool.get();
      if (batch == nullptr)
      {
        return XQC_SOCKET_EAGAIN;
      }
    }

    UDPContext *packet = &batch->msgs[0];
    if (size > MAX_IPV6_UDP_PACKET_SIZE)
    {
      self->networkHub->sendPool.relinquish(batch);
      return XQC_SOCKET_ERROR;
    }

    memcpy(packet->buffer(), buf, size);
    packet->setLength(size);
    packet->copyInAddress(peerAddr);
    batch->count = 1;
    self->networkHub->sendBatch(batch);

    return static_cast<ssize_t>(size);
  }

  static ssize_t writeSocket(const unsigned char *buf, size_t size, const struct sockaddr *peerAddr, socklen_t peerAddrLen, void *userData)
  {
    return sendOne(buf, size, peerAddr, peerAddrLen, userData);
  }

  static ssize_t writeSocketEx(uint64_t pathId, const unsigned char *buf, size_t size, const struct sockaddr *peerAddr, socklen_t peerAddrLen, void *userData)
  {
    return sendOne(buf, size, peerAddr, peerAddrLen, userData);
  }

  ServerStreamState *newServerStreamState(xqc_stream_t *activeStream)
  {
    auto state = std::make_unique<ServerStreamState>();
    state->owner = this;
    state->stream = activeStream;
    ServerStreamState *raw = state.get();
    serverStreams.push_back(std::move(state));
    xqc_stream_set_user_data(activeStream, raw);
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

  void initializeGenericClientState(GenericStreamState& state)
  {
    state.owner = this;
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

  GenericStreamState *newGenericServerStreamState(xqc_stream_t *activeStream)
  {
    auto state = std::make_unique<GenericStreamState>();
    state->owner = this;
    state->stream = activeStream;
    state->phase = GenericPhase::readRequest;
    GenericStreamState *raw = state.get();
    genericStreams.push_back(std::move(state));
    xqc_stream_set_user_data(activeStream, raw);
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
    if (state == nullptr || state->complete)
    {
      return;
    }
    state->complete = true;
    state->phase = GenericPhase::complete;
    ++genericServerCompletedStreams;
  }

  void openMoreGenericClientStreams(void)
  {
    if constexpr (mode & Mode::client)
    {
      const bool earlyDataReady = benchmarkIsZeroRttReqResp() && importedZeroRtt &&
                                  conn != nullptr && xqc_conn_is_ready_to_send_early_data(conn);
      if (!genericStarted || !benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) ||
          (!connected && !earlyDataReady) || closed)
      {
        return;
      }
      const uint64_t targetStreams = benchmarkGenericStreamsPerConnection();
      const uint64_t maxActive = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
      uint64_t active = 0;
      for (const auto& item : genericStreams)
      {
        if (!item->complete)
        {
          ++active;
        }
      }
      while (genericRequestedStreams < targetStreams && active < maxActive)
      {
        auto state = std::make_unique<GenericStreamState>();
        initializeGenericClientState(*state);
        GenericStreamState *raw = state.get();
        xqc_stream_t *activeStream = xqc_stream_create(engine, &cid, nullptr, raw);
        if (activeStream == nullptr)
        {
          break;
        }
        raw->stream = activeStream;
        xqc_stream_set_user_data(activeStream, raw);
        genericStreams.push_back(std::move(state));
        ++genericRequestedStreams;
        ++active;
      }
    }
  }

  DatagramConnState *newDatagramServerState(xqc_connection_t *activeConn)
  {
    auto state = std::make_unique<DatagramConnState>();
    state->owner = this;
    state->conn = activeConn;
    DatagramConnState *raw = state.get();
    datagramServerConns.push_back(std::move(state));
    xqc_datagram_set_user_data(activeConn, raw);
    return raw;
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

  size_t datagramPayloadSize(void) const
  {
    return std::min<size_t>(benchmarkScenarioMessageBytes, sizeof(networkHub->junk));
  }

  bool datagramClientCanSend(void) const
  {
    if (conn == nullptr || !datagramStarted || !connected || closed ||
        datagramClientReceived >= benchmarkScenarioOperations)
    {
      return false;
    }
    const size_t mss = datagramClientMss != 0 ? datagramClientMss : xqc_datagram_get_mss(conn);
    if (mss < datagramPayloadSize())
    {
      return false;
    }
    const uint64_t maxInFlight = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    return datagramClientSent < datagramMaxAttempts() &&
           datagramClientSent - datagramClientReceived < maxInFlight;
  }

  bool hasPendingSimpleStreamWrite(void) const
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) ||
        benchmarkScenario == BenchmarkScenario::datagram)
    {
      return false;
    }
    if constexpr (mode & Mode::client)
    {
      return benchmarkIsUpload() && stream != nullptr &&
             requestBytesWritten == requestBytes.size() && bytesInFlight > 0;
    }
    else
    {
      for (const auto& state : serverStreams)
      {
        if (state->stream == nullptr || !state->requestParsed)
        {
          continue;
        }
        if (benchmarkIsUpload())
        {
          if (state->bytesInFlight == 0 && !state->uploadFinSent)
          {
            return true;
          }
        }
        else if (state->bytesInFlight > 0)
        {
          return true;
        }
      }
      return false;
    }
  }

  void sendClientDatagrams(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (benchmarkScenario != BenchmarkScenario::datagram || conn == nullptr || !datagramStarted)
      {
        return;
      }
      ScopedWriteGuard guard(datagramWriteInProgress);
      if (!guard)
      {
        return;
      }
      if (datagramClientSent >= datagramMaxAttempts() &&
          datagramClientReceived < benchmarkScenarioOperations)
      {
        fprintf(stderr, "xquic datagram delivery target not reached received=%" PRIu64 " sent=%" PRIu64 " target=%" PRIu64 "\n",
                datagramClientReceived, datagramClientSent, benchmarkScenarioOperations);
        abort();
      }
      const size_t payloadSize = datagramPayloadSize();
      datagramClientMss = xqc_datagram_get_mss(conn);
      if (datagramClientMss < payloadSize)
      {
        return;
      }
      uint64_t burstRemaining = 1;
      while (datagramClientCanSend() && burstRemaining > 0)
      {
        uint64_t datagramId = 0;
        xqc_int_t rv = xqc_datagram_send(conn, networkHub->junk, payloadSize, &datagramId, XQC_DATA_QOS_HIGHEST);
        if (rv == -XQC_EAGAIN)
        {
          break;
        }
        if (rv < 0)
        {
          fprintf(stderr, "xquic datagram send failed rv=%d\n", rv);
          abort();
        }
        ++datagramClientSent;
        --burstRemaining;
        drainIouringSends();
      }
    }
  }

  void sendPendingServerDatagrams(DatagramConnState *state)
  {
    if constexpr (mode & Mode::server)
    {
      if (state == nullptr || state->conn == nullptr)
      {
        return;
      }
      ScopedWriteGuard guard(state->writeInProgress);
      if (!guard)
      {
        return;
      }
      const size_t payloadSize = state->owner->datagramPayloadSize();
      state->mss = xqc_datagram_get_mss(state->conn);
      if (state->mss < payloadSize)
      {
        return;
      }
      uint64_t burstRemaining = 1;
      while (state->pendingEchoes > 0 && burstRemaining > 0)
      {
        uint64_t datagramId = 0;
        xqc_int_t rv = xqc_datagram_send(state->conn, state->owner->networkHub->junk,
                                         payloadSize, &datagramId, XQC_DATA_QOS_HIGHEST);
        if (rv == -XQC_EAGAIN)
        {
          break;
        }
        if (rv < 0)
        {
          fprintf(stderr, "xquic server datagram send failed rv=%d\n", rv);
          abort();
        }
        --state->pendingEchoes;
        ++state->echoed;
        --burstRemaining;
        state->owner->drainIouringSends();
      }
      markDatagramServerComplete(state);
    }
  }

  static ssize_t writeMmsg(const struct iovec *iov, unsigned int vlen, const struct sockaddr *peerAddr, socklen_t peerAddrLen, void *userData)
  {
    auto self = static_cast<Xquic<mode> *>(userData);
    if (self == nullptr)
    {
      return XQC_SOCKET_ERROR;
    }

    MultiUDPContext *batch = nullptr;
    unsigned int sent = 0;
    for (; sent < vlen; ++sent)
    {
      if (batch == nullptr)
      {
        batch = self->networkHub->sendPool.get();
        if (batch == nullptr)
        {
          drainNetworkIouringSends(self);
          batch = self->networkHub->sendPool.get();
          if (batch == nullptr)
          {
            break;
          }
        }
      }

      if (iov[sent].iov_len > MAX_IPV6_UDP_PACKET_SIZE)
      {
        break;
      }

      UDPContext *packet = &batch->msgs[batch->count];
      memcpy(packet->buffer(), iov[sent].iov_base, iov[sent].iov_len);
      packet->setLength(iov[sent].iov_len);
      packet->copyInAddress(peerAddr);
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

    return sent == 0 ? XQC_SOCKET_EAGAIN : static_cast<ssize_t>(sent);
  }

  static ssize_t writeMmsgEx(uint64_t pathId, const struct iovec *iov, unsigned int vlen, const struct sockaddr *peerAddr, socklen_t peerAddrLen, void *userData)
  {
    return writeMmsg(iov, vlen, peerAddr, peerAddrLen, userData);
  }

  static int serverAccept(xqc_engine_t *engine, xqc_connection_t *connection, const xqc_cid_t *acceptedCid, void *userData)
  {
    auto self = static_cast<Xquic<mode> *>(userData);
    self->conn = connection;
    memcpy(&self->cid, acceptedCid, sizeof(self->cid));
    xqc_conn_set_transport_user_data(connection, self);
    return 0;
  }

  static void serverRefuse(xqc_engine_t *engine, xqc_connection_t *connection, const xqc_cid_t *refusedCid, void *userData)
  {
  }

  static ssize_t statelessReset(const unsigned char *buf, size_t size, const struct sockaddr *peerAddr, socklen_t peerAddrLen, const struct sockaddr *localAddr, socklen_t localAddrLen, void *userData)
  {
    return sendOne(buf, size, peerAddr, peerAddrLen, userData);
  }

  static void updateCid(xqc_connection_t *connection, const xqc_cid_t *retireCid, const xqc_cid_t *newCid, void *userData)
  {
    auto self = static_cast<Xquic<mode> *>(userData);
    if (self != nullptr && newCid != nullptr)
    {
      memcpy(&self->cid, newCid, sizeof(self->cid));
    }
  }

  static void saveToken(const unsigned char *token, uint32_t tokenLen, void *userData)
  {
  }

  static void saveSession(const char *data, size_t dataLen, void *userData)
  {
    if constexpr (mode & Mode::client)
    {
      auto self = static_cast<Xquic<mode> *>(userData);
      if (self != nullptr && data != nullptr && dataLen != 0)
      {
        self->savedSession.assign(data, data + dataLen);
      }
    }
  }

  static void saveTransportParams(const char *data, size_t dataLen, void *userData)
  {
    if constexpr (mode & Mode::client)
    {
      auto self = static_cast<Xquic<mode> *>(userData);
      if (self != nullptr && data != nullptr && dataLen != 0)
      {
        self->savedTransportParams.assign(data, data + dataLen);
      }
    }
  }

  static int verifyCert(const unsigned char *certs[], const size_t certLen[], size_t certsLen, void *userData)
  {
    return 0;
  }

  static bool configuredCertificateChainValid(void)
  {
    BIO *certBio = BIO_new_file(tls_cert, "r");
    if (certBio == nullptr)
    {
      return false;
    }
    X509 *cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    if (cert == nullptr)
    {
      return false;
    }

    X509_STORE *store = X509_STORE_new();
    if (store == nullptr)
    {
      X509_free(cert);
      return false;
    }
    if (X509_STORE_load_locations(store, tls_chain, nullptr) != 1)
    {
      X509_STORE_free(store);
      X509_free(cert);
      return false;
    }

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    bool ok = false;
    if (ctx != nullptr && X509_STORE_CTX_init(ctx, store, cert, nullptr) == 1)
    {
      ok = X509_verify_cert(ctx) == 1;
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    return ok;
  }

  void updateZeroRttStats(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (conn == nullptr)
      {
        return;
      }
      xqc_conn_stats_t stats = xqc_conn_get_stats(engine, &cid);
      resumedObserved = resumedObserved || stats.session_reused == XQC_TRUE;
      if (stats.early_data_flag == XQC_0RTT_ACCEPT)
      {
        resumedObserved = true;
        zeroRttAttemptedObserved = true;
        zeroRttAcceptedObserved = true;
      }
      else if (stats.early_data_flag == XQC_0RTT_REJECT)
      {
        zeroRttAttemptedObserved = true;
        zeroRttRejectedObserved = true;
      }
    }
  }

  static void peerAddrChanged(xqc_connection_t *connection, void *userData)
  {
  }

  static void pathPeerAddrChanged(xqc_connection_t *connection, uint64_t pathId, void *userData)
  {
  }

  static int connCreate(xqc_connection_t *connection, const xqc_cid_t *newCid, void *connUserData, void *connProtoData)
  {
    auto self = static_cast<Xquic<mode> *>(connUserData);
    if (self != nullptr)
    {
      self->conn = connection;
      memcpy(&self->cid, newCid, sizeof(self->cid));
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        if constexpr (mode & Mode::server)
        {
          self->newDatagramServerState(connection);
        }
        else
        {
          xqc_datagram_set_user_data(connection, self);
        }
      }
    }
    return 0;
  }

  static int connClose(xqc_connection_t *connection, const xqc_cid_t *closedCid, void *connUserData, void *connProtoData)
  {
    auto self = static_cast<Xquic<mode> *>(connUserData);
    if (self != nullptr)
    {
      self->closed = true;
    }
    return 0;
  }

  static void handshakeDone(xqc_connection_t *connection, void *connUserData, void *connProtoData)
  {
    auto self = static_cast<Xquic<mode> *>(connUserData);
    if (self != nullptr)
    {
      self->conn = connection;
      self->connected = true;
      self->updateZeroRttStats();
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        if constexpr (mode & Mode::client)
        {
          self->datagramClientMss = xqc_datagram_get_mss(connection);
          self->sendClientDatagrams();
        }
      }
    }
  }

  static void datagramRead(xqc_connection_t *connection, void *userData, const void *data, size_t dataLen, uint64_t unixTs)
  {
    (void)data;
    (void)dataLen;
    (void)unixTs;
    if constexpr (mode & Mode::client)
    {
      auto *self = static_cast<Xquic<mode> *>(userData);
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
        xqc_conn_close(self->engine, &self->cid);
      }
      else
      {
        self->sendClientDatagrams();
      }
    }
    else
    {
      auto *state = static_cast<DatagramConnState *>(userData);
      if (state == nullptr || benchmarkScenario != BenchmarkScenario::datagram)
      {
        return;
      }
      ++state->received;
      ++state->pendingEchoes;
      state->owner->sendPendingServerDatagrams(state);
    }
  }

  static void datagramWrite(xqc_connection_t *connection, void *userData)
  {
    if constexpr (mode & Mode::client)
    {
      auto *self = static_cast<Xquic<mode> *>(userData);
      if (self != nullptr)
      {
        self->sendClientDatagrams();
      }
    }
    else
    {
      auto *state = static_cast<DatagramConnState *>(userData);
      if (state != nullptr)
      {
        state->owner->sendPendingServerDatagrams(state);
      }
    }
  }

  static void datagramMssUpdated(xqc_connection_t *connection, size_t mss, void *userData)
  {
    if constexpr (mode & Mode::client)
    {
      auto *self = static_cast<Xquic<mode> *>(userData);
      if (self != nullptr)
      {
        self->datagramClientMss = mss;
        self->sendClientDatagrams();
      }
    }
    else
    {
      auto *state = static_cast<DatagramConnState *>(userData);
      if (state != nullptr)
      {
        state->mss = mss;
        state->owner->sendPendingServerDatagrams(state);
      }
    }
  }

  static int streamCreate(xqc_stream_t *newStream, void *streamUserData)
  {
    auto self = static_cast<Xquic<mode> *>(xqc_get_conn_user_data_by_stream(newStream));
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if constexpr (mode & Mode::server)
      {
        if (self == nullptr)
        {
          self = static_cast<Xquic<mode> *>(streamUserData);
        }
        if (self != nullptr)
        {
          self->newGenericServerStreamState(newStream);
        }
      }
      else
      {
        auto state = static_cast<GenericStreamState *>(streamUserData);
        if (state != nullptr)
        {
          if (self == nullptr)
          {
            self = state->owner;
          }
          state->owner = self;
          state->stream = newStream;
          xqc_stream_set_user_data(newStream, state);
        }
      }
      return 0;
    }
    if (self == nullptr)
    {
      self = static_cast<Xquic<mode> *>(streamUserData);
    }
    if (self == nullptr)
    {
      return 0;
    }
    if constexpr (mode & Mode::server)
    {
      self->newServerStreamState(newStream);
    }
    else
    {
      self->stream = newStream;
      xqc_stream_set_user_data(newStream, self);
    }
    return 0;
  }

  static int streamClose(xqc_stream_t *closedStream, void *streamUserData)
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      auto state = static_cast<GenericStreamState *>(streamUserData);
      if (state != nullptr)
      {
        if constexpr (mode & Mode::server)
        {
          if (state->ackBytesWritten >= 1)
          {
            state->owner->markGenericServerComplete(state);
          }
        }
        else if (state->ackBytesRead >= 1)
        {
          state->owner->markGenericClientComplete(state);
        }
      }
      return 0;
    }
    if constexpr (mode & Mode::server)
    {
      auto state = static_cast<ServerStreamState *>(streamUserData);
      if (state != nullptr && state->stream == closedStream)
      {
        state->closed = true;
        state->owner->markServerStateComplete(state);
      }
    }
    else
    {
      auto self = static_cast<Xquic<mode> *>(streamUserData);
      if (self != nullptr && self->stream == closedStream)
      {
        self->clientDone = true;
      }
    }
    return 0;
  }

  static int streamRead(xqc_stream_t *readStream, void *streamUserData)
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      auto state = static_cast<GenericStreamState *>(streamUserData);
      if (state != nullptr)
      {
        if constexpr (mode & Mode::server)
        {
          state->owner->readFromServerGenericStream(*state, readStream);
        }
        else
        {
          state->owner->readFromClientGenericStream(*state, readStream);
        }
      }
      return 0;
    }
    if constexpr (mode & Mode::server)
    {
      auto state = static_cast<ServerStreamState *>(streamUserData);
      if (state != nullptr)
      {
        state->owner->readFromServerStream(*state, readStream);
      }
    }
    else
    {
      auto self = static_cast<Xquic<mode> *>(streamUserData);
      if (self != nullptr)
      {
        self->readFromStream(readStream);
      }
    }
    return 0;
  }

  static int streamWrite(xqc_stream_t *writeStream, void *streamUserData)
  {
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      auto state = static_cast<GenericStreamState *>(streamUserData);
      if (state != nullptr)
      {
        state->writeBlocked = false;
        if constexpr (mode & Mode::server)
        {
          state->owner->writeToServerGenericStream(*state, writeStream);
        }
        else
        {
          state->owner->writeToClientGenericStream(*state, writeStream);
        }
      }
      return 0;
    }
    if constexpr (mode & Mode::server)
    {
      auto state = static_cast<ServerStreamState *>(streamUserData);
      if (state != nullptr)
      {
        state->owner->writeToServerStream(*state, writeStream);
      }
    }
    else
    {
      auto self = static_cast<Xquic<mode> *>(streamUserData);
      if (self != nullptr)
      {
        self->writeToStream(writeStream);
      }
    }
    return 0;
  }

  void readFromClientGenericStream(GenericStreamState& state, xqc_stream_t *activeStream)
  {
    std::array<unsigned char, benchmarkAppChunkSize> buffer = {};

    while (true)
    {
      uint8_t fin = 0;
      ssize_t read = xqc_stream_recv(activeStream, buffer.data(), buffer.size(), &fin);
      if (read == -XQC_EAGAIN)
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
          writeToClientGenericStream(state, activeStream);
        }
      }

      if (state.writeClosed && state.ackBytesRead < 1 && consumed < static_cast<size_t>(read))
      {
        const size_t copied = std::min<size_t>(
            1 - state.ackBytesRead, static_cast<size_t>(read) - consumed);
        state.ackBytesRead += copied;
      }

      if (state.ackBytesRead >= 1)
      {
        markGenericClientComplete(&state);
      }

      if (fin)
      {
        break;
      }
    }
  }

  void readFromServerGenericStream(GenericStreamState& state, xqc_stream_t *activeStream)
  {
    std::array<unsigned char, benchmarkAppChunkSize> buffer = {};

    while (true)
    {
      uint8_t fin = 0;
      ssize_t read = xqc_stream_recv(activeStream, buffer.data(), buffer.size(), &fin);
      if (read == -XQC_EAGAIN)
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
            writeToServerGenericStream(state, activeStream);
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
              writeToServerGenericStream(state, activeStream);
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
          writeToServerGenericStream(state, activeStream);
        }
      }

      if (state.phase == GenericPhase::readResponse && consumed < static_cast<size_t>(read))
      {
        const size_t copied = std::min<size_t>(
            1 - state.doneBytesRead, static_cast<size_t>(read) - consumed);
        state.doneBytesRead += copied;
        if (state.doneBytesRead >= 1)
        {
          writeToServerGenericStream(state, activeStream);
        }
      }

      if (fin)
      {
        break;
      }
    }
  }

  void writeToClientGenericStream(GenericStreamState& state, xqc_stream_t *activeStream)
  {
    if constexpr (mode & Mode::client)
    {
      if (state.complete || state.writeClosed)
      {
        return;
      }
      if (state.writeBlocked)
      {
        return;
      }
      ScopedWriteGuard connectionGuard(writeInProgress);
      if (!connectionGuard)
      {
        return;
      }
      ScopedWriteGuard guard(state.writeInProgress);
      if (!guard)
      {
        return;
      }

      uint64_t burstRemaining = maxStreamWriteBurstBytes;
      while (state.requestBytesWritten < state.requestBytesExpected && burstRemaining > 0)
      {
        const size_t left = static_cast<size_t>(state.requestBytesExpected - state.requestBytesWritten);
        unsigned char *source = nullptr;
        if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
        {
          source = networkHub->junk;
        }
        else
        {
          source = state.requestBytes.data() + state.requestBytesWritten;
        }
        const size_t chunk = std::min<size_t>(
            left,
            static_cast<size_t>(std::min<uint64_t>(sizeof(networkHub->junk), burstRemaining)));
        ssize_t written = xqc_stream_send(activeStream, source, chunk, 0);
        if (written == -XQC_EAGAIN)
        {
          state.writeBlocked = true;
          break;
        }
        if (written <= 0)
        {
          break;
        }
        state.requestBytesWritten += static_cast<uint64_t>(written);
        burstRemaining -= static_cast<uint64_t>(written);
        drainIouringSends();
      }
      if (state.requestBytesWritten < state.requestBytesExpected)
      {
        return;
      }

      while (state.payloadRemaining > 0 && burstRemaining > 0)
      {
        const size_t chunk = static_cast<size_t>(
            std::min<uint64_t>(
                state.payloadRemaining,
                std::min<uint64_t>(sizeof(networkHub->junk), burstRemaining)));
        ssize_t written = xqc_stream_send(activeStream, networkHub->junk, chunk, 0);
        if (written == -XQC_EAGAIN)
        {
          state.writeBlocked = true;
          break;
        }
        if (written <= 0)
        {
          break;
        }
        state.payloadRemaining -= static_cast<uint64_t>(written);
        burstRemaining -= static_cast<uint64_t>(written);
        drainIouringSends();
      }
      if (state.payloadRemaining > 0)
      {
        return;
      }

      if (state.responseRemaining == 0 && state.doneBytesWritten == 0)
      {
        unsigned char done = 0;
        ssize_t written = xqc_stream_send(activeStream, &done, sizeof(done), 1);
        if (written == -XQC_EAGAIN)
        {
          state.writeBlocked = true;
          return;
        }
        if (written > 0)
        {
          state.doneBytesWritten += static_cast<size_t>(written);
          state.writeClosed = true;
          drainIouringSends();
        }
      }
    }
  }

  void writeToServerGenericStream(GenericStreamState& state, xqc_stream_t *activeStream)
  {
    if (state.complete)
    {
      return;
    }
    if (state.writeBlocked)
    {
      return;
    }
    ScopedWriteGuard connectionGuard(writeInProgress);
    if (!connectionGuard)
    {
      return;
    }
    ScopedWriteGuard guard(state.writeInProgress);
    if (!guard)
    {
      return;
    }
    if (state.phase == GenericPhase::readResponse && state.doneBytesRead > 0 && state.ackBytesWritten < 1)
    {
      unsigned char ack = 0;
      ssize_t written = xqc_stream_send(activeStream, &ack, sizeof(ack), 1);
      if (written == -XQC_EAGAIN)
      {
        state.writeBlocked = true;
        return;
      }
      if (written > 0)
      {
        state.ackBytesWritten += static_cast<size_t>(written);
        state.phase = GenericPhase::complete;
        drainIouringSends();
      }
      return;
    }
    if (state.phase != GenericPhase::sendResponse)
    {
      return;
    }

    uint64_t burstRemaining = maxStreamWriteBurstBytes;
    while (state.responseRemaining > 0 && burstRemaining > 0)
    {
      const size_t chunk = static_cast<size_t>(
          std::min<uint64_t>(
              state.responseRemaining,
              std::min<uint64_t>(sizeof(networkHub->junk), burstRemaining)));
      ssize_t written = xqc_stream_send(activeStream, networkHub->junk, chunk, 0);
      if (written == -XQC_EAGAIN)
      {
        state.writeBlocked = true;
        break;
      }
      if (written <= 0)
      {
        break;
      }
      state.responseRemaining -= static_cast<uint64_t>(written);
      burstRemaining -= static_cast<uint64_t>(written);
      drainIouringSends();
    }

    if (state.responseRemaining == 0)
    {
      state.writeClosed = true;
      state.phase = GenericPhase::readResponse;
    }
  }

  void readFromStream(xqc_stream_t *activeStream)
  {
    std::array<unsigned char, benchmarkAppChunkSize> buffer = {};

    while (true)
    {
      uint8_t fin = 0;
      ssize_t read = xqc_stream_recv(activeStream, buffer.data(), buffer.size(), &fin);
      if (read == -XQC_EAGAIN)
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
            unsigned char empty = 0;
            xqc_stream_send(activeStream, &empty, 0, 1);
            drainIouringSends();
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
            writeToStream(activeStream);
          }
        }

        if (benchmarkIsUpload() && requestParsed && consumed < static_cast<size_t>(read))
        {
          bytesInFlight -= std::min<int64_t>(bytesInFlight, static_cast<int64_t>(read - consumed));
          if (bytesInFlight == 0)
          {
            writeToStream(activeStream);
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

  void readFromServerStream(ServerStreamState& state, xqc_stream_t *activeStream)
  {
    std::array<unsigned char, benchmarkAppChunkSize> buffer = {};

    while (true)
    {
      uint8_t fin = 0;
      ssize_t read = xqc_stream_recv(activeStream, buffer.data(), buffer.size(), &fin);
      if (read == -XQC_EAGAIN)
      {
        break;
      }
      if (read < 0)
      {
        break;
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
          writeToServerStream(state, activeStream);
        }
      }

      if (benchmarkIsUpload() && state.requestParsed && consumed < static_cast<size_t>(read))
      {
        state.bytesInFlight -= std::min<int64_t>(state.bytesInFlight, static_cast<int64_t>(read - consumed));
        if (state.bytesInFlight == 0)
        {
          writeToServerStream(state, activeStream);
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

  void writeToStream(xqc_stream_t *activeStream)
  {
    if constexpr (mode & Mode::client)
    {
      ScopedWriteGuard guard(writeInProgress);
      if (!guard)
      {
        return;
      }
      while (requestBytesWritten < requestBytes.size())
      {
        ssize_t written = xqc_stream_send(
            activeStream,
            requestBytes.data() + requestBytesWritten,
            requestBytes.size() - requestBytesWritten,
            0);

        if (written == -XQC_EAGAIN)
        {
          break;
        }
        if (written < 0)
        {
          break;
        }

        requestBytesWritten += static_cast<size_t>(written);
        drainIouringSends();
      }

      if (benchmarkIsUpload() && requestBytesWritten == requestBytes.size())
      {
        uint64_t burstRemaining = maxStreamWriteBurstBytes;
        while (bytesInFlight > 0 && burstRemaining > 0)
        {
          const size_t sendLength = static_cast<size_t>(
              std::min<int64_t>(
                  bytesInFlight,
                  static_cast<int64_t>(std::min<uint64_t>(sizeof(networkHub->junk), burstRemaining))));
          const uint8_t fin = sendLength == static_cast<size_t>(bytesInFlight);

          ssize_t written = xqc_stream_send(
              activeStream,
              networkHub->junk,
              sendLength,
              fin);

          if (written == -XQC_EAGAIN)
          {
            break;
          }
          if (written < 0)
          {
            break;
          }

          bytesInFlight -= written;
          burstRemaining -= static_cast<uint64_t>(written);
          drainIouringSends();
          if (written == 0)
          {
            break;
          }
        }
      }
    }
  }

  void writeToServerStream(ServerStreamState& state, xqc_stream_t *activeStream)
  {
    ScopedWriteGuard connectionGuard(writeInProgress);
    if (!connectionGuard)
    {
      return;
    }
    ScopedWriteGuard guard(state.writeInProgress);
    if (!guard)
    {
      return;
    }
    if (benchmarkIsUpload())
    {
      if (state.requestParsed && state.bytesInFlight == 0 && !state.uploadFinSent)
      {
        unsigned char ack = 0;
        ssize_t written = xqc_stream_send(activeStream, &ack, sizeof(ack), 1);
        if (written > 0)
        {
          state.uploadFinSent = true;
          drainIouringSends();
          if (state.serverDrainDeadlineUs == 0)
          {
            state.serverDrainDeadlineUs = timeNowUs() + 100'000;
          }
          markServerStateComplete(&state);
        }
      }
      return;
    }

    uint64_t burstRemaining = maxStreamWriteBurstBytes;
    while (state.bytesInFlight > 0 && burstRemaining > 0)
    {
      const size_t sendLength = static_cast<size_t>(
          std::min<int64_t>(
              state.bytesInFlight,
              static_cast<int64_t>(std::min<uint64_t>(sizeof(networkHub->junk), burstRemaining))));
      const uint8_t fin = sendLength == static_cast<size_t>(state.bytesInFlight);

      ssize_t written = xqc_stream_send(
          activeStream,
          networkHub->junk,
          sendLength,
          fin);

      if (written == -XQC_EAGAIN)
      {
        break;
      }
      if (written < 0)
      {
        break;
      }

      state.bytesInFlight -= written;
      burstRemaining -= static_cast<uint64_t>(written);
      drainIouringSends();
      if (written == 0)
      {
        break;
      }
    }

    if (state.bytesInFlight == 0 && state.serverDrainDeadlineUs == 0)
    {
      state.serverDrainDeadlineUs = timeNowUs() + 100'000;
      markServerStateComplete(&state);
    }
  }

  void drainIouringSends(void)
  {
    drainNetworkIouringSends(this);
  }

  static xqc_conn_settings_t benchmarkConnSettings(void)
  {
    xqc_conn_settings_t settings = {};
    settings.pacing_on = 1;
    settings.cong_ctrl_callback = benchmarkCongestionProfileUsesCubic() ? xqc_cubic_cb : xqc_bbr_cb;
    if (benchmarkCongestionProfileIsAggressive())
    {
      settings.cc_params.customize_on = 1;
      settings.cc_params.init_cwnd = 32;
      settings.cc_params.bbr_enable_lt_bw = 1;
      settings.ack_frequency = 10;
    }
    settings.so_sndbuf = static_cast<uint32_t>(benchmarkConnectionWindow);
    settings.init_idle_time_out = benchmarkIdleTimeoutMs;
    settings.idle_time_out = benchmarkIdleTimeoutMs;
    settings.max_ack_delay = benchmarkMaxAckDelayMs;
    settings.max_udp_payload_size = benchmarkUdpPayloadSize;
    settings.init_recv_window = static_cast<uint32_t>(benchmarkConnectionWindow);
    settings.max_streams_bidi = benchmarkMaxBidiStreams;
    settings.max_streams_uni = benchmarkMaxUniStreams;
    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      settings.max_datagram_frame_size = benchmarkUdpPayloadSize;
    }
    return settings;
  }

  void createEngine(void)
  {
    xqc_engine_ssl_config_t sslConfig = {};
    if constexpr (mode & Mode::server)
    {
      static char ticketKey[48] = {
          'q',
          'u',
          'i',
          'c',
          'p',
          'e',
          'r',
          'f',
          'x',
          'q',
          'u',
          'i',
          'c',
          't',
          'k',
          '1',
          '0',
          '1',
          '2',
          '3',
          '4',
          '5',
          '6',
          '7',
          '8',
          '9',
          'a',
          'b',
          'c',
          'd',
          'e',
          'f',
          'g',
          'h',
          'i',
          'j',
          'k',
          'l',
          'm',
          'n',
          'o',
          'p',
          'q',
          'r',
          's',
          't',
          'u',
          'v',
      };
      sslConfig.private_key_file = const_cast<char *>(tls_key);
      sslConfig.cert_file = const_cast<char *>(tls_cert);
      sslConfig.session_ticket_key_data = ticketKey;
      sslConfig.session_ticket_key_len = sizeof(ticketKey);
    }

    xqc_config_t engineConfig = {};
    xqc_engine_type_t engineType = (mode & Mode::server) ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;
    xqc_engine_get_default_config(&engineConfig, engineType);
    engineConfig.cfg_log_level = XQC_LOG_ERROR;
    engineConfig.cfg_log_event = 0;
    engineConfig.cid_len = 12;
    if constexpr (mode & Mode::iouring)
    {
      engineConfig.sendmmsg_on = 0;
    }
    else
    {
      engineConfig.sendmmsg_on = 1;
    }

    xqc_engine_callback_t engineCallbacks = {};
    engineCallbacks.set_event_timer = setTimer;
    engineCallbacks.log_callbacks.xqc_log_write_err = ignoreLog;
    engineCallbacks.log_callbacks.xqc_log_write_stat = ignoreLog;
    engineCallbacks.log_callbacks.xqc_qlog_event_write = ignoreQlog;
    engineCallbacks.realtime_ts = now;
    engineCallbacks.monotonic_ts = now;

    xqc_transport_callbacks_t transportCallbacks = {};
    transportCallbacks.server_accept = serverAccept;
    transportCallbacks.server_refuse = serverRefuse;
    transportCallbacks.stateless_reset = statelessReset;
    transportCallbacks.write_socket = writeSocket;
    transportCallbacks.write_mmsg = writeMmsg;
    transportCallbacks.write_socket_ex = writeSocketEx;
    transportCallbacks.write_mmsg_ex = writeMmsgEx;
    transportCallbacks.conn_update_cid_notify = updateCid;
    transportCallbacks.save_token = saveToken;
    transportCallbacks.save_session_cb = saveSession;
    transportCallbacks.save_tp_cb = saveTransportParams;
    transportCallbacks.cert_verify_cb = verifyCert;
    transportCallbacks.conn_peer_addr_changed_notify = peerAddrChanged;
    transportCallbacks.path_peer_addr_changed_notify = pathPeerAddrChanged;
    transportCallbacks.conn_send_packet_before_accept = writeSocket;

    engine = xqc_engine_create(engineType, &engineConfig, &sslConfig, &engineCallbacks, &transportCallbacks, this);
    if (engine == nullptr)
    {
      fprintf(stderr, "xquic: failed to create engine cert=%s key=%s chain=%s\n", tls_cert, tls_key, tls_chain);
      abort();
    }

    xqc_app_proto_callbacks_t appCallbacks = {};
    appCallbacks.conn_cbs.conn_create_notify = connCreate;
    appCallbacks.conn_cbs.conn_close_notify = connClose;
    appCallbacks.conn_cbs.conn_handshake_finished = handshakeDone;
    appCallbacks.stream_cbs.stream_create_notify = streamCreate;
    appCallbacks.stream_cbs.stream_close_notify = streamClose;
    appCallbacks.stream_cbs.stream_read_notify = streamRead;
    appCallbacks.stream_cbs.stream_write_notify = streamWrite;
    appCallbacks.dgram_cbs.datagram_read_notify = datagramRead;
    appCallbacks.dgram_cbs.datagram_write_notify = datagramWrite;
    appCallbacks.dgram_cbs.datagram_mss_updated_notify = datagramMssUpdated;
    xqc_engine_register_alpn(engine, "perf", 4, &appCallbacks, nullptr);

    if constexpr (mode & Mode::server)
    {
      xqc_conn_settings_t settings = benchmarkConnSettings();
      xqc_server_set_conn_settings(engine, &settings);
    }
  }

  void advance(int32_t count = 0)
  {
    do
    {
      if constexpr (mode & Mode::client)
      {
        sendClientDatagrams();
      }
      xqc_engine_main_logic(engine);
      drainIouringSends();
      const int64_t timeoutUs = std::min<xqc_usec_t>(nextWakeUs, 100'000);
      const int64_t receiveTimeoutUs = hasPendingSimpleStreamWrite() ? 0 : timeoutUs;

      bool timedout = networkHub->recvmsgWithTimeout(receiveTimeoutUs, [&](UDPContext *msg) -> void {
        xqc_engine_packet_process(
            engine,
            msg->buffer(),
            msg->msg_len,
            networkHub->socket.address(),
            networkHub->socket.addressLen,
            msg->address(),
            sizeof(struct sockaddr_in6),
            timeNowUs(),
            this);
      });

      xqc_engine_finish_recv(engine);
      drainIouringSends();
      if constexpr (mode & Mode::server)
      {
        if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
        {
          for (auto& state : genericStreams)
          {
            if (state->stream != nullptr)
            {
              writeToServerGenericStream(*state, state->stream);
              if (state->ackBytesWritten >= 1 && !state->complete)
              {
                xqc_engine_main_logic(engine);
                drainIouringSends();
                markGenericServerComplete(state.get());
              }
            }
          }
        }
        else
        {
          for (auto& state : serverStreams)
          {
            if (benchmarkIsUpload() && state->stream != nullptr && state->requestParsed && state->bytesInFlight == 0 && !state->uploadFinSent)
            {
              writeToServerStream(*state, state->stream);
            }
            else if (!benchmarkIsUpload() && state->stream != nullptr && state->requestParsed && state->bytesInFlight > 0)
            {
              writeToServerStream(*state, state->stream);
            }
            markServerStateComplete(state.get());
          }
          for (auto& state : datagramServerConns)
          {
            sendPendingServerDatagrams(state.get());
            markDatagramServerComplete(state.get());
          }
        }
      }
      else if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        for (auto& state : genericStreams)
        {
          if (state->stream != nullptr)
          {
            writeToClientGenericStream(*state, state->stream);
          }
        }
      }
      else if (benchmarkIsUpload() && stream != nullptr && requestBytesWritten == requestBytes.size() && bytesInFlight > 0)
      {
        writeToStream(stream);
      }
      if (timedout)
      {
        xqc_engine_main_logic(engine);
        drainIouringSends();
      }
    } while (!perfComplete() && (count == 0 || --count > 0));
  }

public:

  void instanceSetup(uint16_t localPort, int argc, char *argv[])
  {
    networkHub = new NetworkHub<mode>(localPort);
    createEngine();
  }

  void connectToServer(struct sockaddr *address)
  {
    if constexpr (mode & Mode::client)
    {
      xqc_conn_settings_t settings = benchmarkConnSettings();
      xqc_conn_ssl_config_t sslConfig = {};
      if (importedResumption && !importedSession.empty())
      {
        sslConfig.session_ticket_data = importedSession.data();
        sslConfig.session_ticket_len = importedSession.size();
        if (!importedTransportParams.empty())
        {
          sslConfig.transport_parameter_data = importedTransportParams.data();
          sslConfig.transport_parameter_data_len = importedTransportParams.size();
        }
      }
      if (benchmarkTlsVerifyPeer())
      {
        if (!configuredCertificateChainValid())
        {
          fprintf(stderr, "xquic: configured certificate does not verify against chain cert=%s chain=%s\n", tls_cert, tls_chain);
          abort();
        }
      }

      const xqc_cid_t *newCid = xqc_connect(
          engine,
          &settings,
          nullptr,
          0,
          "localhost",
          0,
          &sslConfig,
          address,
          sizeof(struct sockaddr_in6),
          "perf",
          this);

      if (newCid != nullptr)
      {
        memcpy(&cid, newCid, sizeof(cid));
      }
      else
      {
        fprintf(stderr, "xquic: xqc_connect failed\n");
        closed = true;
      }

      while (!connected && !closed)
      {
        advance(1);
      }
      updateZeroRttStats();
    }
  }

  void connectToServerForZeroRtt(struct sockaddr *address) override
  {
    if constexpr (mode & Mode::client)
    {
      xqc_conn_settings_t settings = benchmarkConnSettings();
      xqc_conn_ssl_config_t sslConfig = {};
      if (!importedSession.empty())
      {
        sslConfig.session_ticket_data = importedSession.data();
        sslConfig.session_ticket_len = importedSession.size();
      }
      if (!importedTransportParams.empty())
      {
        sslConfig.transport_parameter_data = importedTransportParams.data();
        sslConfig.transport_parameter_data_len = importedTransportParams.size();
      }

      const xqc_cid_t *newCid = xqc_connect(
          engine,
          &settings,
          nullptr,
          0,
          "localhost",
          0,
          &sslConfig,
          address,
          sizeof(struct sockaddr_in6),
          "perf",
          this);

      if (newCid != nullptr)
      {
        memcpy(&cid, newCid, sizeof(cid));
      }
      else
      {
        fprintf(stderr, "xquic: xqc_connect failed for 0-RTT\n");
        closed = true;
        return;
      }
      zeroRttAttemptedObserved = conn != nullptr && xqc_conn_is_ready_to_send_early_data(conn);
      xqc_engine_main_logic(engine);
      drainIouringSends();
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
      if (!connected)
      {
        fprintf(stderr, "xquic: connection closed before stream creation\n");
        abort();
      }
      stream = xqc_stream_create(engine, &cid, nullptr, this);
      if (stream == nullptr)
      {
        fprintf(stderr, "xquic: xqc_stream_create failed\n");
        abort();
      }
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
        genericServerCompletedStreams = 0;
        genericStreams.clear();
        genericStarted = true;
        openMoreGenericClientStreams();
        for (auto& state : genericStreams)
        {
          if (state->stream != nullptr)
          {
            writeToClientGenericStream(*state, state->stream);
          }
        }
        advance();
        if (benchmarkIsZeroRttReqResp())
        {
          while (!connected && !closed)
          {
            advance(1);
          }
          updateZeroRttStats();
        }
        return;
      }
      if (benchmarkScenario == BenchmarkScenario::datagram)
      {
        datagramClientSent = 0;
        datagramClientReceived = 0;
        datagramClientDrainDeadlineUs = 0;
        datagramClientMss = conn != nullptr ? xqc_datagram_get_mss(conn) : 0;
        datagramStarted = true;
        sendClientDatagrams();
        advance();
        benchmarkRecordDatagramClientCounters(datagramClientSent, datagramClientReceived);
        return;
      }
      bytesInFlight = static_cast<int64_t>(nBytes);
      uint64_t swapped = bswap_64(nBytes);
      memcpy(requestBytes.data(), &swapped, requestBytes.size());
      writeToStream(stream);
    }

    advance();
  }

  bool supportsZeroRtt(void) const override
  {
    return true;
  }

  bool supportsSessionResumption(void) const override
  {
    return true;
  }

  bool exportResumptionState(BenchmarkResumptionState& state) override
  {
    if constexpr (mode & Mode::client)
    {
      for (unsigned i = 0; i < 200; ++i)
      {
        if (!savedSession.empty() && !savedTransportParams.empty())
        {
          state.session.assign(savedSession.begin(), savedSession.end());
          state.transportParams.assign(savedTransportParams.begin(), savedTransportParams.end());
          state.proofLabel = "xquic_conn_stats_session_reused";
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
      importedSession.assign(state.session.begin(), state.session.end());
      importedTransportParams.assign(state.transportParams.begin(), state.transportParams.end());
      importedResumption = true;
      importedZeroRtt = enableZeroRtt;
      resumedObserved = false;
      zeroRttAttemptedObserved = false;
      zeroRttAcceptedObserved = false;
      zeroRttRejectedObserved = false;
      return true;
    }
    return false;
  }

  bool connectionWasResumed(void) const override
  {
    return importedResumption && resumedObserved;
  }

  bool zeroRttWasAttempted(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved;
  }

  bool zeroRttWasAccepted(void) const override
  {
    return importedZeroRtt && zeroRttAcceptedObserved;
  }

  bool zeroRttWasRejected(void) const override
  {
    return importedZeroRtt && zeroRttRejectedObserved;
  }

  const char *resumptionProofLabel(void) const override
  {
    return "xquic_conn_stats_session_reused";
  }
};
