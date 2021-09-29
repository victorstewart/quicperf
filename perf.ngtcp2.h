#include <cassert>
#include <iostream>

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
  uint8_t alert = 0;
  int64_t bytesInFlight = -1;
  bool data_ready = false;
  std::array<uint8_t, sizeof(int64_t)> reqsizebuf;
  size_t reqsizebuflen = 0;
  size_t reqsizebufoffset = 0;
  bool stream_opened = false;

  static int set_read_secret(SSL *ssl, enum ssl_encryption_level_t ssl_level,
                             const SSL_CIPHER *cipher, const uint8_t *secret,
                             size_t secretlen) {
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
                              size_t secretlen) {
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
                                const uint8_t *data, size_t len) {
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

  constexpr static int flush_flight(SSL *ssl) { return 1; }

  static int send_alert(SSL *ssl, enum ssl_encryption_level_t level,
                        uint8_t alert) {
    auto c = static_cast<Ngtcp2<mode> *>(SSL_get_app_data(ssl));

    c->alert = alert;

    return 1;
  }

  constexpr static auto quic_method = SSL_QUIC_METHOD{
      set_read_secret, set_write_secret, add_handshake_data,
      flush_flight,    send_alert,
  };

  static void rand(uint8_t *dest, size_t destlen,
                   const ngtcp2_rand_ctx *rand_ctx) {
    RAND_bytes(dest, static_cast<int>(destlen));
  }

  static int extend_max_stream_data_server(ngtcp2_conn *conn, int64_t stream_id,
                                           uint64_t max_data, void *user_data,
                                           void *stream_user_data) {
    if (stream_id != 0)
    {
      return 0;
    }

    auto c = static_cast<Ngtcp2<mode> *>(user_data);

    if (c->bytesInFlight > 0)
    {
      c->data_ready = true;
    }

    return 0;
  }

  static int recv_stream_data_server(ngtcp2_conn *conn, uint32_t flags,
                                     int64_t stream_id, uint64_t offset,
                                     const uint8_t *data, size_t datalen,
                                     void *user_data, void *stream_user_data) {
    if (stream_id != 0)
    {
      return 0;
    }

    auto c = static_cast<Ngtcp2<mode> *>(user_data);

    if (c->reqsizebuf.size() == c->reqsizebuflen)
    {
      return 0;
    }

    auto n = std::min(c->reqsizebuf.size() - c->reqsizebuflen, datalen);
    std::copy_n(data, n, c->reqsizebuf.data());
    c->reqsizebuflen += n;

    if (c->reqsizebuf.size() > c->reqsizebuflen)
    {
      return 0;
    }

    memcpy(&c->bytesInFlight, c->reqsizebuf.data(), c->reqsizebuf.size());
    c->bytesInFlight = bswap_64(c->bytesInFlight);

    c->data_ready = true;

    return 0;
  }

  static int recv_stream_data_client(ngtcp2_conn *conn, uint32_t flags,
                                     int64_t stream_id, uint64_t offset,
                                     const uint8_t *data, size_t datalen,
                                     void *user_data, void *stream_user_data) {
    ngtcp2_conn_extend_max_offset(conn, datalen);

    if (stream_id != 0)
    {
      return 0;
    }

    auto c = static_cast<Ngtcp2<mode> *>(user_data);

    if (c->bytesInFlight < datalen)
    {
      c->bytesInFlight = 0;
    } else
    {
      c->bytesInFlight -= datalen;

      ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    }

    return 0;
  }

  static int extend_max_streams_bidi_client(ngtcp2_conn *conn,
                                            uint64_t max_streams,
                                            void *user_data) {
    auto c = static_cast<Ngtcp2<mode> *>(user_data);

    if (c->stream_opened)
    {
      return 0;
    }

    int64_t stream_id;
    if (auto rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, nullptr);
        rv != 0)
    {
      assert(NGTCP2_ERR_STREAM_ID_BLOCKED == rv);
      return 0;
    }

    assert(0 == stream_id);

    c->stream_opened = true;

    return 0;
  }

  void init_conn_server(UDPContext *msg) {
    ngtcp2_pkt_hd hd;
    if (auto rv = ngtcp2_accept(&hd, msg->buffer(), msg->msg_len); rv != 0)
    {
      std::cerr << "ngtcp2_accept: " << rv << std::endl;
      assert(0);
      abort();
    }

    auto callbacks = ngtcp2_callbacks{
        nullptr, // client_initial
        ngtcp2_crypto_recv_client_initial_cb,
        ngtcp2_crypto_recv_crypto_data_cb,
        nullptr, // handshake_completed
        nullptr, // recv_version_negotiation
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        recv_stream_data_server,
        nullptr, // acked_stream_data_offset
        nullptr, // stream_open
        nullptr, // stream_close
        nullptr, // recv_stateless_reset
        nullptr, // recv_retry
        nullptr, // extend_max_streams_bidi
        nullptr, // extend_max_streams_uni
        rand,
        nullptr, // get_new_connection_id
        nullptr, // remove_connection_id
        ngtcp2_crypto_update_key_cb,
        nullptr, // path_validation
        nullptr, // select_preferred_addr
        nullptr, // stream_reset
        nullptr, // extend_max_remote_streams_bidi
        nullptr, // extend_max_remote_streams_uni
        extend_max_stream_data_server,
        nullptr, // dcid_status
        nullptr, // handshake_confirmed
        nullptr, // recv_new_token
        ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        nullptr, // recv_datagram
        nullptr, // ack_datagram
        nullptr, // lost_datagram
        ngtcp2_crypto_get_path_challenge_data_cb,
    };

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = timeNowUs() * NGTCP2_MICROSECONDS;
    settings.max_stream_window = 8 * 1024 * 1024;
    settings.max_window = 8 * 1024 * 1024;
    settings.max_udp_payload_size = MAX_IPV6_UDP_PACKET_SIZE;
    settings.no_udp_payload_size_shaping = 1;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = 100;
    params.initial_max_stream_data_bidi_remote = 1024 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.original_dcid = hd.dcid;

    auto path =
        ngtcp2_path{{sizeof(struct sockaddr_in6),
                     reinterpret_cast<sockaddr *>(networkHub->socket.address6)},
                    {sizeof(struct sockaddr_in6), msg->address()}};

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

    ngtcp2_conn_set_tls_native_handle(conn, ssl);
  }

  void init_conn_client(struct sockaddr *address) {
    auto callbacks = ngtcp2_callbacks{
        ngtcp2_crypto_client_initial_cb,
        nullptr, // recv_client_initial
        ngtcp2_crypto_recv_crypto_data_cb,
        nullptr, // handshake_completed
        nullptr, // recv_version_negotiation
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        recv_stream_data_client,
        nullptr, // acked_stream_data_offset
        nullptr, // stream_open
        nullptr, // stream_close
        nullptr, // recv_stateless_reset
        ngtcp2_crypto_recv_retry_cb,
        extend_max_streams_bidi_client,
        nullptr, // extend_max_streams_uni
        rand,
        nullptr, // get_new_connection_id
        nullptr, // remove_connection_id
        ngtcp2_crypto_update_key_cb,
        nullptr, // path_validation
        nullptr, // select_preferred_addr
        nullptr, // stream_reset
        nullptr, // extend_max_remote_streams_bidi
        nullptr, // extend_max_remote_streams_uni
        nullptr, // extend_max_stream_data
        nullptr, // dcid_status
        nullptr, // handshake_confirmed
        nullptr, // recv_new_token
        ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        nullptr, // recv_datagram
        nullptr, // ack_datagram
        nullptr, // lost_datagram
        ngtcp2_crypto_get_path_challenge_data_cb,
    };

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = timeNowUs() * NGTCP2_MICROSECONDS;
    settings.max_stream_window = 8 * 1024 * 1024;
    settings.max_window = 8 * 1024 * 1024;
    settings.max_udp_payload_size = MAX_IPV6_UDP_PACKET_SIZE;
    settings.no_udp_payload_size_shaping = 1;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 1024 * 1024;
    params.initial_max_data = 1024 * 1024;

    auto path =
        ngtcp2_path{{sizeof(struct sockaddr_in6),
                     reinterpret_cast<sockaddr *>(networkHub->socket.address6)},
                    {sizeof(struct sockaddr_in6), address}};

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

    ngtcp2_conn_set_tls_native_handle(conn, ssl);
  }

  std::tuple<int64_t, ngtcp2_vec, size_t, uint32_t> get_stream_data_server() {
    int64_t stream_id = -1;
    size_t vcnt = 0;
    ngtcp2_vec vec{};
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

    if (data_ready && bytesInFlight >= 0 && ngtcp2_conn_get_max_data_left(conn))
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

  std::tuple<int64_t, ngtcp2_vec, size_t, uint32_t> get_stream_data_client() {
    int64_t stream_id = -1;
    size_t vcnt = 0;
    ngtcp2_vec vec{};
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

    if (data_ready && ngtcp2_conn_get_max_data_left(conn))
    {
      vec.len = reqsizebuflen - reqsizebufoffset;
      vec.base = reqsizebuf.data() + reqsizebufoffset;
      vcnt = 1;
      stream_id = 0;
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    return {stream_id, vec, vcnt, flags};
  }

  std::tuple<int64_t, ngtcp2_vec, size_t, uint32_t> get_stream_data() {
    if constexpr (mode & Mode::server)
    {
      return get_stream_data_server();
    } else
    { return get_stream_data_client(); }
  }

  void stream_data_sent_server(size_t datalen) {
    bytesInFlight -= datalen;
    if (bytesInFlight == 0)
    {
      data_ready = false;
    }
  }

  void stream_data_sent_client(size_t datalen) {
    reqsizebufoffset += datalen;
    if (reqsizebufoffset == reqsizebuflen)
    {
      data_ready = false;
    }
  }

  void stream_data_sent(size_t datalen) {
    if constexpr (mode & Mode::server)
    {
      return stream_data_sent_server(datalen);
    } else
    { return stream_data_sent_client(datalen); }
  }

  void send_packet(ngtcp2_tstamp ts) {
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
      auto remote_addr = packet->address();

      for (;;)
      {
        sockaddr_storage local_addr;

        auto [stream_id, vec, vcnt, flags] = get_stream_data();
        auto path = ngtcp2_path{
            {0, reinterpret_cast<sockaddr *>(&local_addr)},
            {0, reinterpret_cast<sockaddr *>(remote_addr)},
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
        } else if (ndatalen >= 0)
        { stream_data_sent(static_cast<size_t>(ndatalen)); }

        if (nwrite == 0)
        {
          break;
        }

        packet->msg_hdr.msg_iov[0].iov_len = nwrite;
        ++packets->count;

        break;
      }
    } while (nwrite > 0 && packets->count < MultiUDPContext::batchSize);

    if (packets->count > 0)
    {
      networkHub->sendBatch(packets);
    } else
    { networkHub->sendPool.relinquish(packets); }
  }

  void advance(int32_t count = 0) {
    do
    {
      int64_t usTil = 0;
      if (conn)
      {
        auto now = timeNowUs() * NGTCP2_MICROSECONDS;

        send_packet(now);

        auto expiry = ngtcp2_conn_get_expiry(conn);
        if (expiry != std::numeric_limits<uint64_t>::max() && now < expiry)
        {
          usTil = static_cast<int64_t>(std::max(
              (expiry - now) / NGTCP2_MICROSECONDS, static_cast<uint64_t>(1)));
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

        auto path = ngtcp2_path{
            {sizeof(struct sockaddr_in6),
             reinterpret_cast<sockaddr *>(networkHub->socket.address6)},
            {sizeof(struct sockaddr_in6), msg->address()}};
        auto pi = ngtcp2_pkt_info{};

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
    } while (bytesInFlight != 0 && (count == 0 || --count > 0));
  }

public:
  void instanceSetup(uint16_t localPort, int argc, char *argv[]) {
    networkHub = new NetworkHub<mode>(localPort);

    ssl_ctx = TLS::getTLSCtx();

    SSL_CTX_set_quic_method(ssl_ctx, &quic_method);
  }

  void connectToServer(struct sockaddr *address) { init_conn_client(address); }

  void openStream(void) {}

  void startPerfTest(uint64_t nBytes) {
    if constexpr (mode & Mode::client)
    {
      bytesInFlight = nBytes;
      data_ready = true;

      auto n = bswap_64(bytesInFlight);
      reqsizebuflen = sizeof(n);
      memcpy(reqsizebuf.data(), &n, reqsizebuflen);
    }

    advance();
  }
};
