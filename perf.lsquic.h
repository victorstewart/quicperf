#include "lsquic.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>

#pragma once

struct lsquic_conn_ctx { };
struct lsquic_stream_ctx { };

class LsTLS {
private:

	static inline char s_alpn[0x100];

	static int boringSSLPrintError(const char *str, size_t len, void *ctx)
	{
		//printf("boringSSLPrintError -> %.*s\n", len ,str);
		return 1;
	}

	static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
	{
		if (SSL_select_next_proto((unsigned char **) out, outlen, in, inlen, (unsigned char *) s_alpn, strlen(s_alpn)) == OPENSSL_NPN_NEGOTIATED)
		{
			return SSL_TLSEXT_ERR_OK;
		}
	   else
	   {
	      return SSL_TLSEXT_ERR_ALERT_FATAL;
	   }
	}

	static int verifyCallback(int ok, X509_STORE_CTX *store_ctx)
	{
		//printf("verifyCallback\n");
		return 1;
	}

	static int certVerifyCallback(X509_STORE_CTX *store_ctx, void *ctx)
	{
		//printf("certVerifyCallback\n");
		return 1;
	}

	static ssl_verify_result_t customVerifyCallback(SSL *ssl, uint8_t *out_alert)
	{
		//printf("customVerifyCallback\n");
		return ssl_verify_ok;
	}

public:

	static int verifyCert(void *verify_ctx, struct stack_st_X509 *chain)
	{
		//printf("lstls %s: verifyCert\n");
	}
	static void addALPN(const char *alpn)
	{
	   size_t alpn_len, all_len;

	   alpn_len = strlen(alpn);
	   all_len = strlen(s_alpn);

	   s_alpn[all_len] = alpn_len;
	   memcpy(&s_alpn[all_len + 1], alpn, alpn_len);
	   s_alpn[all_len + 1 + alpn_len] = '\0';
	}

	static struct ssl_ctx_st* getTLSCtx(void *peer_ctx, const struct sockaddr *address)
	{
		struct ssl_ctx_st *context = SSL_CTX_new(TLS_method());
		SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION);

		SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verifyCallback);

		SSL_CTX_set_cert_verify_callback(context, certVerifyCallback, NULL);

		SSL_CTX_set_custom_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, customVerifyCallback);

		SSL_CTX_load_verify_locations(context, tls_chain, NULL);
		SSL_CTX_set_default_verify_paths(context);

		SSL_CTX_use_certificate_file(context, tls_cert, SSL_FILETYPE_PEM);

		//SSL_CTX_use_certificate_chain_file(context, chain); // should we send the full chain ?
		SSL_CTX_use_PrivateKey_file(context, tls_key, SSL_FILETYPE_PEM);
		
		static const int X25519Only = NID_X25519;
		SSL_CTX_set1_curves(context, &X25519Only, 1);

		static const uint16_t ED25519Only = SSL_SIGN_ED25519;
		SSL_CTX_set_signing_algorithm_prefs(context, &ED25519Only, 1);
		SSL_CTX_set_verify_algorithm_prefs(context, &ED25519Only, 1);

		SSL_CTX_set_alpn_protos(context, (const uint8_t *)s_alpn, sizeof(s_alpn));
		SSL_CTX_set_alpn_select_cb(context, select_alpn, NULL);

      return context;
	}

	// static void printErrorsIfAny(void)
	// {
	// 	ERR_print_errors_cb(boringSSLPrintError, NULL);
	// }
};

template <Mode mode>
class Lsquic : public QuicLibrary<mode> {
private:

	using QuicLibrary<mode>::networkHub;

	int64_t bytesInFlight = -1;
	struct ssl_ctx_st *tlsCtx;
	lsquic_conn_t *connection;
	lsquic_stream_t *stream;
	lsquic_engine_t *engine;

	static lsquic_conn_ctx_t* connectionOpen(void *stream_if_ctx, lsquic_conn_t *connection)
	{
		//printf("lsquic %s: connectionOpen\n", modeToString(mode));

		if constexpr (mode & Mode::client)
		{
			((Lsquic<mode> *)stream_if_ctx)->connection = connection;
		}
		
		return (lsquic_conn_ctx_t *)stream_if_ctx;
	}

	static void connectionClose(lsquic_conn_t *conn) 
	{ 
		//printf("lsquic %s: connectionClose\n", modeToString(mode));
	}

	static lsquic_stream_ctx_t* streamOpen(void *stream_if_ctx, lsquic_stream_t *stream)
	{
		//printf("lsquic %s: streamOpen\n", modeToString(mode));

		lsquic_stream_wantread(stream, 1);

		if constexpr (mode & Mode::client)
		{
			((Lsquic<mode> *)stream_if_ctx)->stream = stream;
		}
		 
		return (lsquic_stream_ctx_t *)stream_if_ctx;
	}

	static void streamClose(lsquic_stream_t *stream, lsquic_stream_ctx_t *context)
	{
		//printf("lsquic %s: streamClose\n", modeToString(mode));
	}

	static size_t streamRead(void *context, const unsigned char *data, size_t len, int fin)
	{
		//printf("lsquic %s: streamRead\n", modeToString(mode));

		if constexpr (mode & Mode::client)
		{
			// throw away the bytes
			((Lsquic<mode> *)context)->bytesInFlight -= len;
		}
		else
		{
			// the client is telling us how many bytes to send it
			((Lsquic<mode> *)context)->bytesInFlight = bswap_64(*(uint64_t *)data);
		}

		return len;
	}

	static void streamReadTrigger(lsquic_stream_t *stream, lsquic_stream_ctx_t *context) 
	{
		//printf("lsquic %s: streamReadTrigger\n", modeToString(mode));

		lsquic_stream_readf(stream, streamRead, context);

		if constexpr (mode & Mode::client)
		{
			//printf("received = %.1f\n", (_1GB - ((Lsquic<mode> *)context)->bytesInFlight)/_1GB);

			// we're done
		}
		else
		{
			// start sending the client bytes
			lsquic_stream_wantwrite(stream, 1);
		}
	}

	static void streamWrite(lsquic_stream_t *stream, lsquic_stream_ctx_t *context) 
	{
		//printf("lsquic %s: streamWrite\n", modeToString(mode));

		if constexpr (mode & Mode::client)
		{
			// tell the server we want bytesInFlight
			uint64_t bytesInUgly = bswap_64(((Lsquic<mode> *)context)->bytesInFlight);
			lsquic_stream_write(stream, &bytesInUgly, sizeof(uint64_t));
			lsquic_stream_wantwrite(stream, 0);
			lsquic_stream_flush(stream);
		}
		else
		{
			NetworkHub<mode> *networkHub = ((Lsquic<mode> *)context)->networkHub;
			int64_t& bytesToSend = ((Lsquic<mode> *)context)->bytesInFlight;

			// send more junk to the client
			bytesToSend -= lsquic_stream_write(stream, networkHub->junk, (MultiUDPContext::batchSize > bytesToSend ? bytesToSend : MultiUDPContext::batchSize));

			if (unlikely(bytesToSend == 0))
			{
				// the server is done
				lsquic_stream_wantwrite(stream, 0);
				lsquic_stream_flush(stream);
			}
		}
	}

	static int packetsOut(void *context, const struct lsquic_out_spec *specs, unsigned n_specs)
	{
		// printf("lsquic %s: packetsOut -> n_specs = %lu\n", modeToString(mode), n_specs);

		NetworkHub<mode> *networkHub = ((Lsquic<mode> *)context)->networkHub;

		MultiUDPContext *packets = networkHub->sendPool.get();

		for (uint32_t index = 0; index < n_specs; index++)
		{
			const struct lsquic_out_spec& spec = specs[index];

			for (uint32_t subIndex = 0; subIndex < spec.iovlen; subIndex++)
			{
				struct iovec& vec = spec.iov[subIndex];

				UDPContext *packet = packets->nextPacket();

				if (packet == NULL) 
				{
					networkHub->sendBatch(packets);
					packets = networkHub->sendPool.get();
					packet = packets->nextPacket();
				}

				packet->copyInAddress(spec.dest_sa);
				packet->copyInIov(vec);
			}
		}

		networkHub->sendBatch(packets);
		return n_specs;
	}

	void advance(int32_t count = 0)
	{
		//printf("lsquic %s: advance(%d)\n", modeToString(mode), count);

		do
		{
			lsquic_engine_process_conns(engine);

			int usTil = 0;
 			lsquic_engine_earliest_adv_tick(engine, &usTil);

 			networkHub->recvmsgWithTimeout(usTil, [&] (UDPContext *msg) -> void {

 				int result = lsquic_engine_packet_in(engine, (const unsigned char *)msg->buffer(), msg->msg_len, (const struct sockaddr *)networkHub->socket.address6, (const struct sockaddr *)msg->address(), this, 0);
 			});

		} while (bytesInFlight != 0 && (count == 0 || --count > 0));
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

		LsTLS::addALPN("perf");

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

		//printf("lsquic %s: setup\n", modeToString(mode));

      static struct lsquic_engine_settings settings;
      memset(&settings, 0, sizeof(struct lsquic_engine_settings));

      if constexpr (mode & Mode::server)
      {
      	lsquic_engine_init_settings(&settings, LSENG_SERVER);
      }
      else
      {
      	lsquic_engine_init_settings(&settings, 0);
      }

      settings.es_sfcw = 1024 * 1024;
      settings.es_cfcw = 1024 * 1024;
      settings.es_max_sfcw = 8 * settings.es_sfcw;
      settings.es_max_cfcw = 8 * settings.es_cfcw;
      settings.es_max_inchoate = 10'000;
      settings.es_versions = (1 << LSQVER_I001);
      settings.es_pace_packets = 1;
      settings.es_cc_algo = 1; // 2 for bbr
      settings.es_idle_timeout = 600;
      settings.es_ecn = 0;
      settings.es_ql_bits = 2;
      settings.es_spin = 1;
      settings.es_scid_len = 8;
		settings.es_delayed_acks = 1;
		settings.es_max_udp_payload_size_rx = 1500;
		settings.es_dplpmtud = 1;
		settings.es_base_plpmtu = 1400;
		settings.es_max_plpmtu = 1500;
		settings.es_max_batch_size = 50;

		static struct lsquic_stream_if streamConfig = {	.on_new_conn = connectionOpen,
																		.on_conn_closed = connectionClose,
																		.on_new_stream = streamOpen,
																		.on_read = streamReadTrigger,
																		.on_write = streamWrite,
																		.on_close = streamClose
																	};

		static struct lsquic_engine_api config = { 	.ea_settings = &settings,
																	.ea_stream_if = &streamConfig,
																	.ea_stream_if_ctx = this,
																	.ea_packets_out = packetsOut,
																	.ea_packets_out_ctx = this,
																	.ea_get_ssl_ctx = LsTLS::getTLSCtx,
																	.ea_verify_cert = LsTLS::verifyCert,
																	.ea_verify_ctx = this,
																	.ea_alpn = "perf"
																};

		if constexpr (mode & Mode::server)
		{
			engine = lsquic_engine_new(LSENG_SERVER, &config);
		}
		else
		{
			engine = lsquic_engine_new(0, &config);
		}
	}

	void connect(struct sockaddr *address)
	{
		//printf("lsquic %s: connect\n", modeToString(mode));

		lsquic_conn_t *conn = lsquic_engine_connect(engine, LSQVER_I001, networkHub->socket.address(), address, this, (lsquic_conn_ctx_t *)this, NULL, 1400, NULL, 0, NULL, 0);

		do
		{
			advance(1);

		} while (connection == NULL);
	}

	void openStream(void)
	{
		//printf("lsquic %s: openStream\n", modeToString(mode));

		lsquic_conn_make_stream(connection);

		do
		{
			advance(1);

		} while (stream == NULL);
	}

	void startPerfTest(uint64_t nBytes)
	{
		//printf("lsquic %s: startPerfTest\n", modeToString(mode));

		if constexpr (mode & Mode::client)
		{
			bytesInFlight = nBytes;
			lsquic_stream_wantwrite(stream, 1);
		}

		advance();
	}
};
