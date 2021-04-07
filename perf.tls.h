#include <openssl/ssl.h>
#include <openssl/bio.h>

#pragma once

class TLS {
private:

	static constexpr uint8_t alpn[5] = {4, 'p', 'e', 'r', 'f'};

	static int boringSSLPrintError(const char *str, size_t len, void *ctx)
	{
		printf("boringSSLPrintError -> %.*s\n", len ,str);
		return 1;
	}

	static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
	{
		if (SSL_select_next_proto((unsigned char **) out, outlen, in, inlen, (unsigned char *) alpn, sizeof(alpn)) == OPENSSL_NPN_NEGOTIATED)
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

	static struct ssl_ctx_st* getTLSCtx(void *peer_ctx = NULL, const struct sockaddr *address = NULL)
	{
		struct ssl_ctx_st *context = SSL_CTX_new(TLS_method());
		SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION);

		//SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verifyCallback);
		//SSL_CTX_set_verify(context, SSL_VERIFY_NONE, verifyCallback);

		//SSL_CTX_set_cert_verify_callback(context, certVerifyCallback, NULL);

		//SSL_CTX_set_custom_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, customVerifyCallback);

		SSL_CTX_use_certificate_file(context, tls_cert, SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(context, tls_key, SSL_FILETYPE_PEM);

		SSL_CTX_load_verify_locations(context, tls_chain, NULL);
		
		static const int X25519Only = NID_X25519;
		SSL_CTX_set1_curves(context, &X25519Only, 1);

		static const uint16_t ED25519Only = SSL_SIGN_ED25519;
		SSL_CTX_set_signing_algorithm_prefs(context, &ED25519Only, 1);
		SSL_CTX_set_verify_algorithm_prefs(context, &ED25519Only, 1);
		
		SSL_CTX_set_alpn_protos(context, alpn, sizeof(alpn));
	 	SSL_CTX_set_alpn_select_cb(context, select_alpn, NULL);

      return context;
	}

	static void printErrorsIfAny(void)
	{
		ERR_print_errors_cb(boringSSLPrintError, NULL);
	}
};