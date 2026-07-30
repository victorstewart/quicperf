#include <openssl/ssl.h>

#include <cstdlib>

extern "C" SSL_CTX* __real_SSL_CTX_new(const SSL_METHOD* method);

extern "C" SSL_CTX* __wrap_SSL_CTX_new(const SSL_METHOD* method)
{
  SSL_CTX* context = __real_SSL_CTX_new(method);
  if (context && SSL_CTX_set1_sigalgs_list(
      context, "ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256") != 1)
    std::abort();
  return context;
}
