#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qpf_engine_t qpf_engine_t;

enum {
    QPF_LIBRARY_QUINN = 1,
    QPF_LIBRARY_NOQ = 2,
    QPF_LIBRARY_NEQO = 3,
    QPF_LIBRARY_S2N = 4,
};

typedef struct qpf_addr_t {
    uint8_t ip[16];
    uint16_t port;
} qpf_addr_t;

typedef struct qpf_config_t {
    uint32_t library;
    bool is_server;
    qpf_addr_t local_addr;
    const char *cert_path;
    const char *key_path;
    const char *chain_path;
    bool tls_verify_peer;
    bool use_bbr;
    uint64_t connection_window;
    uint64_t stream_window;
    uint64_t max_bidi_streams;
    uint64_t max_uni_streams;
    uint64_t idle_timeout_ms;
    uint32_t udp_payload_size;
    uint64_t now_us;
} qpf_config_t;

qpf_engine_t *qpf_engine_new(const qpf_config_t *config);
void qpf_engine_free(qpf_engine_t *engine);

int qpf_engine_connect(qpf_engine_t *engine, const qpf_addr_t *remote, uint64_t now_us, uint64_t *conn_id);
int qpf_engine_accept_connection(qpf_engine_t *engine, uint64_t *conn_id);
int qpf_engine_is_connected(qpf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qpf_engine_receive(qpf_engine_t *engine, const qpf_addr_t *remote, const uint8_t *data, size_t len, uint64_t now_us);
int qpf_engine_poll_transmit(qpf_engine_t *engine, qpf_addr_t *remote, uint8_t *data, size_t capacity, size_t *len, uint64_t now_us);
int qpf_engine_next_timeout_us(qpf_engine_t *engine, uint64_t now_us, uint64_t *timeout_us);
int qpf_engine_on_timeout(qpf_engine_t *engine, uint64_t now_us);

int qpf_connection_open_bidi(qpf_engine_t *engine, uint64_t conn_id, uint64_t *stream_id, uint64_t now_us);
int qpf_connection_accept_bidi(qpf_engine_t *engine, uint64_t conn_id, uint64_t *stream_id, uint64_t now_us);
int qpf_stream_send(qpf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, const uint8_t *data, size_t len, size_t *written, uint64_t now_us);
int qpf_stream_recv(qpf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, uint8_t *data, size_t capacity, size_t *read, bool *fin, uint64_t now_us);
int qpf_stream_finish(qpf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, uint64_t now_us);
int qpf_datagram_send(qpf_engine_t *engine, uint64_t conn_id, const uint8_t *data, size_t len, uint64_t now_us);
int qpf_datagram_recv(qpf_engine_t *engine, uint64_t conn_id, uint8_t *data, size_t capacity, size_t *read, uint64_t now_us);

const char *qpf_last_error(void);

#ifdef __cplusplus
}
#endif
