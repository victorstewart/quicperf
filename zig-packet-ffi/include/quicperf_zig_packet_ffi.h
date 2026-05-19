#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qzf_engine_t qzf_engine_t;

typedef struct qzf_addr_t {
  uint8_t ip[16];
  uint16_t port;
} qzf_addr_t;

typedef struct qzf_config_t {
  bool is_server;
  qzf_addr_t local_addr;
  const char *cert_path;
  const char *key_path;
  const char *chain_path;
  bool tls_verify_peer;
  bool use_bbr;
  bool disable_pacing;
  uint64_t connection_window;
  uint64_t stream_window;
  uint64_t max_bidi_streams;
  uint64_t max_uni_streams;
  uint64_t idle_timeout_ms;
  uint32_t udp_payload_size;
  uint64_t send_backlog_limit;
  uint64_t now_us;
} qzf_config_t;

typedef struct qzf_stream_debug_t {
  bool found;
  uint64_t send_write_offset;
  uint64_t send_send_offset;
  uint64_t send_ack_offset;
  uint64_t send_window;
  uint64_t send_retransmit_count;
  bool send_fin_queued;
  bool send_fin_sent;
  bool send_fin_lost;
  bool send_has_data;
  bool send_has_unacked;
  uint64_t recv_read_pos;
  uint64_t recv_highest_buffered;
  uint64_t recv_fin_offset;
  bool recv_fin_known;
  bool recv_finished;
  uint64_t recv_chunk_count;
  uint64_t bytes_in_flight;
  uint64_t cwnd;
  uint64_t conn_send_window;
} qzf_stream_debug_t;

qzf_engine_t *qzf_engine_new(const qzf_config_t *config);
void qzf_engine_free(qzf_engine_t *engine);

int qzf_engine_connect(qzf_engine_t *engine, const qzf_addr_t *remote, uint64_t now_us, uint64_t *conn_id);
int qzf_engine_accept_connection(qzf_engine_t *engine, uint64_t *conn_id);
int qzf_engine_is_connected(qzf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qzf_engine_receive(qzf_engine_t *engine, const qzf_addr_t *remote, uint8_t *data, size_t len, uint64_t now_us);
int qzf_engine_poll_transmit(qzf_engine_t *engine, qzf_addr_t *remote, uint8_t *data, size_t capacity, size_t *len, uint64_t now_us);
int qzf_engine_next_timeout_us(qzf_engine_t *engine, uint64_t now_us, uint64_t *timeout_us);
int qzf_engine_on_timeout(qzf_engine_t *engine, uint64_t now_us);
int qzf_engine_has_pending_app_data(qzf_engine_t *engine);
int qzf_engine_export_resumption_state(qzf_engine_t *engine, uint64_t conn_id, uint8_t *data, size_t capacity, size_t *len, uint64_t now_us);
int qzf_engine_import_resumption_state(qzf_engine_t *engine, const uint8_t *data, size_t len, bool use_zero_rtt, uint64_t now_us);
int qzf_connection_resumed(qzf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qzf_connection_zero_rtt_attempted(qzf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qzf_connection_zero_rtt_accepted(qzf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qzf_connection_zero_rtt_rejected(qzf_engine_t *engine, uint64_t conn_id, uint64_t now_us);

int qzf_connection_open_bidi(qzf_engine_t *engine, uint64_t conn_id, uint64_t *stream_id, uint64_t now_us);
int qzf_connection_accept_bidi(qzf_engine_t *engine, uint64_t conn_id, uint64_t *stream_id, uint64_t now_us);
int qzf_stream_send(qzf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, const uint8_t *data, size_t len, size_t *written, uint64_t now_us);
int qzf_stream_recv(qzf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, uint8_t *data, size_t capacity, size_t *read, bool *fin, uint64_t now_us);
int qzf_stream_finish(qzf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, uint64_t now_us);
int qzf_stream_debug(qzf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, qzf_stream_debug_t *debug);
int qzf_datagram_send(qzf_engine_t *engine, uint64_t conn_id, const uint8_t *data, size_t len, uint64_t now_us);
int qzf_datagram_recv(qzf_engine_t *engine, uint64_t conn_id, uint8_t *data, size_t capacity, size_t *read, uint64_t now_us);

const char *qzf_last_error(void);

#ifdef __cplusplus
}
#endif
