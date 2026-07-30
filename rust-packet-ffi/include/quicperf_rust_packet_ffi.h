#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qpf_engine_t qpf_engine_t;

enum {
  QPF_PACKET_ABI_VERSION = 8,
  QPF_PACKET_BATCH_CAPACITY = 64,
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
  qpf_addr_t peer_addr;
  const char *cert_path;
  const char *key_path;
  const char *chain_path;
  const char *tls_hostname;
  bool tls_verify_peer;
  bool use_bbr;
  uint64_t initial_congestion_window_bytes;
  uint64_t max_ack_delay_ns;
  uint64_t ack_delay_exponent;
  bool ack_frequency;
  bool active_migration;
  uint64_t active_connection_id_limit;
  uint64_t connection_id_bytes;
  uint64_t connection_window;
  uint64_t stream_window;
  uint64_t stream_credit_replenish_below;
  uint64_t max_bidi_streams;
  uint64_t max_uni_streams;
  uint64_t idle_timeout_ms;
  uint32_t udp_payload_size;
  uint64_t datagram_max_frame_size;
  uint64_t datagram_max_unreturned_per_connection;
  uint64_t ticket_lifetime_ns;
  uint64_t maximum_early_data_bytes;
  bool one_use_tickets;
  uint64_t now_us;
  uint64_t calendar_unix_seconds;
} qpf_config_t;

typedef struct qpf_receive_descriptor_v2_t {
  const uint8_t *data;
  size_t len;
  qpf_addr_t peer;
  uint8_t ecn;
  uint8_t reserved[7];
} qpf_receive_descriptor_v2_t;

typedef struct qpf_transmit_descriptor_v2_t {
  uint8_t *data;
  size_t capacity;
  size_t len;
  qpf_addr_t peer;
  uint8_t ecn;
  uint8_t reserved[7];
  uint64_t desired_send_raw_ns;
} qpf_transmit_descriptor_v2_t;

typedef struct qpf_adapter_status_v2_t {
  int32_t code;
  uint32_t reserved;
  char message[256];
} qpf_adapter_status_v2_t;

typedef struct qpf_transport_counters_v3_t {
  uint64_t packets_lost;
  uint64_t packets_retransmitted;
  uint64_t recovery_wakeups;
  uint64_t flow_control_blocked_events;
  uint64_t stream_credit_blocked_events;
} qpf_transport_counters_v3_t;

typedef struct qpf_peer_terminal_facts_v6_t {
  bool available;
  bool fin;
  bool reset_stream;
  bool stop_sending;
  bool connection_close;
  uint8_t reserved[3];
  uint64_t reset_stream_error;
  uint64_t stop_sending_error;
  uint64_t connection_close_error;
  uint64_t connection_close_reason_length;
} qpf_peer_terminal_facts_v6_t;

typedef struct qpf_negotiated_settings_v7_t {
  uint8_t available;
  uint8_t alpn_qperf_2;
  uint8_t peer_certificate_present;
  uint8_t peer_certificate_verified;
  uint8_t hostname_verified;
  uint8_t tls_leaf_ed25519;
  uint8_t use_bbr;
  uint8_t ack_frequency;
  uint8_t active_migration;
  uint8_t one_use_tickets;
  uint8_t reserved8[6];
  uint32_t quic_version;
  uint16_t tls_version;
  uint16_t tls_cipher_suite;
  uint16_t tls_key_exchange_group;
  uint16_t tls_leaf_signature_algorithm;
  uint32_t reserved32;
  uint64_t initial_congestion_window_bytes;
  uint64_t max_udp_payload_size;
  uint64_t max_ack_delay_ns;
  uint64_t ack_delay_exponent;
  uint64_t active_connection_id_limit;
  uint64_t connection_id_bytes;
  uint64_t max_idle_timeout_ns;
  uint64_t max_bidi_streams;
  uint64_t max_uni_streams;
  uint64_t stream_credit_replenish_below;
  uint64_t connection_window_bytes;
  uint64_t stream_window_bytes;
  uint64_t datagram_max_frame_size;
  uint64_t ticket_lifetime_ns;
  uint64_t maximum_early_data_bytes;
} qpf_negotiated_settings_v7_t;

qpf_engine_t *qpf_engine_new(const qpf_config_t *config);
void qpf_engine_free(qpf_engine_t *engine);

int qpf_engine_connect(qpf_engine_t *engine, const qpf_addr_t *remote, uint64_t now_us, uint64_t *conn_id);
int qpf_engine_accept_connection(qpf_engine_t *engine, uint64_t *conn_id);
int qpf_engine_is_connected(qpf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qpf_connection_is_closed(qpf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qpf_connection_retire(qpf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qpf_engine_receive(qpf_engine_t *engine, const qpf_addr_t *remote, const uint8_t *data, size_t len, uint64_t now_us);
int qpf_engine_poll_transmit(qpf_engine_t *engine, qpf_addr_t *remote, uint8_t *data, size_t capacity, size_t *len, uint64_t now_us);
int qpf_engine_next_timeout_us(qpf_engine_t *engine, uint64_t now_us, uint64_t *timeout_us);
int qpf_engine_on_timeout(qpf_engine_t *engine, uint64_t now_us);

/* Publication ABI. Descriptors and packet storage are borrowed for the call. */
uint32_t qpf_packet_abi_version(void);
int qpf_engine_receive_batch(qpf_engine_t *engine,
                             const qpf_receive_descriptor_v2_t *packets,
                             size_t count,
                             uint64_t now_raw_ns,
                             qpf_adapter_status_v2_t *status);
int qpf_engine_poll_transmit_batch(qpf_engine_t *engine,
                                   qpf_transmit_descriptor_v2_t *packets,
                                   size_t capacity,
                                   size_t *count,
                                   uint64_t now_raw_ns,
                                   qpf_adapter_status_v2_t *status);
int qpf_engine_next_timeout_raw_ns(qpf_engine_t *engine,
                                   uint64_t now_raw_ns,
                                   uint64_t *deadline_raw_ns,
                                   qpf_adapter_status_v2_t *status);
int qpf_engine_on_timeout_raw_ns(qpf_engine_t *engine,
                                 uint64_t now_raw_ns,
                                 qpf_adapter_status_v2_t *status);
int qpf_engine_transport_counters_v3(qpf_engine_t *engine,
                                     qpf_transport_counters_v3_t *counters,
                                     qpf_adapter_status_v2_t *status);
int qpf_engine_negotiated_settings_v7(qpf_engine_t *engine,
                                      qpf_negotiated_settings_v7_t *settings,
                                      qpf_adapter_status_v2_t *status);
int qpf_peer_terminal_facts_v6(qpf_engine_t *engine,
                               uint64_t conn_id,
                               uint64_t stream_id,
                               qpf_peer_terminal_facts_v6_t *facts,
                               uint64_t now_us);
int qpf_engine_export_resumption_state(qpf_engine_t *engine, uint64_t conn_id, uint8_t *data, size_t capacity, size_t *len, uint64_t now_us);
int qpf_engine_import_resumption_state(qpf_engine_t *engine, const uint8_t *data, size_t len, bool use_zero_rtt, uint64_t now_us);
int qpf_connection_resumed(qpf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qpf_connection_zero_rtt_attempted(qpf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qpf_connection_zero_rtt_accepted(qpf_engine_t *engine, uint64_t conn_id, uint64_t now_us);
int qpf_connection_zero_rtt_rejected(qpf_engine_t *engine, uint64_t conn_id, uint64_t now_us);

int qpf_connection_open_bidi(qpf_engine_t *engine, uint64_t conn_id, uint64_t *stream_id, uint64_t now_us);
int qpf_connection_accept_bidi(qpf_engine_t *engine, uint64_t conn_id, uint64_t *stream_id, uint64_t now_us);
int qpf_connection_open_uni(qpf_engine_t *engine, uint64_t conn_id, uint64_t *stream_id, uint64_t now_us);
int qpf_connection_accept_uni(qpf_engine_t *engine, uint64_t conn_id, uint64_t *stream_id, uint64_t now_us);
int qpf_stream_send(qpf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, const uint8_t *data, size_t len, size_t *written, uint64_t now_us);
int qpf_stream_recv(qpf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, uint8_t *data, size_t capacity, size_t *read, bool *fin, uint64_t now_us);
int qpf_stream_finish(qpf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, uint64_t now_us);
int qpf_stream_reset(qpf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, uint64_t application_error, uint64_t now_us);
int qpf_stream_stop_sending(qpf_engine_t *engine, uint64_t conn_id, uint64_t stream_id, uint64_t application_error, uint64_t now_us);
int qpf_datagram_send(qpf_engine_t *engine, uint64_t conn_id, const uint8_t *data, size_t len, uint64_t now_us);
int qpf_datagram_recv(qpf_engine_t *engine, uint64_t conn_id, uint8_t *data, size_t capacity, size_t *read, uint64_t now_us);
int qpf_connection_close(qpf_engine_t *engine, uint64_t conn_id, uint64_t application_error, uint64_t now_us);

const char *qpf_last_error(void);

#ifdef __cplusplus
}
#endif
