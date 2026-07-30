#include "quicperf_rust_packet_ffi.h"
#include "quicperf_zig_packet_ffi.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <type_traits>

static_assert(QPF_PACKET_ABI_VERSION == 8 && QZF_PACKET_ABI_VERSION == 6);
static_assert(QPF_PACKET_BATCH_CAPACITY == 64 && QZF_PACKET_BATCH_CAPACITY == 64);
static_assert(std::is_standard_layout_v<qpf_receive_descriptor_v2_t>);
static_assert(std::is_standard_layout_v<qpf_transmit_descriptor_v2_t>);
static_assert(std::is_standard_layout_v<qpf_transport_counters_v3_t>);
static_assert(sizeof(qpf_transport_counters_v3_t) == 5 * sizeof(uint64_t));
static_assert(std::is_standard_layout_v<qpf_peer_terminal_facts_v6_t>);
static_assert(sizeof(qpf_peer_terminal_facts_v6_t) == 40);
static_assert(std::is_standard_layout_v<qpf_negotiated_settings_v7_t>);
static_assert(sizeof(qpf_negotiated_settings_v7_t) == 152);
static_assert(std::is_standard_layout_v<qzf_transport_counters_v3_t>);
static_assert(sizeof(qzf_transport_counters_v3_t) == 5 * sizeof(uint64_t));
static_assert(std::is_standard_layout_v<qzf_peer_terminal_facts_v6_t>);
static_assert(sizeof(qzf_peer_terminal_facts_v6_t) == 40);
static_assert(std::is_standard_layout_v<qzf_receive_descriptor_v2_t>);
static_assert(std::is_standard_layout_v<qzf_transmit_descriptor_v2_t>);
static_assert(sizeof(qpf_receive_descriptor_v2_t) == sizeof(qzf_receive_descriptor_v2_t));
static_assert(sizeof(qpf_transmit_descriptor_v2_t) == sizeof(qzf_transmit_descriptor_v2_t));
static_assert(offsetof(qpf_transmit_descriptor_v2_t, desired_send_raw_ns) ==
              offsetof(qzf_transmit_descriptor_v2_t, desired_send_raw_ns));

int main()
{
  assert(qpf_packet_abi_version() == QPF_PACKET_ABI_VERSION);
  qpf_adapter_status_v2_t status {};
  assert(qpf_engine_receive_batch(nullptr, nullptr, 0, 1, &status) < 0);
  assert(status.code < 0 && status.message[0] != '\0');

  const auto countEntries = [](const char* path) {
    size_t count = 0;
    for ([[maybe_unused]] const auto& entry : std::filesystem::directory_iterator(path)) ++count;
    return count;
  };
  const auto countNetworkOrEventFds = [] {
    size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd"))
    {
      std::error_code error;
      const std::string target = std::filesystem::read_symlink(entry.path(), error).string();
      if (!error && (target.starts_with("socket:[") || target == "anon_inode:[eventpoll]" ||
                     target == "anon_inode:[io_uring]" || target == "anon_inode:[timerfd]")) ++count;
    }
    return count;
  };
  const size_t baseNetworkOrEventFds = countNetworkOrEventFds();
  const size_t baseThreads = countEntries("/proc/self/task");
  const std::string tls = QUICPERF_SOURCE_DIR "/tls/";
  const std::string rustCert = tls + "server.cert.pem";
  const std::string rustKey = tls + "server.key.pem";
  const std::string rustChain = tls + "chain.cert.pem";
  const std::string hostname = "server.quicperf.test";
  for (const uint32_t library : {QPF_LIBRARY_QUINN, QPF_LIBRARY_NOQ, QPF_LIBRARY_NEQO, QPF_LIBRARY_S2N})
  {
    qpf_config_t config {};
    config.library = library;
    config.is_server = true;
    config.local_addr.ip[10] = 0xff;
    config.local_addr.ip[11] = 0xff;
    config.local_addr.ip[15] = 1;
    config.cert_path = rustCert.c_str();
    config.key_path = rustKey.c_str();
    config.chain_path = rustChain.c_str();
    config.tls_hostname = hostname.c_str();
    config.initial_congestion_window_bytes = 13'500;
    config.max_ack_delay_ns = 25'000'000;
    config.ack_delay_exponent = 3;
    config.active_connection_id_limit = 2;
    config.connection_id_bytes = 8;
    config.connection_window = 262144;
    config.stream_window = 65536;
    config.stream_credit_replenish_below = 32;
    config.max_bidi_streams = 64;
    config.max_uni_streams = 64;
    config.idle_timeout_ms = 30000;
    config.udp_payload_size = 1350;
    config.datagram_max_frame_size = 1200;
    config.datagram_max_unreturned_per_connection = 128;
    config.ticket_lifetime_ns = 300'000'000'000;
    config.maximum_early_data_bytes = 4'096;
    config.one_use_tickets = true;
    config.now_us = 1;
    config.calendar_unix_seconds = 1'784'376'000;
    qpf_engine_t* engine = qpf_engine_new(&config);
    assert(engine != nullptr);
    size_t count = 7;
    status = {};
    assert(qpf_engine_receive_batch(engine, nullptr, 0, 1'000, &status) == 0);
    assert(qpf_engine_poll_transmit_batch(engine, nullptr, 0, &count, 1'000, &status) == 0);
    assert(count == 0);
    uint64_t deadline = 0;
    assert(qpf_engine_next_timeout_raw_ns(engine, 1'000, &deadline, &status) == 0);
    qpf_transport_counters_v3_t counters {};
    assert(qpf_engine_transport_counters_v3(engine, &counters, &status) == 0);
    assert(counters.packets_lost == 0);
    assert(counters.packets_retransmitted == 0);
    assert(counters.recovery_wakeups == 0);
    assert(counters.flow_control_blocked_events == 0);
    assert(counters.stream_credit_blocked_events == 0);
    qpf_peer_terminal_facts_v6_t facts {};
    const int terminalStatus = qpf_peer_terminal_facts_v6(engine, 999, 0, &facts, 1);
    assert(terminalStatus < 0 && !facts.available);
    qpf_engine_free(engine);
    assert(countNetworkOrEventFds() == baseNetworkOrEventFds);
    assert(countEntries("/proc/self/task") == baseThreads);
  }

  qzf_config_t zig {};
  zig.is_server = true;
  zig.local_addr.ip[10] = 0xff;
  zig.local_addr.ip[11] = 0xff;
  zig.local_addr.ip[15] = 1;
  const std::string zigCert = tls + "server.cert.pem";
  const std::string zigKey = tls + "server.key.pem";
  const std::string zigChain = tls + "chain.cert.pem";
  zig.cert_path = zigCert.c_str();
  zig.key_path = zigKey.c_str();
  zig.chain_path = zigChain.c_str();
  zig.connection_window = 262144;
  zig.stream_window = 65536;
  zig.max_bidi_streams = 64;
  zig.max_uni_streams = 64;
  zig.idle_timeout_ms = 30000;
  zig.udp_payload_size = 1350;
  zig.datagram_max_frame_size = 1200;
  zig.send_backlog_limit = 4096;
  zig.now_us = 1;
  zig.calendar_unix_seconds = 1'700'000'000ULL;
  qzf_engine_t* zigEngine = qzf_engine_new(&zig);
  assert(zigEngine != nullptr);
  qzf_adapter_status_v2_t zigStatus {};
  assert(qzf_engine_receive_batch(zigEngine, nullptr, 0, 1'000, &zigStatus) == 0);
  size_t zigCount = 7;
  assert(qzf_engine_poll_transmit_batch(zigEngine, nullptr, 0, &zigCount, 1'000, &zigStatus) == 0);
  assert(zigCount == 0);
  qzf_transport_counters_v3_t zigCounters {};
  assert(qzf_engine_transport_counters_v3(zigEngine, &zigCounters, &zigStatus) == 0);
  assert(zigCounters.packets_lost == 0);
  assert(zigCounters.packets_retransmitted == 0);
  assert(zigCounters.recovery_wakeups == 0);
  assert(zigCounters.flow_control_blocked_events == 0);
  assert(zigCounters.stream_credit_blocked_events == 0);
  qzf_engine_free(zigEngine);
  assert(countNetworkOrEventFds() == baseNetworkOrEventFds);
  assert(countEntries("/proc/self/task") == baseThreads);
  return 0;
}
