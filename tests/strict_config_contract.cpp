#include "core/strict_config.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <iostream>
#include <string>

int main()
{
  std::string valid =
      R"({"ack_delay_exponent":3,"ack_frequency":false,"active_connection_id_limit":2,"active_migration":false,"active_streams_per_connection":1,"alpn":"qperf/2","backend":"syscall","bind_address":"127.0.0.1","bind_port":0,"bulk_chunk_bytes":262144,"busy_polling":false,"certificate_path":"cert.pem","chain_path":"chain.pem","common_pacing":true,"congestion_controller":"cubic","connection_count":16,"connection_id_bytes":8,"connection_window":262144,"datagram_body_bytes":0,"datagram_max_frame_size":1200,"datagram_max_unreturned_per_connection":0,"ecn":false,"event_loop_workers":1,"global_operation_slots":0,"idle_timeout_ms":30000,"initial_congestion_window_bytes":13500,"max_ack_delay_ns":25000000,"max_bidi_streams":256,"max_udp_payload_size":1350,"max_uni_streams":256,"measurement_duration_ns":2000000000,"operation_body_bytes":0,"path_profile":"loopback","peer_address":"0.0.0.0","peer_port":0,"pmtud":false,"private_key_path":"key.pem","progress_interval_ns":200000000,"quic_version":"0x00000001","receive_timestamps":false,"request_body_bytes":8,"require_multishot_receive":false,"response_body_bytes":0,"role":"server","scenario":"download","schema_version":2,"stream_credit_replenish_below":32,"stream_window":65536,"ticket_slots":0,"tls_cipher_suite":"TLS_AES_128_GCM_SHA256","tls_hostname":"server.quicperf.test","tls_key_exchange":"X25519","tls_leaf_signature":"Ed25519","tls_maximum_early_data_bytes":4096,"tls_one_use_tickets":true,"tls_ticket_lifetime_ns":300000000000,"tls_verify_peer":false,"tls_version":"TLSv1.3","trace_seed":"0000000000000000000000000000000000000000000000000000000000000000","udp_gro":true,"udp_gso":true,"warmup_duration_ns":250000000})";
  valid.insert(valid.find("\"certificate_path\""),
               "\"calendar_unix_seconds\":1784376000,");
  const auto parsed = quicperf::parseEndpointConfig(valid);
  if (!parsed) std::cerr << parsed.error << '\n';
  assert(parsed);
  assert(parsed.config.backend == quicperf::PacketBackend::syscall);
  assert(parsed.config.role == quicperf::EndpointRole::server);
  assert(parsed.config.maxUdpPayloadSize == quicperf::maxUdpPayloadSize);
  assert(parsed.config.packetIo.udpGso && parsed.config.packetIo.udpGro);

  std::string streamChurn = valid;
  streamChurn.replace(streamChurn.find("\"bulk_chunk_bytes\":262144"),
                      std::string("\"bulk_chunk_bytes\":262144").size(),
                      "\"bulk_chunk_bytes\":0");
  streamChurn.replace(streamChurn.find("\"global_operation_slots\":0"),
                      std::string("\"global_operation_slots\":0").size(),
                      "\"global_operation_slots\":16");
  streamChurn.replace(streamChurn.find("\"operation_body_bytes\":0"),
                      std::string("\"operation_body_bytes\":0").size(),
                      "\"operation_body_bytes\":1");
  streamChurn.replace(streamChurn.find("\"request_body_bytes\":8"),
                      std::string("\"request_body_bytes\":8").size(),
                      "\"request_body_bytes\":0");
  streamChurn.replace(streamChurn.find("\"scenario\":\"download\""),
                      std::string("\"scenario\":\"download\"").size(),
                      "\"scenario\":\"stream_churn\"");
  const auto churn = quicperf::parseEndpointConfig(streamChurn);
  if (!churn) std::cerr << churn.error << '\n';
  assert(churn && churn.config.warmupDurationNs == 250'000'000);

  std::string unknown = valid;
  unknown.insert(unknown.size() - 1, R"(,"unknown":true)");
  assert(!quicperf::parseEndpointConfig(unknown));

  std::string reordered = valid;
  const auto first = reordered.find(R"("backend")");
  reordered.replace(first, 9, R"("zbackend")");
  assert(!quicperf::parseEndpointConfig(reordered));

  std::string wrongPayload = valid;
  wrongPayload.replace(wrongPayload.find("1350"), 4, "1400");
  assert(!quicperf::parseEndpointConfig(wrongPayload));

  std::string mismatchedScenario = valid;
  mismatchedScenario.replace(mismatchedScenario.find("download"), 8, "datagram");
  assert(!quicperf::parseEndpointConfig(mismatchedScenario));

  std::string wrongWorkerCount = valid;
  const auto worker = wrongWorkerCount.find("\"event_loop_workers\":1");
  wrongWorkerCount.replace(worker, std::string("\"event_loop_workers\":1").size(), "\"event_loop_workers\":2");
  assert(!quicperf::parseEndpointConfig(wrongWorkerCount));

  std::string fourWorkerClient = valid;
  fourWorkerClient.replace(fourWorkerClient.find("\"event_loop_workers\":1"),
                           std::string("\"event_loop_workers\":1").size(),
                           "\"event_loop_workers\":4");
  fourWorkerClient.replace(fourWorkerClient.find("\"peer_address\":\"0.0.0.0\""),
                           std::string("\"peer_address\":\"0.0.0.0\"").size(),
                           "\"peer_address\":\"127.0.0.1\"");
  fourWorkerClient.replace(fourWorkerClient.find("\"peer_port\":0"),
                           std::string("\"peer_port\":0").size(), "\"peer_port\":4433");
  fourWorkerClient.replace(fourWorkerClient.find("\"role\":\"server\""),
                           std::string("\"role\":\"server\"").size(),
                           "\"role\":\"client\"");
  const auto fourWorkers = quicperf::parseEndpointConfig(fourWorkerClient);
  assert(fourWorkers && fourWorkers.config.eventLoopWorkers == 4);
}
