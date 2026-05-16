#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <netinet/in.h>
#include <sys/socket.h>

enum class BenchmarkScenario : uint8_t {
	download,
	upload,
	connect,
	reqresp,
	stream_churn,
	multistream_download,
	multistream_upload,
	bidi,
	small_payload_pps,
	loss_recovery,
	flow_control,
	resumed_connect,
	zero_rtt_reqresp,
	datagram,
	idle_footprint,
	close_reset_cleanup
};

static inline BenchmarkScenario benchmarkScenario = BenchmarkScenario::download;
static inline const char *benchmarkScenarioProfile = "default";

static constexpr const char *benchmarkScenarioName(BenchmarkScenario scenario)
{
	switch (scenario)
	{
		case BenchmarkScenario::download: return "download";
		case BenchmarkScenario::upload: return "upload";
		case BenchmarkScenario::connect: return "connect";
		case BenchmarkScenario::reqresp: return "reqresp";
		case BenchmarkScenario::stream_churn: return "stream_churn";
		case BenchmarkScenario::multistream_download: return "multistream_download";
		case BenchmarkScenario::multistream_upload: return "multistream_upload";
		case BenchmarkScenario::bidi: return "bidi";
		case BenchmarkScenario::small_payload_pps: return "small_payload_pps";
		case BenchmarkScenario::loss_recovery: return "loss_recovery";
		case BenchmarkScenario::flow_control: return "flow_control";
		case BenchmarkScenario::resumed_connect: return "resumed_connect";
		case BenchmarkScenario::zero_rtt_reqresp: return "zero_rtt_reqresp";
		case BenchmarkScenario::datagram: return "datagram";
		case BenchmarkScenario::idle_footprint: return "idle_footprint";
		case BenchmarkScenario::close_reset_cleanup: return "close_reset_cleanup";
	}
	return "unknown";
}

static constexpr const char *benchmarkScenarioMetricName(BenchmarkScenario scenario)
{
	switch (scenario)
	{
		case BenchmarkScenario::connect:
		case BenchmarkScenario::resumed_connect:
			return "connections_per_second";
		case BenchmarkScenario::reqresp:
		case BenchmarkScenario::zero_rtt_reqresp:
			return "requests_per_second";
		case BenchmarkScenario::stream_churn:
		case BenchmarkScenario::close_reset_cleanup:
			return "streams_per_second";
		case BenchmarkScenario::small_payload_pps:
		case BenchmarkScenario::datagram:
			return "messages_per_second";
		case BenchmarkScenario::idle_footprint:
			return "server_rss_delta_bytes_per_connection";
		case BenchmarkScenario::download:
		case BenchmarkScenario::upload:
		case BenchmarkScenario::multistream_download:
		case BenchmarkScenario::multistream_upload:
		case BenchmarkScenario::bidi:
		case BenchmarkScenario::loss_recovery:
		case BenchmarkScenario::flow_control:
			return "throughput_gbps";
	}
	return "unknown";
}

static constexpr bool benchmarkScenarioUsesSharedTransfer(BenchmarkScenario scenario)
{
	switch (scenario)
	{
		case BenchmarkScenario::download:
		case BenchmarkScenario::upload:
		case BenchmarkScenario::connect:
		case BenchmarkScenario::loss_recovery:
		case BenchmarkScenario::flow_control:
			return true;
		default:
			return false;
	}
}

static inline const char *benchmarkScenarioUnsupportedReason(BenchmarkScenario scenario)
{
	switch (scenario)
	{
		case BenchmarkScenario::reqresp:
		case BenchmarkScenario::stream_churn:
			return "requires_repeated_bidi_stream_lifecycle_adapter_api";
		case BenchmarkScenario::multistream_download:
		case BenchmarkScenario::multistream_upload:
			return "requires_concurrent_multistream_adapter_api";
		case BenchmarkScenario::bidi:
			return "requires_simultaneous_bidirectional_transfer_adapter_api";
		case BenchmarkScenario::small_payload_pps:
			return "requires_message_loop_latency_and_pps_adapter_api";
		case BenchmarkScenario::resumed_connect:
		case BenchmarkScenario::zero_rtt_reqresp:
			return "requires_session_ticket_resumption_and_0rtt_adapter_api";
		case BenchmarkScenario::datagram:
			return "requires_quic_datagram_adapter_api";
		case BenchmarkScenario::idle_footprint:
			return "requires_idle_connection_retention_and_resource_sampling_api";
		case BenchmarkScenario::close_reset_cleanup:
			return "requires_stream_reset_stop_sending_and_connection_close_adapter_api";
		default:
			return "supported";
	}
}

static inline bool benchmarkIsUpload(void)
{
	return benchmarkScenario == BenchmarkScenario::upload ||
		benchmarkScenario == BenchmarkScenario::multistream_upload;
}

static inline bool benchmarkIsConnect(void)
{
	return benchmarkScenario == BenchmarkScenario::connect;
}

static inline bool benchmarkIsLossRecovery(void)
{
	return benchmarkScenario == BenchmarkScenario::loss_recovery;
}

static inline bool benchmarkIsFlowControl(void)
{
	return benchmarkScenario == BenchmarkScenario::flow_control;
}

static inline bool benchmarkIsIdleFootprint(void)
{
	return benchmarkScenario == BenchmarkScenario::idle_footprint;
}

static constexpr bool benchmarkScenarioIsGenericStreamWorkload(BenchmarkScenario scenario)
{
	switch (scenario)
	{
		case BenchmarkScenario::reqresp:
		case BenchmarkScenario::stream_churn:
		case BenchmarkScenario::multistream_download:
		case BenchmarkScenario::multistream_upload:
		case BenchmarkScenario::bidi:
		case BenchmarkScenario::small_payload_pps:
		case BenchmarkScenario::close_reset_cleanup:
			return true;
		default:
			return false;
	}
}

static constexpr bool benchmarkScenarioIsSmallGenericStreamWorkload(BenchmarkScenario scenario)
{
	switch (scenario)
	{
		case BenchmarkScenario::reqresp:
		case BenchmarkScenario::stream_churn:
		case BenchmarkScenario::small_payload_pps:
		case BenchmarkScenario::close_reset_cleanup:
			return true;
		default:
			return false;
	}
}

static constexpr bool benchmarkScenarioOpensOwnStreams(BenchmarkScenario scenario)
{
	return benchmarkScenarioIsGenericStreamWorkload(scenario) ||
		scenario == BenchmarkScenario::datagram ||
		scenario == BenchmarkScenario::idle_footprint;
}

static inline bool benchmarkScenarioCloseCleanupProfileSupported(void)
{
	return strcmp(benchmarkScenarioProfile, "graceful_fin_cleanup") == 0;
}

static constexpr bool benchmarkScenarioDatagramSupportedByAdapter(void)
{
#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF) || defined(QUICZIGPERF) || defined(QUICHEPERF)
	return true;
#else
	return false;
#endif
}

static constexpr bool benchmarkScenarioIdleFootprintSupportedByAdapter(void)
{
	return true;
}

static inline bool benchmarkScenarioSupportedByAdapter(BenchmarkScenario scenario)
{
	if (benchmarkScenarioUsesSharedTransfer(scenario))
	{
		return true;
	}
	if (scenario == BenchmarkScenario::datagram)
	{
		return benchmarkScenarioDatagramSupportedByAdapter();
	}
	if (scenario == BenchmarkScenario::idle_footprint)
	{
		return benchmarkScenarioIdleFootprintSupportedByAdapter();
	}
	if (scenario == BenchmarkScenario::close_reset_cleanup)
	{
		return benchmarkScenarioCloseCleanupProfileSupported();
	}
#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF) || defined(QUICZIGPERF) || defined(LSPERF) || defined(QUICHEPERF) || defined(TQUICPERF) || defined(XQUICPERF) || defined(NGTCP2PERF) || defined(PICOPERF) || defined(MVFSTPERF)
	if (benchmarkScenarioIsGenericStreamWorkload(scenario))
	{
		return true;
	}
#endif
	return false;
}

static constexpr uint64_t benchmarkDefaultConnectionWindow = 64ULL * 1024ULL * 1024ULL;
static constexpr uint64_t benchmarkFlowControlConnectionWindow = 256ULL * 1024ULL;
static constexpr uint64_t benchmarkLargeConnectionWindow = 256ULL * 1024ULL * 1024ULL;
static inline uint64_t benchmarkConnectionWindow = benchmarkDefaultConnectionWindow;
static constexpr uint64_t benchmarkConnectCleanupBytes = 1;
static constexpr uint64_t benchmarkDefaultStreamWindow = 64ULL * 1024ULL * 1024ULL;
static constexpr uint64_t benchmarkFlowControlStreamWindow = 64ULL * 1024ULL;
static constexpr uint64_t benchmarkLargeStreamWindow = 256ULL * 1024ULL * 1024ULL;
static inline uint64_t benchmarkStreamWindow = benchmarkDefaultStreamWindow;
static constexpr uint64_t benchmarkDefaultMaxBidiStreams = 1;
static inline uint64_t benchmarkMaxBidiStreams = benchmarkDefaultMaxBidiStreams;
static constexpr uint64_t benchmarkMaxUniStreams = 0;
static constexpr uint64_t benchmarkIdleTimeoutMs = 300'000;
static constexpr uint64_t benchmarkIdleTimeoutSeconds = benchmarkIdleTimeoutMs / 1000;
static constexpr uint64_t benchmarkMaxAckDelayMs = 25;
static constexpr uint64_t benchmarkMaxAckDelayUs = benchmarkMaxAckDelayMs * 1000;
static constexpr uint64_t benchmarkAckDelayExponent = 3;
static constexpr uint32_t benchmarkUdpPayloadSize = 1500 - 40 - 8;
static constexpr uint32_t benchmarkUdpBatchSize = 150;
static constexpr uint32_t benchmarkAppChunkSize = 256 * 1024;
static constexpr uint32_t benchmarkTcpTlsBufferSize = benchmarkAppChunkSize;
static inline const char *benchmarkBuildProfile = "native-lto";
static inline const char *benchmarkWindowProfile = "default";
static inline const char *benchmarkCongestionProfile = "default-bbr";
static inline const char *benchmarkNetworkProfile = "default";
static inline const char *benchmarkTlsVerifyMode = "disabled";
static inline const char *benchmarkTlsCertProfile = "ed25519";
static inline uint32_t benchmarkServerTargetConnections = 1;
static inline uint64_t benchmarkLossDropEveryPackets = 0;
static inline uint64_t benchmarkLossWarmupPackets = 128;
static inline uint64_t benchmarkScenarioOperations = 0;
static inline uint32_t benchmarkScenarioStreamsInFlight = 8;
static inline uint32_t benchmarkScenarioRequestBytes = 64;
static inline uint32_t benchmarkScenarioResponseBytes = 1024;
static inline uint32_t benchmarkScenarioMessageBytes = 64;
static inline uint64_t benchmarkIdleHoldMs = 1000;
static constexpr uint32_t benchmarkAggressiveInitialCwndPackets = 32;
static constexpr uint32_t benchmarkAggressiveAckFrequencyPackets = 10;
static inline std::atomic<int> benchmarkSocketSndbufEffective{-1};
static inline std::atomic<int> benchmarkSocketRcvbufEffective{-1};

static inline bool benchmarkCongestionProfileIsAggressive(void)
{
	return strcmp(benchmarkCongestionProfile, "aggressive") == 0;
}

static inline uint32_t benchmarkAdapterInitialCwndPackets(void)
{
#if defined(TQUICPERF) || defined(XQUICPERF) || defined(MVFSTPERF)
	return benchmarkCongestionProfileIsAggressive() ? benchmarkAggressiveInitialCwndPackets : 0;
#else
	return 0;
#endif
}

static inline uint32_t benchmarkAdapterAckFrequencyPackets(void)
{
#if defined(XQUICPERF)
	return benchmarkCongestionProfileIsAggressive() ? benchmarkAggressiveAckFrequencyPackets : 0;
#else
	return 0;
#endif
}

static inline bool benchmarkTlsVerifyPeer(void)
{
	return strcmp(benchmarkTlsVerifyMode, "peer") == 0 || strcmp(benchmarkTlsVerifyMode, "chain") == 0;
}

static inline uint64_t benchmarkGenericReqRespRequestBytes(void)
{
	if (benchmarkScenario == BenchmarkScenario::stream_churn)
	{
		return 1;
	}
	if (benchmarkScenario == BenchmarkScenario::close_reset_cleanup)
	{
		return 1;
	}
	if (benchmarkScenario == BenchmarkScenario::small_payload_pps)
	{
		return benchmarkScenarioMessageBytes;
	}
	return benchmarkScenarioRequestBytes;
}

static inline uint64_t benchmarkGenericReqRespResponseBytes(void)
{
	if (benchmarkScenario == BenchmarkScenario::stream_churn)
	{
		return 1;
	}
	if (benchmarkScenario == BenchmarkScenario::close_reset_cleanup)
	{
		return 1;
	}
	if (benchmarkScenario == BenchmarkScenario::small_payload_pps)
	{
		return benchmarkScenarioMessageBytes;
	}
	return benchmarkScenarioResponseBytes;
}

static inline uint64_t benchmarkGenericStreamsPerConnection(void)
{
	switch (benchmarkScenario)
	{
		case BenchmarkScenario::reqresp:
		case BenchmarkScenario::stream_churn:
		case BenchmarkScenario::small_payload_pps:
		case BenchmarkScenario::close_reset_cleanup:
			return benchmarkScenarioOperations;
		case BenchmarkScenario::multistream_download:
		case BenchmarkScenario::multistream_upload:
			return std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
		default:
			return 1;
	}
}

static inline uint64_t benchmarkScenarioUnitsPerThread(uint64_t testBytes)
{
	switch (benchmarkScenario)
	{
		case BenchmarkScenario::connect:
		case BenchmarkScenario::resumed_connect:
			return 1;
		case BenchmarkScenario::reqresp:
			return benchmarkScenarioOperations;
		case BenchmarkScenario::stream_churn:
			return benchmarkScenarioOperations;
		case BenchmarkScenario::small_payload_pps:
			return benchmarkScenarioOperations;
		case BenchmarkScenario::datagram:
			return benchmarkScenarioOperations;
		case BenchmarkScenario::close_reset_cleanup:
			return benchmarkScenarioOperations;
		case BenchmarkScenario::idle_footprint:
			return 1;
		case BenchmarkScenario::bidi:
			return testBytes * 2;
		default:
			return testBytes;
	}
}

static inline void benchmarkRecordSocketBuffers(int fd)
{
	int value = -1;
	socklen_t valueLen = sizeof(value);
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &valueLen) == 0)
	{
		benchmarkSocketSndbufEffective.store(value, std::memory_order_relaxed);
	}

	value = -1;
	valueLen = sizeof(value);
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &valueLen) == 0)
	{
		benchmarkSocketRcvbufEffective.store(value, std::memory_order_relaxed);
	}
}

static inline std::string benchmarkPeerKey(const struct sockaddr *addr)
{
	const auto *addr6 = reinterpret_cast<const struct sockaddr_in6 *>(addr);
	std::string key(sizeof(addr6->sin6_addr) + sizeof(addr6->sin6_port) + sizeof(addr6->sin6_scope_id), '\0');
	size_t offset = 0;
	memcpy(key.data() + offset, &addr6->sin6_addr, sizeof(addr6->sin6_addr));
	offset += sizeof(addr6->sin6_addr);
	memcpy(key.data() + offset, &addr6->sin6_port, sizeof(addr6->sin6_port));
	offset += sizeof(addr6->sin6_port);
	memcpy(key.data() + offset, &addr6->sin6_scope_id, sizeof(addr6->sin6_scope_id));
	return key;
}
