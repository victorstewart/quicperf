#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_config.h"
#include "picotls.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <unordered_map>
#include <vector>

#pragma once

extern "C" void picoquic_seed_bandwidth(
	picoquic_cnx_t* cnx,
	uint64_t rtt_min,
	uint64_t cwin,
	const uint8_t *ip_addr,
	uint8_t ip_addr_length);

extern "C" void quicperf_picoquic_seed_sender_now(
	picoquic_cnx_t* cnx,
	uint64_t cwin,
	uint64_t pacing_rate,
	uint64_t current_time);

static inline const char *benchmarkPicoquicCongestionAlgorithmName(void)
{
	if (strcmp(benchmarkCongestionProfile, "path-auto") == 0 ||
	    strcmp(benchmarkCongestionProfile, "auto") == 0)
	{
		if (strcmp(benchmarkPathProfile, "dc-fabric-10g") == 0)
		{
			return "cubic";
		}
		if (strcmp(benchmarkPathProfile, "dc-fabric-1ms") == 0 ||
		    strcmp(benchmarkPathProfile, "lte-good") == 0 ||
		    strcmp(benchmarkPathProfile, "5g-sub6-good") == 0 ||
		    strcmp(benchmarkPathProfile, "5g-mmwave-bursty") == 0)
		{
			return "fastcc";
		}
		if (strcmp(benchmarkPathProfile, "lte-congested") == 0)
		{
			return "bbr1";
		}
		return "bbr";
	}
	if (strcmp(benchmarkCongestionProfile, "bbr1") == 0)
	{
		return "bbr1";
	}
	if (strcmp(benchmarkCongestionProfile, "cubic") == 0)
	{
		return "cubic";
	}
	if (strcmp(benchmarkCongestionProfile, "dcubic") == 0)
	{
		return "dcubic";
	}
	if (strcmp(benchmarkCongestionProfile, "newreno") == 0 ||
	    strcmp(benchmarkCongestionProfile, "reno") == 0)
	{
		return "newreno";
	}
	if (strcmp(benchmarkCongestionProfile, "fastcc") == 0)
	{
		return "fastcc";
	}
	if (strcmp(benchmarkCongestionProfile, "prague") == 0)
	{
		return "prague";
	}
	if (strcmp(benchmarkCongestionProfile, "c4") == 0)
	{
		return "c4";
	}
	return "bbr";
}

static inline picoquic_congestion_algorithm_t const *benchmarkPicoquicCongestionAlgorithm(void)
{
	picoquic_register_all_congestion_control_algorithms();
	picoquic_congestion_algorithm_t const *algorithm =
		picoquic_get_congestion_algorithm(benchmarkPicoquicCongestionAlgorithmName());
	if (algorithm == nullptr)
	{
		algorithm = picoquic_get_congestion_algorithm("bbr");
	}
	return algorithm;
}

static inline const char *benchmarkPicoquicAdapterFeatures(void)
{
	static thread_local char features[256];
	snprintf(features, sizeof(features),
		"cc=%s|pmtud=off|packet_train=%s|bdp_frame=%s|bdp_seed=%s|seed_now=%s|mtu=%u|null_verifier=ed25519_sigalgs",
		benchmarkPicoquicCongestionAlgorithmName(),
		benchmarkPicoquicPacketTrainMode ? "on" : "off",
		benchmarkPicoquicBdpFrameMode ? "on" : "off",
		benchmarkPicoquicBdpSeedMode ? "on" : "off",
		benchmarkPicoquicBdpSeedImmediateMode ? "on" : "off",
		static_cast<unsigned>(benchmarkUdpPayloadSize));
	return features;
}

template <Mode mode>
class Picoquic : public QuicLibrary<mode> {
private:

	using QuicLibrary<mode>::networkHub;

		picoquic_quic_t *engine = nullptr;
		picoquic_cnx_t *cnx = nullptr;
		int64_t bytesInFlight = -1;
		std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
		size_t requestBytesRead = 0;
		size_t requestBytesWritten = 0;
		bool requestParsed = false;
			bool ready = false;
			bool clientDone = false;
			bool downloadDoneSignalSent = false;
			bool downloadCompletionAckRead = false;
			bool uploadFinSent = false;
			uint32_t serverCompletedConnections = 0;

			enum class GenericPhase : uint8_t {
				sendRequest,
				readRequest,
				sendPayload,
				readPayload,
				sendResponse,
				readResponse,
				complete
			};

			struct GenericStreamState {
				Picoquic<mode> *owner = nullptr;
				picoquic_cnx_t *cnx = nullptr;
				uint64_t streamId = 0;
				GenericPhase phase = GenericPhase::sendRequest;
				std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
				uint64_t requestValue = 0;
				uint64_t requestBytesExpected = 0;
				uint64_t requestBytesRead = 0;
				uint64_t requestBytesWritten = 0;
				uint64_t payloadRemaining = 0;
				uint64_t responseRemaining = 0;
				size_t doneBytesRead = 0;
				size_t doneBytesWritten = 0;
				size_t ackBytesRead = 0;
				size_t ackBytesWritten = 0;
				bool complete = false;
			};

		static int noVerifyCertificate(
			ptls_verify_certificate_t *self,
			ptls_t *tls,
			const char *serverName,
			int (**verifySign)(void *verifyCtx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign),
			void **verifyData,
			ptls_iovec_t *certs,
			size_t numCerts)
		{
			*verifySign = nullptr;
			*verifyData = nullptr;
			return 0;
		}

		static constexpr uint16_t noVerifySignatureAlgorithms[] = {
			PTLS_SIGNATURE_ED25519,
			PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
			PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
			PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
			PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
			PTLS_SIGNATURE_RSA_PKCS1_SHA256,
			PTLS_SIGNATURE_RSA_PKCS1_SHA1,
			UINT16_MAX,
		};

		static inline ptls_verify_certificate_t noVerifyWithEd25519 = {
			noVerifyCertificate,
			noVerifySignatureAlgorithms,
		};

			struct ServerStreamState {
				Picoquic<mode> *owner = nullptr;
				picoquic_cnx_t *cnx = nullptr;
				uint64_t streamId = 0;
				int64_t bytesInFlight = -1;
				std::array<uint8_t, sizeof(uint64_t)> requestBytes = {};
				size_t requestBytesRead = 0;
				size_t requestBytesWritten = 0;
				bool requestParsed = false;
				bool clientDone = false;
				bool uploadFinSent = false;
				bool completionAckSent = false;
				uint64_t serverDrainDeadlineUs = 0;
				bool complete = false;
			};

				std::vector<std::unique_ptr<ServerStreamState>> serverStreams;
				std::vector<std::unique_ptr<GenericStreamState>> genericStreams;
				std::unordered_map<uint64_t, GenericStreamState *> genericStreamById;
				bool genericStarted = false;
				uint64_t genericClientBytes = 0;
				uint64_t genericRequestedStreams = 0;
				uint64_t genericOpenedStreams = 0;
				uint64_t genericCompletedStreams = 0;
				uint64_t genericServerCompletedStreams = 0;
				uint64_t genericActiveStreams = 0;
				struct DatagramConnState {
					picoquic_cnx_t *cnx = nullptr;
					uint64_t received = 0;
					uint64_t echoed = 0;
					uint64_t pendingEchoes = 0;
					bool clientDone = false;
					bool complete = false;
				};
				std::vector<std::unique_ptr<DatagramConnState>> datagramServerConns;
				uint64_t datagramClientSent = 0;
				uint64_t datagramClientReceived = 0;
				uint64_t datagramClientDrainDeadlineUs = 0;
				bool datagramDoneSignalSent = false;
				bool datagramDoneStreamWritten = false;

		bool perfComplete(void) const
		{
			if constexpr (mode & Mode::server)
			{
					if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
					{
						return genericServerCompletedStreams >=
							static_cast<uint64_t>(benchmarkServerTargetConnections) * benchmarkGenericStreamsPerConnection();
					}
					if (benchmarkScenario == BenchmarkScenario::datagram)
					{
						return serverCompletedConnections >= benchmarkServerTargetConnections;
					}
					return serverCompletedConnections >= benchmarkServerTargetConnections;
				}
				else
				{
					if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
					{
						return genericCompletedStreams >= benchmarkGenericStreamsPerConnection();
					}
					if (benchmarkScenario == BenchmarkScenario::datagram)
					{
						return datagramClientReceived >= benchmarkScenarioOperations &&
							datagramDoneSignalSent &&
							datagramDoneStreamWritten &&
							datagramClientDrainDeadlineUs != 0 &&
							timeNowUs() >= datagramClientDrainDeadlineUs;
					}
					return benchmarkIsUpload()
						? clientDone
						: bytesInFlight == 0;
				}
			}

		ServerStreamState *newServerStreamState(picoquic_cnx_t *activeConnection, uint64_t streamId)
		{
			auto state = std::make_unique<ServerStreamState>();
			state->owner = this;
			state->cnx = activeConnection;
			state->streamId = streamId;
			ServerStreamState *raw = state.get();
			serverStreams.push_back(std::move(state));
			picoquic_set_app_stream_ctx(activeConnection, streamId, raw);
			return raw;
		}

		void markServerStateComplete(ServerStreamState *state)
		{
			if (state == nullptr || state->complete)
			{
				return;
			}
			if (benchmarkIsUpload())
			{
				if (!state->uploadFinSent || state->serverDrainDeadlineUs == 0 || timeNowUs() < state->serverDrainDeadlineUs)
				{
					return;
				}
			}
				else if (!state->requestParsed || state->bytesInFlight != 0 ||
				         !state->clientDone || !state->completionAckSent ||
				         state->serverDrainDeadlineUs == 0 || timeNowUs() < state->serverDrainDeadlineUs)
				{
					return;
				}
			state->complete = true;
			++serverCompletedConnections;
		}

		static uint64_t picoquicBdpSeedCwin(void)
		{
			if (benchmarkPathRttUs == 0 || benchmarkPathMaxRateBps == 0)
			{
				return 0;
			}
			const uint64_t seedRateBps = picoquicBdpSeedRate();
			const uint64_t bdpBytes = ((seedRateBps * benchmarkPathRttUs) + 7'999'999ULL) / 8'000'000ULL;
			return std::clamp<uint64_t>(bdpBytes * 2ULL, 64ULL * 1024ULL, 16ULL * 1024ULL * 1024ULL);
		}

		static uint64_t picoquicBdpSeedRate(void)
		{
			if (strcmp(benchmarkPathProfile, "lte-good") == 0 &&
			    benchmarkPathDownlinkBps != 0)
			{
				return benchmarkPathDownlinkBps;
			}
			return benchmarkPathMaxRateBps;
		}

		static uint64_t picoquicBdpSeedPacingRate(void)
		{
			return picoquicBdpSeedRate() / 8ULL;
		}

		static void seedServerBandwidth(picoquic_cnx_t *activeConnection)
		{
			if constexpr (mode & Mode::server)
			{
				if (!benchmarkPicoquicBdpSeedMode ||
				    strcmp(benchmarkPathProfile, "loopback") == 0)
				{
					return;
				}
				const uint64_t seedCwin = picoquicBdpSeedCwin();
				if (seedCwin != 0)
				{
					picoquic_seed_bandwidth(activeConnection, benchmarkPathRttUs, seedCwin, serverAddress.s6_addr, 16);
					if (benchmarkPicoquicBdpSeedImmediateMode)
					{
						quicperf_picoquic_seed_sender_now(
							activeConnection, seedCwin, picoquicBdpSeedPacingRate(), timeNowUs());
					}
				}
			}
		}

		static void encodeU64(uint64_t value, std::array<uint8_t, sizeof(uint64_t)>& out)
		{
			uint64_t swapped = bswap_64(value);
			memcpy(out.data(), &swapped, out.size());
		}

		static uint64_t decodeU64(const std::array<uint8_t, sizeof(uint64_t)>& in)
		{
			uint64_t value = 0;
			memcpy(&value, in.data(), in.size());
			return bswap_64(value);
		}

		uint64_t genericTransferBytesForStream(uint64_t index) const
		{
			const uint64_t count = std::max<uint64_t>(1, benchmarkGenericStreamsPerConnection());
			const uint64_t base = genericClientBytes / count;
			if (index + 1 == count)
			{
				return genericClientBytes - (base * (count - 1));
			}
			return std::max<uint64_t>(1, base);
		}

		void initializeGenericClientState(GenericStreamState& state, uint64_t streamId)
		{
			state.owner = this;
			state.cnx = cnx;
			state.streamId = streamId;
			state.phase = GenericPhase::sendRequest;
			const uint64_t index = genericOpenedStreams++;
			if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
			{
				state.requestBytesExpected = benchmarkGenericReqRespRequestBytes();
				state.responseRemaining = benchmarkGenericReqRespResponseBytes();
			}
			else
			{
				const uint64_t streamBytes = genericTransferBytesForStream(index);
				state.requestValue = streamBytes;
				encodeU64(streamBytes, state.requestBytes);
				state.requestBytesExpected = state.requestBytes.size();
				state.payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
					benchmarkScenario == BenchmarkScenario::bidi) ? streamBytes : 0;
				state.responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : streamBytes;
			}
		}

		GenericStreamState *newGenericServerStreamState(picoquic_cnx_t *activeConnection, uint64_t streamId)
		{
			auto state = std::make_unique<GenericStreamState>();
			state->owner = this;
			state->cnx = activeConnection;
			state->streamId = streamId;
			state->phase = GenericPhase::readRequest;
			GenericStreamState *raw = state.get();
			genericStreams.push_back(std::move(state));
			picoquic_set_app_stream_ctx(activeConnection, streamId, raw);
			return raw;
		}

			GenericStreamState *genericClientStreamFor(uint64_t streamId)
			{
				auto found = genericStreamById.find(streamId);
				return found == genericStreamById.end() ? nullptr : found->second;
			}

			DatagramConnState *datagramServerStateFor(picoquic_cnx_t *activeConnection)
			{
				for (auto& state : datagramServerConns)
				{
					if (state->cnx == activeConnection)
					{
						return state.get();
					}
				}

				auto state = std::make_unique<DatagramConnState>();
				state->cnx = activeConnection;
				DatagramConnState *raw = state.get();
				datagramServerConns.push_back(std::move(state));
				return raw;
			}

			void markDatagramServerComplete(DatagramConnState *state)
			{
				if (state == nullptr || state->complete)
				{
					return;
				}
				if (state->echoed < benchmarkScenarioOperations || !state->clientDone)
				{
					return;
				}
				state->complete = true;
				++serverCompletedConnections;
			}

			void sendPendingServerDatagrams(void)
			{
				if constexpr (mode & Mode::server)
				{
					const size_t payloadSize = std::min<size_t>(
						benchmarkScenarioMessageBytes, sizeof(networkHub->junk));
					for (auto& owned : datagramServerConns)
					{
						auto *state = owned.get();
						while (state->pendingEchoes > 0)
						{
							int rv = picoquic_queue_datagram_frame(state->cnx, payloadSize, networkHub->junk);
							if (rv != 0)
							{
								break;
							}
							--state->pendingEchoes;
							++state->echoed;
						}
						markDatagramServerComplete(state);
					}
				}
			}

			void sendClientDatagrams(void)
			{
				if constexpr (mode & Mode::client)
				{
					if (benchmarkScenario != BenchmarkScenario::datagram ||
					    cnx == nullptr ||
					    datagramClientReceived >= benchmarkScenarioOperations)
					{
						return;
					}
					const uint64_t maxInFlight = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
					const uint64_t maxAttempts = benchmarkScenarioOperations + maxInFlight;
					if (datagramClientSent >= maxAttempts && datagramClientReceived < benchmarkScenarioOperations)
					{
						fprintf(stderr, "picoquic datagram delivery target not reached received=%" PRIu64 " sent=%" PRIu64 " target=%" PRIu64 "\n",
							datagramClientReceived, datagramClientSent, benchmarkScenarioOperations);
						abort();
					}
					const size_t payloadSize = std::min<size_t>(
						benchmarkScenarioMessageBytes, sizeof(networkHub->junk));
					uint64_t sentThisCall = 0;
					while (sentThisCall < maxInFlight &&
					       datagramClientSent < maxAttempts &&
					       datagramClientSent - datagramClientReceived < maxInFlight)
					{
						int rv = picoquic_queue_datagram_frame(cnx, payloadSize, networkHub->junk);
						if (rv != 0)
						{
							break;
						}
						++datagramClientSent;
						++sentThisCall;
					}
				}
			}

			void sendClientDatagramDoneSignal(void)
			{
				if constexpr (mode & Mode::client)
				{
					if (datagramDoneSignalSent || cnx == nullptr)
					{
						return;
					}
					static const uint8_t done = 0;
					if (picoquic_add_to_stream_with_ctx(cnx, 0, &done, sizeof(done), true, this) == 0)
					{
						datagramDoneSignalSent = true;
						datagramDoneStreamWritten = true;
						datagramClientDrainDeadlineUs = timeNowUs() + 100'000;
					}
				}
			}

		void markGenericClientComplete(GenericStreamState *state)
		{
			if (state == nullptr || state->complete)
			{
				return;
			}
			state->complete = true;
			state->phase = GenericPhase::complete;
			++genericCompletedStreams;
			if (genericActiveStreams > 0)
			{
				--genericActiveStreams;
			}
			openMoreGenericClientStreams();
		}

		void markGenericServerComplete(GenericStreamState *state)
		{
			if (state == nullptr || state->complete)
			{
				return;
			}
			state->complete = true;
			state->phase = GenericPhase::complete;
			++genericServerCompletedStreams;
		}

		void openMoreGenericClientStreams(void)
		{
			if constexpr (mode & Mode::client)
			{
				if (!genericStarted || !benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) || cnx == nullptr)
				{
					return;
				}
				const uint64_t targetStreams = benchmarkGenericStreamsPerConnection();
				const uint64_t maxActive = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
				while (genericRequestedStreams < targetStreams && genericActiveStreams < maxActive)
				{
					const uint64_t streamId = genericRequestedStreams * 4;
					auto state = std::make_unique<GenericStreamState>();
					initializeGenericClientState(*state, streamId);
					GenericStreamState *raw = state.get();
					genericStreams.push_back(std::move(state));
					genericStreamById[streamId] = raw;
					picoquic_set_app_stream_ctx(cnx, streamId, raw);
					picoquic_mark_active_stream(cnx, streamId, true, raw);
					++genericRequestedStreams;
					++genericActiveStreams;
				}
			}
		}

	// static const char* picoeventToString(picoquic_call_back_event_t fin_or_event)
	// {
	// 	switch (fin_or_event)
	// 	{
	// 		case picoquic_callback_stream_data: 			return "picoquic_callback_stream_data";
	// 		case picoquic_callback_stream_fin:  			return "picoquic_callback_stream_fin";
	// 		case picoquic_callback_stream_reset:  			return "picoquic_callback_stream_reset";
	// 		case picoquic_callback_stop_sending:  			return "picoquic_callback_stop_sending";
	// 		case picoquic_callback_stateless_reset:  		return "picoquic_callback_stateless_reset";
	// 		case picoquic_callback_close:  					return "picoquic_callback_close";
	// 		case picoquic_callback_application_close:  	return "picoquic_callback_application_close";
	// 		case picoquic_callback_stream_gap:  			return "picoquic_callback_stream_gap";
	// 		case picoquic_callback_prepare_to_send:  		return "picoquic_callback_prepare_to_send";
	// 		case picoquic_callback_almost_ready:  			return "picoquic_callback_almost_ready";
	// 		case picoquic_callback_ready:  					return "picoquic_callback_ready";
	// 		case picoquic_callback_datagram:  				return "picoquic_callback_datagram";
	// 		case picoquic_callback_version_negotiation:  return "picoquic_callback_version_negotiation";
	// 		case picoquic_callback_request_alpn_list:  	return "picoquic_callback_request_alpn_list";
	// 		case picoquic_callback_set_alpn:  				return "picoquic_callback_set_alpn";
	// 		case picoquic_callback_pacing_changed:  		return "picoquic_callback_pacing_changed";
	// 		default: break;
	// 	}

	// 	printf("got bad picoevent value = %d\n", fin_or_event);
	// 	return "";
	// }

	static int datain(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes, size_t length, picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *stream_ctx)
	{
		//printf("datain -> %s\n", picoeventToString(fin_or_event));

				Picoquic<mode> *instance = (Picoquic<mode> *)callback_ctx;
				ServerStreamState *serverState = nullptr;
				if constexpr (mode & Mode::server)
				{
					if (!benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
					{
						serverState = (ServerStreamState *)stream_ctx;
						if (serverState == nullptr)
						{
							serverState = instance->newServerStreamState(cnx, stream_id);
						}
					}
				}
				GenericStreamState *genericState = nullptr;
				if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
				{
					if constexpr (mode & Mode::server)
					{
						genericState = (GenericStreamState *)stream_ctx;
						if (genericState == nullptr)
						{
							genericState = instance->newGenericServerStreamState(cnx, stream_id);
						}
					}
					else
					{
						genericState = (GenericStreamState *)stream_ctx;
						if (genericState == nullptr)
						{
							genericState = instance->genericClientStreamFor(stream_id);
							if (genericState != nullptr)
							{
								picoquic_set_app_stream_ctx(cnx, stream_id, genericState);
							}
						}
					}
				}
					switch (fin_or_event)
			{
			// Data received from peer on stream N
				case picoquic_callback_stream_data:
				// Fin received from peer on stream N; data is optional
				case picoquic_callback_stream_fin:
				{
					if (benchmarkScenario == BenchmarkScenario::datagram)
					{
						if constexpr (mode & Mode::server)
						{
							if (fin_or_event == picoquic_callback_stream_fin)
							{
								auto *datagramState = instance->datagramServerStateFor(cnx);
								datagramState->clientDone = true;
								instance->markDatagramServerComplete(datagramState);
							}
						}
						break;
					}
					if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) && genericState != nullptr)
					{
					size_t consumed = 0;
					if constexpr (mode & Mode::client)
					{
						if (genericState->responseRemaining > 0)
						{
							const uint64_t copied = std::min<uint64_t>(genericState->responseRemaining, length);
							genericState->responseRemaining -= copied;
							consumed += static_cast<size_t>(copied);
							if (genericState->responseRemaining == 0)
							{
								genericState->phase = GenericPhase::sendPayload;
								picoquic_mark_active_stream(cnx, stream_id, true, genericState);
							}
						}
						if (genericState->doneBytesWritten > 0 && genericState->ackBytesRead < 1 && consumed < length)
						{
							const size_t copied = std::min<size_t>(1 - genericState->ackBytesRead, length - consumed);
							genericState->ackBytesRead += copied;
						}
						if (genericState->ackBytesRead >= 1)
						{
							instance->markGenericClientComplete(genericState);
						}
					}
					else
					{
						if (genericState->phase == GenericPhase::readRequest)
						{
								if (benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario))
							{
								if (genericState->requestBytesExpected == 0)
								{
									genericState->requestBytesExpected = benchmarkGenericReqRespRequestBytes();
								}
								const uint64_t copied = std::min<uint64_t>(
									genericState->requestBytesExpected - genericState->requestBytesRead, length);
								genericState->requestBytesRead += copied;
								consumed += static_cast<size_t>(copied);
								if (genericState->requestBytesRead == genericState->requestBytesExpected)
								{
									genericState->responseRemaining = benchmarkGenericReqRespResponseBytes();
									genericState->phase = GenericPhase::sendResponse;
									picoquic_mark_active_stream(cnx, stream_id, true, genericState);
								}
							}
							else
							{
								while (genericState->requestBytesRead < genericState->requestBytes.size() && consumed < length)
								{
									genericState->requestBytes[genericState->requestBytesRead++] = bytes[consumed++];
								}
								if (genericState->requestBytesRead == genericState->requestBytes.size())
								{
									genericState->requestValue = decodeU64(genericState->requestBytes);
									genericState->payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
										benchmarkScenario == BenchmarkScenario::bidi) ? genericState->requestValue : 0;
									genericState->responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : genericState->requestValue;
									genericState->phase = genericState->payloadRemaining > 0 ? GenericPhase::readPayload : GenericPhase::sendResponse;
									if (genericState->phase == GenericPhase::sendResponse)
									{
										picoquic_mark_active_stream(cnx, stream_id, true, genericState);
									}
								}
							}
						}
						if ((benchmarkScenario == BenchmarkScenario::multistream_upload ||
						     benchmarkScenario == BenchmarkScenario::bidi) &&
						    consumed < length && genericState->payloadRemaining > 0)
						{
							const uint64_t copied = std::min<uint64_t>(genericState->payloadRemaining, length - consumed);
							genericState->payloadRemaining -= copied;
							consumed += static_cast<size_t>(copied);
							if (genericState->payloadRemaining == 0)
							{
								genericState->phase = GenericPhase::sendResponse;
								picoquic_mark_active_stream(cnx, stream_id, true, genericState);
							}
						}
						if (genericState->phase == GenericPhase::readResponse && consumed < length)
						{
							const size_t copied = std::min<size_t>(1 - genericState->doneBytesRead, length - consumed);
							genericState->doneBytesRead += copied;
							if (genericState->doneBytesRead >= 1)
							{
								picoquic_mark_active_stream(cnx, stream_id, true, genericState);
							}
						}
					}
					break;
				}
				if constexpr (mode & Mode::client)
				{
					if (benchmarkIsUpload())
					{
						instance->bytesInFlight -= length;
						if (fin_or_event == picoquic_callback_stream_fin)
						{
							instance->clientDone = true;
						}
					}
					else if (instance->bytesInFlight > 0)
					{
						const int64_t copied = std::min<int64_t>(
							instance->bytesInFlight, static_cast<int64_t>(length));
						instance->bytesInFlight -= copied;
						if (instance->bytesInFlight == 0)
						{
							picoquic_mark_active_stream(cnx, stream_id, true, instance);
						}
					}
					else if (instance->downloadDoneSignalSent &&
					         !instance->downloadCompletionAckRead && length > 0)
					{
						instance->downloadCompletionAckRead = true;
					}
					//if ((rand() % 250) == 0) printf("received %.1f%%\n", 100.0 * (double)(_1GB - instance->bytesInFlight)/(double)_1GB );
				}
					else
					{
						size_t consumed = 0;
						while (serverState->requestBytesRead < serverState->requestBytes.size() && consumed < length)
						{
							serverState->requestBytes[serverState->requestBytesRead++] = bytes[consumed++];
						}

						if (!serverState->requestParsed && serverState->requestBytesRead == serverState->requestBytes.size())
						{
							uint64_t requested = 0;
							memcpy(&requested, serverState->requestBytes.data(), serverState->requestBytes.size());
							serverState->bytesInFlight = static_cast<int64_t>(bswap_64(requested));
							serverState->requestParsed = true;
							if (!benchmarkIsUpload())
							{
								seedServerBandwidth(cnx);
								picoquic_mark_active_stream(cnx, stream_id, true, serverState);
							}
						}

						if (benchmarkIsUpload() && serverState->requestParsed && consumed < length)
						{
							serverState->bytesInFlight -= std::min<int64_t>(serverState->bytesInFlight, static_cast<int64_t>(length - consumed));
							if (serverState->bytesInFlight == 0)
							{
								picoquic_mark_active_stream(cnx, stream_id, true, serverState);
							}
						}
							if (fin_or_event == picoquic_callback_stream_fin)
						{
							serverState->clientDone = true;
							if (!benchmarkIsUpload())
							{
								picoquic_mark_active_stream(cnx, stream_id, true, serverState);
							}
						}
					}

				break;
			}
			// Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details
				case picoquic_callback_prepare_to_send:
				{
					if (benchmarkScenario == BenchmarkScenario::datagram)
					{
						if constexpr (mode & Mode::client)
						{
							if (instance->datagramClientReceived >= benchmarkScenarioOperations &&
							    !instance->datagramDoneSignalSent)
							{
								instance->sendClientDatagramDoneSignal();
							}
							if (instance->datagramDoneSignalSent && !instance->datagramDoneStreamWritten)
							{
								uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, 1, true, false);
								if (buffer != nullptr)
								{
									buffer[0] = 0;
									instance->datagramDoneStreamWritten = true;
									instance->datagramClientDrainDeadlineUs = timeNowUs() + 100'000;
								}
							}
						}
						break;
					}
					if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) && genericState != nullptr)
					{
					if constexpr (mode & Mode::client)
					{
						size_t sendLength = 0;
						const uint8_t *source = nullptr;
						bool finished = false;
						bool stillActive = false;
						if (genericState->requestBytesWritten < genericState->requestBytesExpected)
						{
							const size_t left = static_cast<size_t>(
								genericState->requestBytesExpected - genericState->requestBytesWritten);
							sendLength = std::min<size_t>(length, left);
								source = benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario)
									? instance->networkHub->junk
									: genericState->requestBytes.data() + genericState->requestBytesWritten;
							stillActive = sendLength < left || genericState->payloadRemaining > 0;
						}
						else if (genericState->payloadRemaining > 0)
						{
							sendLength = static_cast<size_t>(
								std::min<uint64_t>(length, genericState->payloadRemaining));
							source = instance->networkHub->junk;
							stillActive = sendLength < genericState->payloadRemaining;
						}
						else if (genericState->responseRemaining == 0 && genericState->doneBytesWritten == 0)
						{
							static const uint8_t done = 0;
							sendLength = std::min<size_t>(length, sizeof(done));
							source = &done;
							finished = true;
						}

						uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sendLength, finished, stillActive);
						if (buffer != nullptr && sendLength > 0 && source != nullptr)
						{
							memcpy(buffer, source, sendLength);
							if (genericState->requestBytesWritten < genericState->requestBytesExpected)
							{
								genericState->requestBytesWritten += sendLength;
							}
							else if (genericState->payloadRemaining > 0)
							{
								genericState->payloadRemaining -= sendLength;
							}
							else if (finished)
							{
								genericState->doneBytesWritten += sendLength;
							}
						}
					}
					else
					{
						size_t sendLength = 0;
						const uint8_t *source = nullptr;
						bool finished = false;
						bool stillActive = false;
						if (genericState->phase == GenericPhase::sendResponse && genericState->responseRemaining > 0)
						{
							sendLength = static_cast<size_t>(
								std::min<uint64_t>(length, genericState->responseRemaining));
							source = instance->networkHub->junk;
							stillActive = sendLength < genericState->responseRemaining;
						}
						else if (genericState->phase == GenericPhase::readResponse &&
						         genericState->doneBytesRead > 0 && genericState->ackBytesWritten == 0)
						{
							static const uint8_t ack = 0;
							sendLength = std::min<size_t>(length, sizeof(ack));
							source = &ack;
							finished = true;
						}

						uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sendLength, finished, stillActive);
						if (buffer != nullptr && sendLength > 0 && source != nullptr)
						{
							memcpy(buffer, source, sendLength);
							if (genericState->phase == GenericPhase::sendResponse)
							{
								genericState->responseRemaining -= sendLength;
								if (genericState->responseRemaining == 0)
								{
									genericState->phase = GenericPhase::readResponse;
								}
							}
							else if (finished)
							{
								genericState->ackBytesWritten += sendLength;
								instance->markGenericServerComplete(genericState);
							}
						}
					}
					break;
				}
				if constexpr (mode & Mode::client)
				{
					if (benchmarkIsUpload())
					{
						const size_t headerLeft = instance->requestBytes.size() - instance->requestBytesWritten;
						const size_t payloadLeft = static_cast<size_t>(std::max<int64_t>(instance->bytesInFlight, 0));
						const size_t sendLength = std::min<size_t>(length, headerLeft + payloadLeft);
						const bool finished = sendLength == headerLeft + payloadLeft;
						uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sendLength, finished, !finished);
						if (buffer != nullptr)
						{
							size_t copied = 0;
							const size_t headerBytes = std::min(headerLeft, sendLength);
							if (headerBytes != 0)
							{
								memcpy(buffer, instance->requestBytes.data() + instance->requestBytesWritten, headerBytes);
								instance->requestBytesWritten += headerBytes;
								copied += headerBytes;
							}

							const size_t payloadBytes = sendLength - copied;
							if (payloadBytes != 0)
							{
								memset(buffer + copied, 7, payloadBytes);
								instance->bytesInFlight -= payloadBytes;
							}
						}
					}
					else if (instance->requestBytesWritten < instance->requestBytes.size())
					{
						const size_t left = instance->requestBytes.size() - instance->requestBytesWritten;
						const size_t sendLength = std::min<size_t>(length, left);
						uint8_t* buffer = picoquic_provide_stream_data_buffer(bytes, sendLength, false, sendLength < left);
						if (buffer != nullptr && sendLength > 0)
						{
							memcpy(buffer, instance->requestBytes.data() + instance->requestBytesWritten, sendLength);
							instance->requestBytesWritten += sendLength;
							if (instance->requestBytesWritten == instance->requestBytes.size())
							{
								picoquic_mark_active_stream(cnx, stream_id, false, instance);
							}
						}
					}
					else if (!instance->downloadDoneSignalSent)
					{
						static const uint8_t done = 0;
						uint8_t* buffer = picoquic_provide_stream_data_buffer(bytes, sizeof(done), true, false);
						if (buffer != nullptr)
						{
							buffer[0] = done;
							instance->downloadDoneSignalSent = true;
						}
					}
					else
					{
						instance->ready = true;
					}
				}
					else
					{
							if (serverState->bytesInFlight <= 0)
							{
								if (benchmarkIsUpload())
								{
									picoquic_provide_stream_data_buffer(bytes, 0, true, false);
									serverState->uploadFinSent = true;
									if (serverState->serverDrainDeadlineUs == 0)
									{
										serverState->serverDrainDeadlineUs = timeNowUs() + 100'000;
									}
									instance->markServerStateComplete(serverState);
								}
								else if (serverState->clientDone && !serverState->completionAckSent)
								{
									static const uint8_t ack = 0;
									uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, sizeof(ack), true, false);
									if (buffer != nullptr)
									{
										buffer[0] = ack;
										serverState->completionAckSent = true;
										serverState->serverDrainDeadlineUs = timeNowUs() + 100'000;
										instance->markServerStateComplete(serverState);
									}
								}
								else
								{
									picoquic_provide_stream_data_buffer(bytes, 0, false, false);
									picoquic_mark_active_stream(cnx, stream_id, false, serverState);
								}
								break;
							}

							size_t bytesSending = serverState->bytesInFlight > (int64_t)length ? length : serverState->bytesInFlight;
							bool stillActive = bytesSending < (size_t)serverState->bytesInFlight;
							bool finished = benchmarkIsUpload() && !stillActive;
							uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, bytesSending, finished, stillActive);

							if (buffer != nullptr)
							{
								memset(buffer, 7, bytesSending);
								serverState->bytesInFlight -= bytesSending;
								if (benchmarkIsUpload() && serverState->bytesInFlight == 0 && serverState->serverDrainDeadlineUs == 0)
								{
									serverState->serverDrainDeadlineUs = timeNowUs() + 100'000;
								}
							}
						}

				break;
			}
				// Data can be sent, but the connection is not fully established
				case picoquic_callback_almost_ready:
					break;
				// Data can be sent and received, connection migration can be initiated
				case picoquic_callback_ready:
				{
					instance->ready = true;
					instance->seedServerBandwidth(cnx);
					break;
				}
				// version negotiation requested
				case picoquic_callback_version_negotiation:
			// Provide the list of supported ALPN
			case picoquic_callback_request_alpn_list:
			// Set ALPN to negotiated value
			case picoquic_callback_set_alpn:
			// Pacing rate for the connection changed
			case picoquic_callback_pacing_changed:
			// Reset Stream received from peer on stream N; bytes=NULL, len = 0
			case picoquic_callback_stream_reset:
			// Stop sending received from peer on stream N; bytes=NULL, len = 0
			case picoquic_callback_stop_sending:
				// Stateless reset received from peer. Stream=0, bytes=NULL, len=0
				case picoquic_callback_stateless_reset:
				// Connection close. Stream=0, bytes=NULL, len=0
				case picoquic_callback_close:
				// Application closed by peer. Stream=0, bytes=NULL, len=0
				case picoquic_callback_application_close:
				{
					if (benchmarkScenario == BenchmarkScenario::datagram)
					{
						if constexpr (mode & Mode::server)
						{
							auto *datagramState = instance->datagramServerStateFor(cnx);
							datagramState->clientDone = true;
							instance->markDatagramServerComplete(datagramState);
						}
					}
					break;
				}
				// bytes=NULL, len = length-of-gap or 0 (if unknown)
				case picoquic_callback_stream_gap:
					break;
				// Datagram frame has been received
				case picoquic_callback_datagram:
				{
					if (benchmarkScenario == BenchmarkScenario::datagram)
					{
						if constexpr (mode & Mode::client)
						{
							++instance->datagramClientReceived;
							if (instance->datagramClientReceived >= benchmarkScenarioOperations &&
							    !instance->datagramDoneSignalSent)
							{
								instance->sendClientDatagramDoneSignal();
							}
							else
							{
								instance->sendClientDatagrams();
							}
						}
						else
						{
							auto *datagramState = instance->datagramServerStateFor(cnx);
							++datagramState->received;
							++datagramState->pendingEchoes;
							instance->sendPendingServerDatagrams();
						}
					}
					break;
				}
				default:
					break;
			}

		return 0;
	}

	void advance(int32_t count = 0)
	{
		//printf("picoquic %s: advance(%d)\n", modeToString(mode), count);

		MultiUDPContext *packets;
		UDPContext *packet;

		size_t send_length;
		int result;
		int interfaceIndex;
		int64_t usTil;

		// max sendBatches to push
		uint16_t metaBatchSize = 1; // tried values of 2 and 3, makes no difference for syscalls

			if constexpr (mode & Mode::iouring)
		{
			metaBatchSize = 1;
		}

		// max we push per sendBatch
		uint16_t batchSize = MultiUDPContext::batchSize;

			if constexpr (mode & Mode::iouring)
		{
			batchSize = 125;
		}

			do
			{
				if constexpr (mode & Mode::client)
				{
					sendClientDatagrams();
				}
				else
				{
					sendPendingServerDatagrams();
				}
				do
				{
						if constexpr (mode & Mode::iouring)
					{
						// considering iouring is async, sometimes the recvs outrun the sends completions that refill the pool
						if (likely(networkHub->sendPool.howManyLeft() == 0)) break;
					}

				packets = networkHub->sendPool.get();

				do
				{
					packet = &packets->msgs[packets->count];

					result = picoquic_prepare_next_packet_ex(engine, timeNowUs(), packet->buffer(), MAX_IPV6_UDP_PACKET_SIZE, &send_length, packet->address<sockaddr_storage>(), NULL, &interfaceIndex, NULL, NULL, NULL);

						if (result == 0 && send_length > 0)
						{
							packet->msg_hdr.msg_iov[0].iov_len = send_length;
							packet->msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
							++packets->count;
						}
					else
					{
						metaBatchSize = 1; // terminate outer loop too
						break;
					}

				} while (packets->count < batchSize);

				if (packets->count > 0) networkHub->sendBatch(packets);
				else 							networkHub->sendPool.relinquish(packets);

			} while (--metaBatchSize > 0);

					usTil = picoquic_get_next_wake_delay(engine, timeNowUs(), 300'000);
				if (usTil > 300'000) usTil = 300'000;

						networkHub->recvmsgWithTimeout(usTil, [&] (UDPContext *msg) -> void {

								picoquic_incoming_packet(engine, msg->buffer(), msg->msg_len, msg->address(), networkHub->socket.address(), 0, 0, timeNowUs());
						});

						if constexpr (mode & Mode::server)
						{
							for (auto& state : serverStreams)
							{
								markServerStateComplete(state.get());
							}
							sendPendingServerDatagrams();
						}

			} while (!perfComplete() && (count == 0 || --count > 0));
		}

public:

	void instanceSetup(uint16_t localPort, int argc, char *argv[])
	{
		//printf("picoquic %s: instanceSetup\n", modeToString(mode));

		networkHub = new NetworkHub<mode>(localPort);

			engine = picoquic_create(1000, tls_cert, tls_key, tls_chain, "perf", datain, this, NULL, NULL, NULL, timeNowUs(), NULL, NULL, NULL, 0);
			if (!benchmarkTlsVerifyPeer())
			{
				picoquic_set_verify_certificate_callback(engine, &noVerifyWithEd25519, nullptr);
			}

		picoquic_tp_t transportParams = *picoquic_get_default_tp(engine);
		transportParams.initial_max_stream_data_bidi_local = benchmarkStreamWindow;
		transportParams.initial_max_stream_data_bidi_remote = benchmarkStreamWindow;
		transportParams.initial_max_stream_data_uni = benchmarkStreamWindow;
		transportParams.initial_max_data = benchmarkConnectionWindow;
		transportParams.initial_max_stream_id_bidir = benchmarkMaxBidiStreams;
		transportParams.initial_max_stream_id_unidir = benchmarkMaxUniStreams;
		transportParams.max_idle_timeout = benchmarkIdleTimeoutMs;
			transportParams.max_packet_size = benchmarkUdpPayloadSize;
			transportParams.max_datagram_frame_size = benchmarkUdpPayloadSize;
		transportParams.max_ack_delay = benchmarkMaxAckDelayUs;
		transportParams.ack_delay_exponent = benchmarkAckDelayExponent;
		transportParams.migration_disabled = 1;
		transportParams.enable_bdp_frame = benchmarkPicoquicBdpFrameMode;
		picoquic_set_default_tp(engine, &transportParams);
		picoquic_set_default_idle_timeout(engine, benchmarkIdleTimeoutMs);
			picoquic_set_default_congestion_algorithm(engine, benchmarkPicoquicCongestionAlgorithm());
			picoquic_set_default_bdp_frame_option(engine, benchmarkPicoquicBdpFrameMode);
		picoquic_set_default_pmtud_policy(engine, picoquic_pmtud_blocked);
		picoquic_set_mtu_max(engine, benchmarkUdpPayloadSize);
		picoquic_set_max_data_control(engine, benchmarkConnectionWindow);
				// Packet-train mode is useful to compare on shaped paths, but it has historically
				// throttled some loopback rows, so the default remains off.
				picoquic_set_packet_train_mode(engine, benchmarkPicoquicPacketTrainMode);
		//picoquic_set_log_level(engine, 1);
		//picoquic_set_textlog(engine, "/dev/stdout");
		//picoquic_set_client_authentication(engine, 1);
	}

	void connectToServer(struct sockaddr *address)
	{
		//printf("picoquic %s: connect\n", modeToString(mode));

		// picoquic_cnx_t* picoquic_create_cnx(picoquic_quic_t* quic, picoquic_connection_id_t initial_cnx_id, picoquic_connection_id_t remote_cnx_id, const struct sockaddr* addr_to, uint64_t start_time, uint32_t preferred_version, char const* sni, char const* alpn, char client_mode);

		cnx = picoquic_create_cnx(engine, picoquic_null_connection_id, picoquic_null_connection_id, address, timeNowUs(), 0, "localhost", "perf", true);

		picoquic_set_callback(cnx, datain, this);
		picoquic_set_congestion_algorithm(cnx, benchmarkPicoquicCongestionAlgorithm());

			picoquic_start_client_cnx(cnx);

			do
			{
				advance(1);

			} while (ready == false);
		}

	void openStream(void)
	{
		//printf("picoquic %s: openStream\n", modeToString(mode));

		// picoquic_mark_active_stream(cnx, 0, true, this);

		// do
		// {
		// 	advance(1);

		// } while (ready == false);

		// picoquic_mark_active_stream(cnx, 0, false, this);
	}

	void postPerfTest(void) override
	{
		if constexpr (mode & Mode::client)
		{
			if (!benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario) &&
			    benchmarkScenario != BenchmarkScenario::datagram &&
			    !benchmarkIsUpload() &&
			    requestBytesWritten == requestBytes.size() &&
			    !downloadCompletionAckRead)
			{
				picoquic_mark_active_stream(cnx, 0, true, this);
				while (!downloadDoneSignalSent || !downloadCompletionAckRead)
				{
					advance(1);
				}
			}
		}
	}

	void startPerfTest(uint64_t nBytes)
	{
		//printf("picoquic %s: startPerfTest\n", modeToString(mode));

			if constexpr (mode & Mode::client)
			{
				if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
				{
				genericClientBytes = nBytes;
				genericRequestedStreams = 0;
				genericOpenedStreams = 0;
				genericCompletedStreams = 0;
				genericServerCompletedStreams = 0;
				genericActiveStreams = 0;
				genericStreams.clear();
				genericStreamById.clear();
				const uint64_t targetStreams = benchmarkGenericStreamsPerConnection();
				genericStreams.reserve(static_cast<size_t>(targetStreams));
				genericStreamById.reserve(static_cast<size_t>(targetStreams));
				genericStarted = true;
				openMoreGenericClientStreams();
					advance();
					return;
				}
				if (benchmarkScenario == BenchmarkScenario::datagram)
				{
					datagramClientSent = 0;
					datagramClientReceived = 0;
					datagramClientDrainDeadlineUs = 0;
					datagramDoneSignalSent = false;
					datagramDoneStreamWritten = false;
					bytesInFlight = 0;
					sendClientDatagrams();
					advance();
					return;
				}
				bytesInFlight = nBytes;
				clientDone = false;
				downloadDoneSignalSent = false;
				downloadCompletionAckRead = false;
			uint64_t request = bswap_64(nBytes);
			memcpy(requestBytes.data(), &request, requestBytes.size());
			requestBytesWritten = 0;
			picoquic_mark_active_stream(cnx, 0, true, this);
		}

		advance();
	}
};
