#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "picoquic_unified_log.h"
#include "picoquic_config.h"
#include "picotls.h"

#pragma once

template <Mode mode>
class Picoquic : public QuicLibrary<mode> { 
private:

	using QuicLibrary<mode>::networkHub;

	picoquic_quic_t *engine;
	picoquic_cnx_t *cnx;
	int64_t bytesInFlight = -1;
	bool ready;

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

		switch (fin_or_event)
		{
			// Data received from peer on stream N
			case picoquic_callback_stream_data:
			// Fin received from peer on stream N; data is optional
			case picoquic_callback_stream_fin:
			{
				if constexpr (mode & Mode::client)
				{
					instance->bytesInFlight -= length;
					//if ((rand() % 250) == 0) printf("received %.1f%%\n", 100.0 * (double)(_1GB - instance->bytesInFlight)/(double)_1GB );
				}
				else
				{
					instance->bytesInFlight = bswap_64(*(uint64_t *)bytes);
					picoquic_mark_active_stream(cnx, stream_id, true, instance);
				}	

				break;
			}
			// Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details
			case picoquic_callback_prepare_to_send:
			{
				if constexpr (mode & Mode::client)
				{
					if (instance->bytesInFlight)
					{
						uint8_t* buffer = picoquic_provide_stream_data_buffer(bytes, 8, 1, 0);
						*(uint64_t *)buffer = bswap_64(instance->bytesInFlight);
						picoquic_mark_active_stream(cnx, stream_id, false, instance);
					}
					else
					{
						instance->ready = true;
					}
				}
				else
				{
					size_t bytesSending = instance->bytesInFlight > length ? length : instance->bytesInFlight;
					uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, bytesSending, false, true);
					memset(buffer, 7, bytesSending);
					instance->bytesInFlight -= bytesSending;
				}	

				break;
			}
			// Data can be sent, but the connection is not fully established
			case picoquic_callback_almost_ready:
			// Data can be sent and received, connection migration can be initiated
			case picoquic_callback_ready:
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
			// bytes=NULL, len = length-of-gap or 0 (if unknown)
			case picoquic_callback_stream_gap:
			// Datagram frame has been received
			case picoquic_callback_datagram:
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
			do
			{
				if constexpr (mode & Mode::iouring)
				{
					// considering iouring is async, sometimes the recvs outrun the sends completions that refill the pool
					if (likely(networkHub->sendPool.howManyLeft() == 0)) goto skip;
				}

				packets = networkHub->sendPool.get();

				do
				{
					packet = &packets->msgs[packets->count];

					result = picoquic_prepare_next_packet_ex(engine, timeNowUs(), packet->buffer(), MAX_IPV6_UDP_PACKET_SIZE, &send_length, packet->address<sockaddr_storage>(), NULL, &interfaceIndex, NULL, NULL, NULL);
					
					if (result == 0 && send_length > 0)
					{
						packet->msg_hdr.msg_iov[0].iov_len = send_length;
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
		
		skip:
			usTil = picoquic_get_next_wake_delay(engine, timeNowUs(), 300'000);
			if (usTil > 300'000) usTil = 300'000;

 			networkHub->recvmsgWithTimeout(usTil, [&] (UDPContext *msg) -> void {
 		
 				picoquic_incoming_packet(engine, msg->buffer(), msg->msg_len, msg->address(), NULL, 0, 0, timeNowUs());
 			});
 			
		} while (bytesInFlight != 0 && (count == 0 || --count > 0));
	}

public:

	void instanceSetup(uint16_t localPort, uint32_t batchSize = 0)
	{
		//printf("picoquic %s: instanceSetup\n", modeToString(mode));

		networkHub = new NetworkHub<mode>(localPort, batchSize);

		engine = picoquic_create(1000, tls_cert, tls_key, tls_chain, "perf", datain, this, NULL, NULL, NULL, timeNowUs(), NULL, NULL, NULL, 0);

		static constexpr int x25519 = 20;
		picoquic_set_key_exchange(engine, x25519);

		// performacne of aes-128 over aes-256 holds up for picotls-fusion as well
	/*
		type                    2 bytes     31 bytes    136 bytes   1024 bytes   8192 bytes   16384 bytes
		----                    -------     --------    ---------   ----------   ----------   -----------
		aes-128-gcm             2326.81k    29137.11k   108788.53k  360005.63k   482115.58k   492399.27k
		aes-256-gcm             2256.78k    28163.19k   102470.97k  320374.44k   420995.35k   423843.16k
		chacha20-poly1305       807.76k     11608.37k   32482.65k   129967.34k   167075.84k   169951.23k
	*/

	/* Set cipher suite, for tests. 
	 * 0: default values
	 * 20: chacha20poly1305sha256
	 * 128: aes128gcmsha256
	 * 256: aes256gcmsha384
	 * returns 0 if OK, -1 if the specified ciphersuite is not supported.
	 */
		static constexpr int aes128gcmsha256 = 128;
		picoquic_set_cipher_suite(engine, aes128gcmsha256);

		// picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

		picoquic_set_packet_train_mode(engine, 0);
		//picoquic_set_log_level(engine, 1);
		//picoquic_set_textlog(engine, "/dev/stdout");
		//picoquic_set_client_authentication(engine, 1);
	}

	void connect(struct sockaddr *address)
	{
		//printf("picoquic %s: connect\n", modeToString(mode));

		// picoquic_cnx_t* picoquic_create_cnx(picoquic_quic_t* quic, picoquic_connection_id_t initial_cnx_id, picoquic_connection_id_t remote_cnx_id, const struct sockaddr* addr_to, uint64_t start_time, uint32_t preferred_version, char const* sni, char const* alpn, char client_mode); 

		cnx = picoquic_create_cnx(engine, picoquic_null_connection_id, picoquic_null_connection_id, address, timeNowUs(), 0, "localhost", "perf", true);

		picoquic_set_callback(cnx, datain, this);

		st_picoquic_tp_t parameters = {};
		picoquic_init_transport_parameters(&parameters, mode == Mode::client ? true : false);

		// parameters.initial_max_data = 9'000'000;
		// parameters.idle_timeout = 30'000; // milliseconds 
		// parameters.max_packet_size = 1500;
		// //parameters.max_ack_delay = 6'400'000; // microseconds
		// //parameters.ack_delay_exponent = 8;
		// parameters.migration_disabled = false;

		picoquic_set_transport_parameters(cnx, &parameters);

		picoquic_start_client_cnx(cnx);
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

	void startPerfTest(uint64_t nBytes)
	{
		//printf("picoquic %s: startPerfTest\n", modeToString(mode));
		
		if constexpr (mode & Mode::client)
		{
			bytesInFlight = nBytes;
			picoquic_mark_active_stream(cnx, 0, true, this);
		}
		
		advance();
	}
};
