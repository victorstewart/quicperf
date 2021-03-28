#include "quiche.h"

#pragma once

#define LOCAL_CONN_ID_LEN 16

#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    LOCAL_CONN_ID_LEN

template <Mode mode>
class Quiche : public QuicLibrary<mode> { 
private:

	using QuicLibrary<mode>::networkHub;

	int64_t bytesInFlight = -1;
	quiche_config *config;
	quiche_conn *conn;
	struct sockaddr_in6 *peerAddress;
	bool connected;

	uint64_t flushPackets(void)
	{
		if (unlikely(conn == NULL)) return 0;

		MultiUDPContext *packets = networkHub->sendPool.get();
		UDPContext *packet;

		do
	   {
	   	packet = &packets->msgs[packets->count];

	   	ssize_t written = quiche_conn_send(conn, packet->buffer(), MAX_IPV6_UDP_PACKET_SIZE);

	      if (written == QUICHE_ERR_DONE) break;

	      packet->setLength(written);
	      packet->copyInAddress((struct sockaddr *)peerAddress);

	      packets->count++;

	      if (packets->isFull())
	      {
	      	networkHub->sendBatch(packets);

	      	// printf("networkHub->sendPool.howManyLeft() = %lu\n", networkHub->sendPool.howManyLeft());

	      	//packets = networkHub->sendPool.get();
	      	//if (unlikely(packets == NULL)) return 10000;
	      }

	   } while (true);

	   if (packets->count > 0) networkHub->sendBatch(packets);

	skip:
		return quiche_conn_timeout_as_nanos(conn) / 1'000;
	}

	void advance(int32_t count = 0)
	{
		do
		{
			uint64_t usTil = flushPackets();

			bool timedout = networkHub->recvmsgWithTimeout(usTil, [&] (UDPContext *msg) -> void {

				if constexpr (mode & Mode::server)
				{
					if (conn == NULL)
					{
						uint8_t serverscid[8]; 
						RAND_bytes(serverscid, sizeof(serverscid));

						conn = quiche_conn_new_with_tls(serverscid, sizeof(serverscid), NULL, 0, config, SSL_new(TLS::getTLSCtx()), true);

						peerAddress = (struct sockaddr_in6 *)malloc(sizeof(struct sockaddr_in6));
						memcpy(peerAddress, msg->address(), sizeof(struct sockaddr_in6));
					}
				}
				
				ssize_t result = quiche_conn_recv(conn, msg->buffer(), msg->msg_len);

				//printf("quiche_conn_recv result = %lld\n", result);

				if (quiche_conn_is_established(conn))
				{
					//printf("quiche_conn_stream_capacity = %lld\n", quiche_conn_stream_capacity(conn, 0));

					if constexpr (mode & Mode::client)
					{
						connected = true;
					}

					uint64_t streamID = 0;
					quiche_stream_iter *readable = quiche_conn_readable(conn);

					while (quiche_stream_iter_next(readable, &streamID)) 
					{
						static uint8_t buf[65535];

						bool fin = false;
	               ssize_t recv_len = quiche_conn_stream_recv(conn, streamID, buf, sizeof(buf), &fin);

						if constexpr (mode & Mode::client)
						{
							// throw bytes away
							bytesInFlight -= recv_len;
							//printf("received %.1f%%\n", 100.0 * (double)(_1GB - bytesInFlight)/(double)_1GB);
						}
						else
						{
							// receive the bytes in flight
							bytesInFlight = bswap_64(*(uint64_t *)buf);
						}
					}

					quiche_stream_iter_free(readable);
				}
			});

			if (timedout) quiche_conn_on_timeout(conn);

			if constexpr (mode & Mode::server)
			{
				if (conn == NULL) continue;

				if (quiche_conn_stream_capacity(conn, 0) > 0)
				{
					do
					{
						ssize_t sent = quiche_conn_stream_send(conn, 0, (const uint8_t *)networkHub->junk, bytesInFlight > sizeof(networkHub->junk) ? sizeof(networkHub->junk) : bytesInFlight, false);

						if (sent > 0) bytesInFlight -= sent;
						else 			  break;

					} while (true);

					// one last send
					if (bytesInFlight == 0) flushPackets();
				}
			}
		
		} while (bytesInFlight != 0 && (count == 0 || --count > 0));
	}

public:

	// static void log(const char *line, void *argp)
	// {
	// 	printf("%s\n", line);
	// }

	void instanceSetup(uint16_t localPort, int argc, char *argv[])
	{
		networkHub = new NetworkHub<mode>(localPort);

		config = quiche_config_new(QUICHE_PROTOCOL_VERSION);

		quiche_config_set_max_idle_timeout(config, 5000);
		quiche_config_set_max_recv_udp_payload_size(config, MAX_IPV6_UDP_PACKET_SIZE);
		quiche_config_set_max_send_udp_payload_size(config, MAX_IPV6_UDP_PACKET_SIZE);
		quiche_config_set_initial_max_data(config, 10000000);
		quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
		quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
		quiche_config_set_initial_max_stream_data_uni(config, 10000);
		quiche_config_set_initial_max_streams_bidi(config, 10);
		quiche_config_set_initial_max_streams_uni(config, 10);
		// quiche_config_set_ack_delay_exponent(config, 100);
		// quiche_config_set_max_ack_delay(config, 10000);
		// quiche_config_set_disable_active_migration(config, true);
		// quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);

		//quiche_enable_debug_logging(log, NULL);
	}

	void connect(struct sockaddr *address)
	{
		peerAddress = (struct sockaddr_in6 *)address;

		uint8_t scid[8]; 
		RAND_bytes(scid, sizeof(scid));

		conn = quiche_conn_new_with_tls((const uint8_t *)scid, sizeof(scid), NULL, 0, config, SSL_new(TLS::getTLSCtx()), false);

		do
		{
			advance(1);

		} while (connected == false);
	}

	void openStream(void)
	{
		// just nop this for now

		// do
		// {
		// 	advance(1);

		// } while (ready == false);
	}

	void startPerfTest(uint64_t nBytes)
	{
		if constexpr (mode & Mode::client)
		{
			bytesInFlight = nBytes;

			uint64_t swappedBytes = bswap_64(bytesInFlight);
			quiche_conn_stream_send(conn, 0, (const uint8_t *)&swappedBytes, 8, false);
		}
		
		advance();
	}
};