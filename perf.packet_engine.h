#pragma once

#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF)
#include "quicperf_rust_packet_ffi.h"
#endif

#if defined(QUICZIGPERF)
#include "quicperf_zig_packet_ffi.h"
#endif

#include <algorithm>
#include <array>
#include <cassert>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <type_traits>
#include <vector>

struct PacketStreamDebug {
	bool found = false;
	uint64_t sendWriteOffset = 0;
	uint64_t sendSendOffset = 0;
	uint64_t sendAckOffset = 0;
	uint64_t sendWindow = 0;
	uint64_t sendRetransmitCount = 0;
	bool sendFinQueued = false;
	bool sendFinSent = false;
	bool sendFinLost = false;
	bool sendHasData = false;
	bool sendHasUnacked = false;
	uint64_t recvReadPos = 0;
	uint64_t recvHighestBuffered = 0;
	uint64_t recvFinOffset = 0;
	bool recvFinKnown = false;
	bool recvFinished = false;
	uint64_t recvChunkCount = 0;
	uint64_t bytesInFlight = 0;
	uint64_t cwnd = 0;
	uint64_t connSendWindow = 0;
};

#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF)
struct RustPacketAbi {
	using engine_t = qpf_engine_t;
	using config_t = qpf_config_t;
	using addr_t = qpf_addr_t;

	static constexpr const char *label = "rust packet ffi";
	static constexpr bool is_zig = false;

	static const char *lastError(void) { return qpf_last_error(); }
	static engine_t *engineNew(config_t *config) { return qpf_engine_new(config); }
	static void engineFree(engine_t *engine) { qpf_engine_free(engine); }
	static int connect(engine_t *engine, const addr_t *remote, uint64_t nowUs, uint64_t *conn) { return qpf_engine_connect(engine, remote, nowUs, conn); }
	static int acceptConnection(engine_t *engine, uint64_t *conn) { return qpf_engine_accept_connection(engine, conn); }
	static int isConnected(engine_t *engine, uint64_t conn, uint64_t nowUs) { return qpf_engine_is_connected(engine, conn, nowUs); }
	static int receive(engine_t *engine, const addr_t *remote, uint8_t *data, size_t len, uint64_t nowUs) { return qpf_engine_receive(engine, remote, data, len, nowUs); }
	static int pollTransmit(engine_t *engine, addr_t *remote, uint8_t *data, size_t capacity, size_t *len, uint64_t nowUs) { return qpf_engine_poll_transmit(engine, remote, data, capacity, len, nowUs); }
	static int nextTimeoutUs(engine_t *engine, uint64_t nowUs, uint64_t *timeoutUs) { return qpf_engine_next_timeout_us(engine, nowUs, timeoutUs); }
	static int onTimeout(engine_t *engine, uint64_t nowUs) { return qpf_engine_on_timeout(engine, nowUs); }
	static bool hasPendingAppData(engine_t *) { return false; }
	static int openBidi(engine_t *engine, uint64_t conn, uint64_t *stream, uint64_t nowUs) { return qpf_connection_open_bidi(engine, conn, stream, nowUs); }
	static int acceptBidi(engine_t *engine, uint64_t conn, uint64_t *stream, uint64_t nowUs) { return qpf_connection_accept_bidi(engine, conn, stream, nowUs); }
	static int streamSend(engine_t *engine, uint64_t conn, uint64_t stream, const uint8_t *data, size_t len, size_t *written, uint64_t nowUs) { return qpf_stream_send(engine, conn, stream, data, len, written, nowUs); }
	static int streamRecv(engine_t *engine, uint64_t conn, uint64_t stream, uint8_t *data, size_t capacity, size_t *read, bool *fin, uint64_t nowUs) { return qpf_stream_recv(engine, conn, stream, data, capacity, read, fin, nowUs); }
	static int streamFinish(engine_t *engine, uint64_t conn, uint64_t stream, uint64_t nowUs) { return qpf_stream_finish(engine, conn, stream, nowUs); }
	static bool streamDebug(engine_t *, uint64_t, uint64_t, PacketStreamDebug *) { return false; }
	static int datagramSend(engine_t *engine, uint64_t conn, const uint8_t *data, size_t len, uint64_t nowUs) { return qpf_datagram_send(engine, conn, data, len, nowUs); }
	static int datagramRecv(engine_t *engine, uint64_t conn, uint8_t *data, size_t capacity, size_t *read, uint64_t nowUs) { return qpf_datagram_recv(engine, conn, data, capacity, read, nowUs); }
	static void setLibrary(config_t& config, uint32_t libraryKind) { config.library = libraryKind; }
};
#endif

#if defined(QUICZIGPERF)
struct ZigPacketAbi {
	using engine_t = qzf_engine_t;
	using config_t = qzf_config_t;
	using addr_t = qzf_addr_t;

	static constexpr const char *label = "zig packet ffi";
	static constexpr bool is_zig = true;

	static const char *lastError(void) { return qzf_last_error(); }
	static engine_t *engineNew(config_t *config) { return qzf_engine_new(config); }
	static void engineFree(engine_t *engine) { qzf_engine_free(engine); }
	static int connect(engine_t *engine, const addr_t *remote, uint64_t nowUs, uint64_t *conn) { return qzf_engine_connect(engine, remote, nowUs, conn); }
	static int acceptConnection(engine_t *engine, uint64_t *conn) { return qzf_engine_accept_connection(engine, conn); }
	static int isConnected(engine_t *engine, uint64_t conn, uint64_t nowUs) { return qzf_engine_is_connected(engine, conn, nowUs); }
	static int receive(engine_t *engine, const addr_t *remote, uint8_t *data, size_t len, uint64_t nowUs) { return qzf_engine_receive(engine, remote, data, len, nowUs); }
	static int pollTransmit(engine_t *engine, addr_t *remote, uint8_t *data, size_t capacity, size_t *len, uint64_t nowUs) { return qzf_engine_poll_transmit(engine, remote, data, capacity, len, nowUs); }
	static int nextTimeoutUs(engine_t *engine, uint64_t nowUs, uint64_t *timeoutUs) { return qzf_engine_next_timeout_us(engine, nowUs, timeoutUs); }
	static int onTimeout(engine_t *engine, uint64_t nowUs) { return qzf_engine_on_timeout(engine, nowUs); }
	static bool hasPendingAppData(engine_t *engine) { return qzf_engine_has_pending_app_data(engine) == 1; }
	static int openBidi(engine_t *engine, uint64_t conn, uint64_t *stream, uint64_t nowUs) { return qzf_connection_open_bidi(engine, conn, stream, nowUs); }
	static int acceptBidi(engine_t *engine, uint64_t conn, uint64_t *stream, uint64_t nowUs) { return qzf_connection_accept_bidi(engine, conn, stream, nowUs); }
	static int streamSend(engine_t *engine, uint64_t conn, uint64_t stream, const uint8_t *data, size_t len, size_t *written, uint64_t nowUs) { return qzf_stream_send(engine, conn, stream, data, len, written, nowUs); }
	static int streamRecv(engine_t *engine, uint64_t conn, uint64_t stream, uint8_t *data, size_t capacity, size_t *read, bool *fin, uint64_t nowUs) { return qzf_stream_recv(engine, conn, stream, data, capacity, read, fin, nowUs); }
	static int streamFinish(engine_t *engine, uint64_t conn, uint64_t stream, uint64_t nowUs) { return qzf_stream_finish(engine, conn, stream, nowUs); }
	static bool streamDebug(engine_t *engine, uint64_t conn, uint64_t stream, PacketStreamDebug *debug)
	{
		qzf_stream_debug_t raw = {};
		if (qzf_stream_debug(engine, conn, stream, &raw) != 1 || !raw.found)
		{
			return false;
		}
		debug->found = true;
		debug->sendWriteOffset = raw.send_write_offset;
		debug->sendSendOffset = raw.send_send_offset;
		debug->sendAckOffset = raw.send_ack_offset;
		debug->sendWindow = raw.send_window;
		debug->sendRetransmitCount = raw.send_retransmit_count;
		debug->sendFinQueued = raw.send_fin_queued;
		debug->sendFinSent = raw.send_fin_sent;
		debug->sendFinLost = raw.send_fin_lost;
		debug->sendHasData = raw.send_has_data;
		debug->sendHasUnacked = raw.send_has_unacked;
		debug->recvReadPos = raw.recv_read_pos;
		debug->recvHighestBuffered = raw.recv_highest_buffered;
		debug->recvFinOffset = raw.recv_fin_offset;
		debug->recvFinKnown = raw.recv_fin_known;
		debug->recvFinished = raw.recv_finished;
		debug->recvChunkCount = raw.recv_chunk_count;
		debug->bytesInFlight = raw.bytes_in_flight;
		debug->cwnd = raw.cwnd;
		debug->connSendWindow = raw.conn_send_window;
		return true;
	}
	static int datagramSend(engine_t *engine, uint64_t conn, const uint8_t *data, size_t len, uint64_t nowUs) { return qzf_datagram_send(engine, conn, data, len, nowUs); }
	static int datagramRecv(engine_t *engine, uint64_t conn, uint8_t *data, size_t capacity, size_t *read, uint64_t nowUs) { return qzf_datagram_recv(engine, conn, data, capacity, read, nowUs); }
	static void setLibrary(config_t&, uint32_t) {}
};
#endif

template <Mode mode, typename Abi, uint32_t libraryKind = 0>
class PacketEngineLibrary : public QuicLibrary<mode> {
private:
	using QuicLibrary<mode>::networkHub;

		typename Abi::engine_t *engine = nullptr;
		uint64_t connection = UINT64_MAX;
		uint64_t stream = UINT64_MAX;
		alignas(64) std::array<uint8_t, benchmarkAppChunkSize> buffer = {};
			bool debugTrace = false;
			bool stallTrace = false;

	enum class ServerPhase : uint8_t {
		acceptStream,
		readRequest,
		transfer,
		readDone,
		sendAck,
		finish,
		complete
		};

	enum class GenericPhase : uint8_t {
		readRequest,
		transfer,
		sendResponse,
		readDone,
		sendAck,
		readAck,
		finish,
		complete
	};

	static const char *genericPhaseName(GenericPhase phase)
	{
		switch (phase)
		{
			case GenericPhase::readRequest: return "readRequest";
			case GenericPhase::transfer: return "transfer";
			case GenericPhase::sendResponse: return "sendResponse";
			case GenericPhase::readDone: return "readDone";
			case GenericPhase::sendAck: return "sendAck";
			case GenericPhase::readAck: return "readAck";
			case GenericPhase::finish: return "finish";
			case GenericPhase::complete: return "complete";
		}
		return "unknown";
	}

	struct ServerConn {
		uint64_t conn = UINT64_MAX;
		uint64_t stream = UINT64_MAX;
		ServerPhase phase = ServerPhase::acceptStream;
		std::array<uint8_t, sizeof(uint64_t)> request = {};
		size_t requestRead = 0;
		uint64_t bytesRemaining = 0;
		uint8_t done = 0;
		size_t doneRead = 0;
		uint8_t ack = 0;
		size_t ackSent = 0;
	};

	struct GenericServerStream {
		uint64_t conn = UINT64_MAX;
		uint64_t stream = UINT64_MAX;
		GenericPhase phase = GenericPhase::readRequest;
		uint64_t requestValue = 0;
		std::array<uint8_t, sizeof(uint64_t)> request = {};
		uint64_t requestBytesRead = 0;
		uint64_t requestBytesExpected = 0;
		uint64_t payloadRemaining = 0;
		uint64_t responseRemaining = 0;
		uint8_t done = 0;
		size_t doneRead = 0;
		uint8_t ack = 0;
		size_t ackSent = 0;
		size_t ackRead = 0;
		bool peerFinReceived = false;
		bool finSent = false;
	};

	struct GenericClientStream {
		uint64_t stream = UINT64_MAX;
		GenericPhase phase = GenericPhase::readRequest;
		uint64_t requestValue = 0;
		uint64_t requestBytesSent = 0;
		uint64_t requestBytesExpected = 0;
		uint64_t payloadRemaining = 0;
		uint64_t responseRemaining = 0;
		uint8_t done = 0;
		size_t doneSent = 0;
		uint8_t ack = 0;
		size_t ackRead = 0;
		size_t ackSent = 0;
		bool finSent = false;
	};

	struct DatagramServerConn {
		uint64_t conn = UINT64_MAX;
		uint64_t received = 0;
		uint64_t echoed = 0;
		uint64_t pendingEchoes = 0;
	};

		void check(int result)
		{
			if (result < 0)
			{
				const char *error = Abi::lastError();
				fprintf(stderr, "%s error: %s\n", Abi::label, error == nullptr ? "unknown" : error);
				assert(result >= 0);
				abort();
			}
		}

		bool lastErrorIsInvalidStream(void) const
		{
			const char *error = Abi::lastError();
			return error != nullptr && strstr(error, "InvalidStreamId") != nullptr;
		}

	static void encodeU64(uint64_t value, uint8_t out[8])
	{
		for (int i = 7; i >= 0; --i)
		{
			out[i] = static_cast<uint8_t>(value & 0xff);
			value >>= 8;
		}
	}

	static uint64_t decodeU64(const uint8_t in[8])
	{
		uint64_t value = 0;
		for (int i = 0; i < 8; ++i)
		{
			value = (value << 8) | in[i];
		}
		return value;
	}

	static typename Abi::addr_t packetAddrFromSockaddr(const struct sockaddr *address)
	{
		const auto *addr6 = reinterpret_cast<const struct sockaddr_in6 *>(address);
		typename Abi::addr_t out = {};
		memcpy(out.ip, addr6->sin6_addr.s6_addr, sizeof(out.ip));
		out.port = ntohs(addr6->sin6_port);
		return out;
	}

	static struct sockaddr_in6 sockaddrFromPacketAddr(const typename Abi::addr_t& address)
	{
		struct sockaddr_in6 out = {};
		out.sin6_family = AF_INET6;
		out.sin6_port = htons(address.port);
		memcpy(out.sin6_addr.s6_addr, address.ip, sizeof(out.sin6_addr.s6_addr));
		return out;
	}

	uint64_t nowUs(void) const
	{
		return timeNowUs();
	}

	void flushPackets(void)
	{
		drainReadyIncomingPackets();
		networkHub->drainSendCompletions();
		MultiUDPContext *packets = nullptr;
		while (true)
		{
			if (packets == nullptr)
			{
				packets = networkHub->sendPool.get();
				if (packets == nullptr)
				{
					networkHub->drainSendCompletions();
					packets = networkHub->sendPool.get();
				}
				if (packets == nullptr)
				{
					networkHub->flush();
					return;
				}
			}

			UDPContext *packet = &packets->msgs[packets->count];
			typename Abi::addr_t destination = {};
			size_t len = 0;
			int result = Abi::pollTransmit(engine, &destination, packet->buffer(), MAX_IPV6_UDP_PACKET_SIZE, &len, nowUs());
			check(result);
			if (result == 0)
			{
				break;
			}

			struct sockaddr_in6 sockaddr = sockaddrFromPacketAddr(destination);
			packet->setLength(len);
			packet->copyInAddress(reinterpret_cast<const struct sockaddr *>(&sockaddr));
			++packets->count;

			if (packets->isFull())
			{
				networkHub->sendBatch(packets);
				packets = nullptr;
			}
		}

			if (packets != nullptr)
			{
			if (packets->count > 0)
			{
				networkHub->sendBatch(packets);
			}
			else
			{
				packets->reset();
				networkHub->sendPool.relinquish(packets);
			}
		}
		networkHub->flush();
		drainReadyIncomingPackets();
	}

	void drainReadyIncomingPackets(void)
	{
		networkHub->recvmsgWithTimeout(0, [&] (UDPContext *msg) -> void {
			typename Abi::addr_t remote = packetAddrFromSockaddr(msg->address());
			check(Abi::receive(engine, &remote, msg->buffer(), msg->msg_len, nowUs()));
		});
	}

	void pumpOnce(uint64_t maxWaitUs = 100'000)
	{
		flushPackets();
		uint64_t timeoutUs = maxWaitUs;
		check(Abi::nextTimeoutUs(engine, nowUs(), &timeoutUs));
		timeoutUs = std::min<uint64_t>(timeoutUs, maxWaitUs);

		bool timedout = networkHub->recvmsgWithTimeout(static_cast<int64_t>(timeoutUs), [&] (UDPContext *msg) -> void {
			typename Abi::addr_t remote = packetAddrFromSockaddr(msg->address());
			check(Abi::receive(engine, &remote, msg->buffer(), msg->msg_len, nowUs()));
		});

		uint64_t afterIoUs = nowUs();
		uint64_t dueUs = maxWaitUs;
		check(Abi::nextTimeoutUs(engine, afterIoUs, &dueUs));
		if (timedout || dueUs == 0)
		{
			check(Abi::onTimeout(engine, afterIoUs));
		}
		flushPackets();
	}

	void drainTerminalPackets(uint64_t waitUs = 0, int iterations = 64)
	{
		for (int i = 0; i < iterations; ++i)
		{
			pumpOnce(waitUs);
		}
	}

	size_t sendSome(uint64_t activeStream, const uint8_t *data, size_t length)
	{
		size_t written = 0;
		check(Abi::streamSend(engine, connection, activeStream, data, length, &written, nowUs()));
		flushPackets();
		return written;
	}

	size_t sendSome(ServerConn& active, const uint8_t *data, size_t length)
	{
		size_t written = 0;
		check(Abi::streamSend(engine, active.conn, active.stream, data, length, &written, nowUs()));
		flushPackets();
		return written;
	}

	size_t sendSome(GenericServerStream& active, const uint8_t *data, size_t length)
	{
		size_t written = 0;
		check(Abi::streamSend(engine, active.conn, active.stream, data, length, &written, nowUs()));
		flushPackets();
		return written;
	}

		std::pair<size_t, bool> recvSome(uint64_t activeStream, uint8_t *data, size_t length)
		{
			size_t read = 0;
			bool fin = false;
			check(Abi::streamRecv(engine, connection, activeStream, data, length, &read, &fin, nowUs()));
			flushPackets();
			return {read, fin};
		}

		bool recvSomeAllowInvalidStream(uint64_t activeStream, uint8_t *data, size_t length, size_t& read, bool& fin)
		{
			read = 0;
			fin = false;
			int result = Abi::streamRecv(engine, connection, activeStream, data, length, &read, &fin, nowUs());
			if (result < 0)
			{
				if (lastErrorIsInvalidStream())
				{
					flushPackets();
					return false;
				}
				check(result);
			}
			flushPackets();
			return true;
		}

	std::pair<size_t, bool> recvSome(ServerConn& active, uint8_t *data, size_t length)
	{
		size_t read = 0;
		bool fin = false;
		check(Abi::streamRecv(engine, active.conn, active.stream, data, length, &read, &fin, nowUs()));
		flushPackets();
		return {read, fin};
	}

	std::pair<size_t, bool> recvSome(GenericServerStream& active, uint8_t *data, size_t length)
	{
		size_t read = 0;
		bool fin = false;
		check(Abi::streamRecv(engine, active.conn, active.stream, data, length, &read, &fin, nowUs()));
		flushPackets();
		return {read, fin};
	}

	bool sendDatagram(uint64_t activeConn, const uint8_t *data, size_t length)
	{
		int result = Abi::datagramSend(engine, activeConn, data, length, nowUs());
		check(result);
		flushPackets();
		return result == 1;
	}

	bool recvDatagram(uint64_t activeConn, uint8_t *data, size_t capacity, size_t& read)
	{
		read = 0;
		int result = Abi::datagramRecv(engine, activeConn, data, capacity, &read, nowUs());
		check(result);
		flushPackets();
		return result == 1;
	}

	void sendAll(const uint8_t *data, size_t length)
	{
		size_t offset = 0;
		while (offset < length)
		{
			size_t written = sendSome(stream, data + offset, length - offset);
			if (written == 0)
			{
				pumpOnce();
			}
			else
			{
				offset += written;
			}
		}
	}

	uint64_t openClientBidiStream(void)
	{
		uint64_t opened = UINT64_MAX;
		uint64_t attempts = 0;
		while (true)
		{
			int result = Abi::openBidi(engine, connection, &opened, nowUs());
			check(result);
			if (result == 1)
			{
				return opened;
			}
			++attempts;
			if (debugTrace && (attempts % 1000) == 0)
			{
				fprintf(stderr, "%s debug=open_client_bidi_wait attempts=%" PRIu64 "\n", Abi::label, attempts);
			}
			pumpOnce();
		}
	}

	void finishStream(uint64_t activeStream)
	{
		check(Abi::streamFinish(engine, connection, activeStream, nowUs()));
		flushPackets();
	}

	void finishStream(ServerConn& active)
	{
		check(Abi::streamFinish(engine, active.conn, active.stream, nowUs()));
		flushPackets();
	}

	void finishStream(GenericServerStream& active)
	{
		if (active.finSent)
		{
			return;
		}
		check(Abi::streamFinish(engine, active.conn, active.stream, nowUs()));
		active.finSent = true;
		flushPackets();
	}

	void recvExact(uint8_t *data, size_t length)
	{
		size_t offset = 0;
		while (offset < length)
		{
			auto [read, fin] = recvSome(stream, data + offset, length - offset);
			if (read == 0)
			{
				if (fin)
				{
					fprintf(stderr, "%s stream ended before expected bytes\n", Abi::label);
					abort();
				}
				pumpOnce();
			}
			else
			{
				offset += read;
			}
		}
	}

	void recvTerminalUploadAck(uint8_t *data, size_t length)
	{
		size_t offset = 0;
		while (offset < length)
		{
			size_t read = 0;
			bool fin = false;
			bool streamValid = recvSomeAllowInvalidStream(stream, data + offset, length - offset, read, fin);
			if (!streamValid)
			{
				return;
			}
			if (read == 0)
			{
				if (fin)
				{
					return;
				}
				pumpOnce();
			}
			else
			{
				offset += read;
			}
		}
	}

	void sendBytes(uint64_t bytes)
	{
		while (bytes > 0)
		{
			size_t chunk = static_cast<size_t>(std::min<uint64_t>(bytes, buffer.size()));
			sendAll(buffer.data(), chunk);
			bytes -= chunk;
		}
	}

	void recvBytes(uint64_t bytes)
	{
		while (bytes > 0)
		{
			size_t chunk = static_cast<size_t>(std::min<uint64_t>(bytes, buffer.size()));
			recvExact(buffer.data(), chunk);
			bytes -= chunk;
		}
	}

	bool processServer(ServerConn& active)
	{
		switch (active.phase)
		{
			case ServerPhase::acceptStream:
			{
				int result = Abi::acceptBidi(engine, active.conn, &active.stream, nowUs());
				check(result);
				if (result == 1)
				{
					active.phase = ServerPhase::readRequest;
					return true;
				}
				return false;
			}
			case ServerPhase::readRequest:
			{
				auto [read, fin] = recvSome(active, active.request.data() + active.requestRead, active.request.size() - active.requestRead);
				(void)fin;
				active.requestRead += read;
				if (active.requestRead == active.request.size())
				{
					active.bytesRemaining = decodeU64(active.request.data());
					active.phase = ServerPhase::transfer;
				}
				return read > 0;
			}
			case ServerPhase::transfer:
			{
				if (active.bytesRemaining == 0)
				{
					active.phase = ServerPhase::readDone;
					return true;
				}
				size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.bytesRemaining, buffer.size()));
				if (benchmarkIsUpload())
				{
					auto [read, fin] = recvSome(active, buffer.data(), chunk);
					(void)fin;
					active.bytesRemaining -= read;
					return read > 0;
				}
				size_t written = sendSome(active, buffer.data(), chunk);
				active.bytesRemaining -= written;
				return written > 0;
			}
			case ServerPhase::readDone:
			{
				auto [read, fin] = recvSome(active, &active.done + active.doneRead, sizeof(active.done) - active.doneRead);
				(void)fin;
				active.doneRead += read;
				if (active.doneRead == sizeof(active.done))
				{
					active.phase = ServerPhase::sendAck;
				}
				return read > 0;
			}
			case ServerPhase::sendAck:
			{
				size_t written = sendSome(active, &active.ack + active.ackSent, sizeof(active.ack) - active.ackSent);
				active.ackSent += written;
				if (active.ackSent == sizeof(active.ack))
				{
					active.phase = ServerPhase::finish;
				}
				return written > 0;
			}
			case ServerPhase::finish:
			{
				check(Abi::streamFinish(engine, active.conn, active.stream, nowUs()));
				flushPackets();
				active.phase = ServerPhase::complete;
				return true;
			}
			case ServerPhase::complete:
				return false;
		}
		return false;
	}

	void runServerConnections(void)
	{
		std::vector<ServerConn> conns;
		conns.reserve(benchmarkServerTargetConnections);
		uint32_t completed = 0;
		while (completed < benchmarkServerTargetConnections)
		{
			bool progressed = false;
			while (conns.size() < benchmarkServerTargetConnections)
			{
				uint64_t accepted = UINT64_MAX;
				int result = Abi::acceptConnection(engine, &accepted);
				check(result);
				if (result != 1)
				{
					break;
				}
				conns.push_back(ServerConn{.conn = accepted});
				progressed = true;
			}

			completed = 0;
			for (ServerConn& active : conns)
			{
				if (active.phase == ServerPhase::complete)
				{
					++completed;
					continue;
				}
				progressed = processServer(active) || progressed;
				if (active.phase == ServerPhase::complete)
				{
					++completed;
				}
			}

			if (!progressed)
			{
				pumpOnce();
			}
		}
		drainTerminalPackets(1000, 100);
	}

	void runClientDownload(uint64_t bytes)
	{
		uint8_t request[8];
		encodeU64(bytes, request);
		sendAll(request, sizeof(request));
		recvBytes(bytes);
		uint8_t done = 0;
		sendAll(&done, sizeof(done));
		uint8_t ack = 0;
		recvExact(&ack, sizeof(ack));
		check(Abi::streamFinish(engine, connection, stream, nowUs()));
		flushPackets();
	}

	void runClientUpload(uint64_t bytes)
	{
		uint8_t request[8];
		encodeU64(bytes, request);
		sendAll(request, sizeof(request));
		sendBytes(bytes);
		uint8_t done = 0;
		sendAll(&done, sizeof(done));
		uint8_t ack = 0;
		recvExact(&ack, sizeof(ack));
		check(Abi::streamFinish(engine, connection, stream, nowUs()));
		flushPackets();
	}

	uint64_t reqRespRequestSize(void) const
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

	uint64_t reqRespResponseSize(void) const
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

	bool runClientReqRespStream(GenericClientStream& active)
	{
		switch (active.phase)
		{
			case GenericPhase::readRequest:
			{
				while (active.requestBytesSent < active.requestBytesExpected)
				{
					size_t chunk = static_cast<size_t>(
						std::min<uint64_t>(active.requestBytesExpected - active.requestBytesSent, buffer.size()));
					size_t written = sendSome(active.stream, buffer.data(), chunk);
					if (written == 0)
					{
						return false;
					}
					active.requestBytesSent += written;
				}
				active.phase = GenericPhase::sendResponse;
				return true;
			}
			case GenericPhase::sendResponse:
			{
				if (active.responseRemaining == 0)
				{
					active.phase = GenericPhase::transfer;
					return true;
				}
				size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
				auto [read, fin] = recvSome(active.stream, buffer.data(), chunk);
				(void)fin;
				active.responseRemaining -= read;
				return read > 0;
			}
			case GenericPhase::transfer:
			{
				size_t written = sendSome(active.stream, &active.done + active.doneSent, sizeof(active.done) - active.doneSent);
				active.doneSent += written;
				if (active.doneSent == sizeof(active.done))
				{
					finishStream(active.stream);
					active.phase = GenericPhase::complete;
					return true;
				}
				return written > 0;
			}
			case GenericPhase::complete:
				return false;
			default:
				return false;
		}
	}

	void runClientReqRespLike(uint64_t operations)
	{
		std::vector<GenericClientStream> active;
		active.reserve(benchmarkScenarioStreamsInFlight);
		uint64_t opened = 0;
		uint64_t completed = 0;
		const uint64_t requestBytes = reqRespRequestSize();
		const uint64_t responseBytes = reqRespResponseSize();

		while (completed < operations)
		{
			while (opened < operations && active.size() < benchmarkScenarioStreamsInFlight)
			{
				active.push_back(GenericClientStream{
					.stream = openClientBidiStream(),
					.phase = GenericPhase::readRequest,
					.requestBytesExpected = requestBytes,
					.responseRemaining = responseBytes,
				});
				++opened;
			}

			bool progressed = false;
			for (auto& streamState : active)
			{
				if (streamState.phase == GenericPhase::complete)
				{
					continue;
				}
				progressed = runClientReqRespStream(streamState) || progressed;
			}

			active.erase(std::remove_if(active.begin(), active.end(), [&] (const GenericClientStream& streamState) {
				if (streamState.phase == GenericPhase::complete)
				{
					++completed;
					return true;
				}
				return false;
			}), active.end());

			if (!progressed)
			{
				pumpOnce();
			}
		}
	}

		bool processClientTransferStream(GenericClientStream& active)
		{
			switch (active.phase)
			{
			case GenericPhase::readRequest:
			{
				uint8_t request[8];
				encodeU64(active.requestValue, request);
				while (active.requestBytesSent < sizeof(request))
				{
					size_t written = sendSome(active.stream, request + active.requestBytesSent, sizeof(request) - active.requestBytesSent);
					if (written == 0)
					{
						return false;
					}
					active.requestBytesSent += written;
				}
				if (benchmarkScenario == BenchmarkScenario::multistream_upload)
				{
					active.phase = GenericPhase::transfer;
				}
				else
				{
					active.phase = GenericPhase::sendResponse;
				}
				return true;
			}
			case GenericPhase::transfer:
			{
				if (benchmarkScenario == BenchmarkScenario::multistream_download)
				{
					size_t written = sendSome(active.stream, &active.done + active.doneSent, sizeof(active.done) - active.doneSent);
					active.doneSent += written;
					if (active.doneSent == sizeof(active.done))
					{
						active.phase = GenericPhase::readAck;
						return true;
					}
					return written > 0;
				}
				if (active.payloadRemaining == 0)
				{
					if (benchmarkScenario == BenchmarkScenario::multistream_upload && !active.finSent)
					{
						finishStream(active.stream);
						active.finSent = true;
					}
					active.phase = GenericPhase::sendResponse;
					return true;
				}
				size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
				size_t written = sendSome(active.stream, buffer.data(), chunk);
				active.payloadRemaining -= written;
				return written > 0;
			}
			case GenericPhase::sendResponse:
				{
				if (active.responseRemaining == 0)
				{
					active.phase = GenericPhase::complete;
					return true;
				}
				size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
				size_t read = 0;
				bool fin = false;
				bool streamValid = recvSomeAllowInvalidStream(active.stream, buffer.data(), chunk, read, fin);
				if (!streamValid && benchmarkScenario == BenchmarkScenario::multistream_upload)
				{
					active.responseRemaining = 0;
					active.phase = GenericPhase::complete;
					return true;
				}
				active.responseRemaining -= read;
				if (active.responseRemaining == 0 || (fin && benchmarkScenario == BenchmarkScenario::multistream_upload))
				{
					active.responseRemaining = 0;
					if (benchmarkScenario == BenchmarkScenario::multistream_download)
					{
						active.phase = GenericPhase::transfer;
					}
					else if (benchmarkScenario == BenchmarkScenario::multistream_upload)
					{
						active.phase = GenericPhase::complete;
					}
					else
					{
						active.phase = GenericPhase::complete;
					}
				}
				return read > 0;
			}
			case GenericPhase::readAck:
			{
				size_t read = 0;
				bool fin = false;
				bool streamValid = recvSomeAllowInvalidStream(active.stream, &active.ack + active.ackRead, sizeof(active.ack) - active.ackRead, read, fin);
				active.ackRead += read;
				if (!streamValid || active.ackRead == sizeof(active.ack) || fin)
				{
					if (!active.finSent && streamValid)
					{
						finishStream(active.stream);
						active.finSent = true;
					}
					active.phase = GenericPhase::complete;
					return true;
				}
				return read > 0;
			}
			case GenericPhase::finish:
			{
				size_t written = sendSome(active.stream, &active.done + active.doneSent, sizeof(active.done) - active.doneSent);
				active.doneSent += written;
				if (active.doneSent == sizeof(active.done))
				{
					finishStream(active.stream);
					active.phase = GenericPhase::complete;
					return true;
				}
				return written > 0;
			}
			case GenericPhase::complete:
				return false;
			default:
				return false;
		}
	}

	void runClientMultistream(uint64_t bytes)
	{
		const uint64_t streamCount = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
		const uint64_t bytesPerStream = std::max<uint64_t>(1, bytes / streamCount);
		std::vector<GenericClientStream> active;
		active.reserve(streamCount);
		for (uint64_t i = 0; i < streamCount; ++i)
		{
			const uint64_t streamBytes = i + 1 == streamCount ? bytes - (bytesPerStream * (streamCount - 1)) : bytesPerStream;
			active.push_back(GenericClientStream{
				.stream = openClientBidiStream(),
				.phase = GenericPhase::readRequest,
				.requestValue = streamBytes,
				.payloadRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? streamBytes : 0,
				.responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : streamBytes,
			});
		}

			uint64_t completed = 0;
				uint64_t idleLoops = 0;
				uint64_t lastStallDumpUs = nowUs();
				while (completed < streamCount)
			{
				bool progressed = false;
				completed = 0;
			for (auto& streamState : active)
			{
				if (streamState.phase != GenericPhase::complete)
				{
					progressed = processClientTransferStream(streamState) || progressed;
				}
				if (streamState.phase == GenericPhase::complete)
				{
					++completed;
				}
				}
					if (!progressed)
					{
						++idleLoops;
						const uint64_t idleNowUs = nowUs();
						const bool dumpDebug = debugTrace && (idleLoops % 100000) == 0;
						const bool dumpStall = stallTrace && idleNowUs - lastStallDumpUs >= 1'000'000;
						if (dumpDebug || dumpStall)
						{
							lastStallDumpUs = idleNowUs;
							fprintf(stderr, "%s debug=client_bidi_idle loops=%" PRIu64 " completed=%" PRIu64 "/%" PRIu64,
								Abi::label, idleLoops, completed, streamCount);
						for (const auto& streamState : active)
						{
							fprintf(stderr, " stream=%" PRIu64 " phase=%s payload=%" PRIu64 " response=%" PRIu64 " doneSent=%zu",
								streamState.stream, genericPhaseName(streamState.phase), streamState.payloadRemaining,
								streamState.responseRemaining, streamState.doneSent);
							PacketStreamDebug streamDebug = {};
							if (Abi::streamDebug(engine, connection, streamState.stream, &streamDebug))
							{
								fprintf(stderr,
									" send=%" PRIu64 "/%" PRIu64 "/%" PRIu64 " swin=%" PRIu64 " cwin=%" PRIu64 " rtx=%" PRIu64
									" fin=%d/%d/%d hdata=%d hunacked=%d bif=%" PRIu64 " cwnd=%" PRIu64
									" recv=%" PRIu64 "/%" PRIu64 " chunks=%" PRIu64 " rfin=%d/%" PRIu64 "/%d",
									streamDebug.sendAckOffset, streamDebug.sendSendOffset, streamDebug.sendWriteOffset,
									streamDebug.sendWindow, streamDebug.connSendWindow,
									streamDebug.sendRetransmitCount,
									streamDebug.sendFinQueued ? 1 : 0, streamDebug.sendFinSent ? 1 : 0, streamDebug.sendFinLost ? 1 : 0,
									streamDebug.sendHasData ? 1 : 0, streamDebug.sendHasUnacked ? 1 : 0,
									streamDebug.bytesInFlight, streamDebug.cwnd,
									streamDebug.recvReadPos, streamDebug.recvHighestBuffered, streamDebug.recvChunkCount,
									streamDebug.recvFinKnown ? 1 : 0, streamDebug.recvFinOffset, streamDebug.recvFinished ? 1 : 0);
							}
						}
						fprintf(stderr, "\n");
					}
					pumpOnce();
				}
				else
				{
					idleLoops = 0;
				}
			}
		}

		bool processClientBidiStream(GenericClientStream& active)
		{
			if (active.phase == GenericPhase::readDone)
			{
				if (active.doneSent < sizeof(active.done))
				{
					size_t written = sendSome(active.stream, &active.done + active.doneSent, sizeof(active.done) - active.doneSent);
					active.doneSent += written;
					if (written == 0)
					{
						return false;
					}
				}
				active.phase = GenericPhase::readAck;
				return true;
			}
			if (active.phase == GenericPhase::readAck)
			{
				size_t read = 0;
				bool fin = false;
				bool streamValid = recvSomeAllowInvalidStream(active.stream, &active.ack + active.ackRead, sizeof(active.ack) - active.ackRead, read, fin);
				active.ackRead += read;
				if (!streamValid || active.ackRead == sizeof(active.ack) || fin)
				{
					if (!streamValid || (fin && active.ackRead == 0))
					{
						active.phase = GenericPhase::complete;
					}
					else
					{
						active.phase = GenericPhase::sendAck;
					}
					return true;
				}
				return read > 0;
			}
			if (active.phase == GenericPhase::sendAck)
			{
				size_t written = sendSome(active.stream, &active.ack + active.ackSent, sizeof(active.ack) - active.ackSent);
				active.ackSent += written;
				if (active.ackSent == sizeof(active.ack))
				{
					if (!active.finSent)
					{
						finishStream(active.stream);
						active.finSent = true;
					}
					active.phase = GenericPhase::complete;
					return true;
				}
				return written > 0;
			}

		bool progressed = false;
		if (active.requestBytesSent < sizeof(uint64_t))
		{
			uint8_t request[8];
			encodeU64(active.requestValue, request);
			size_t written = sendSome(active.stream, request + active.requestBytesSent, sizeof(request) - active.requestBytesSent);
			active.requestBytesSent += written;
			progressed = written > 0 || progressed;
			if (active.requestBytesSent < sizeof(request))
			{
				return progressed;
			}
		}
		if (active.payloadRemaining > 0)
		{
			size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
			size_t written = sendSome(active.stream, buffer.data(), chunk);
			active.payloadRemaining -= written;
			progressed = written > 0 || progressed;
		}
		if (active.responseRemaining > 0)
		{
			size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
			auto [read, fin] = recvSome(active.stream, buffer.data(), chunk);
			(void)fin;
			active.responseRemaining -= read;
			progressed = read > 0 || progressed;
		}
		if (active.payloadRemaining == 0 && active.responseRemaining == 0)
		{
			active.phase = GenericPhase::readDone;
			progressed = true;
		}
		return progressed;
	}

	void runClientBidi(uint64_t bytes)
	{
		const uint64_t streamCount = 1;
		const uint64_t bytesPerStream = std::max<uint64_t>(1, bytes / streamCount);
		std::vector<GenericClientStream> active;
		active.reserve(streamCount);
		for (uint64_t i = 0; i < streamCount; ++i)
		{
			const uint64_t streamBytes = i + 1 == streamCount ? bytes - (bytesPerStream * (streamCount - 1)) : bytesPerStream;
			active.push_back(GenericClientStream{
				.stream = openClientBidiStream(),
				.requestValue = streamBytes,
				.payloadRemaining = streamBytes,
				.responseRemaining = streamBytes,
			});
		}
		uint64_t completed = 0;
		uint64_t idleLoops = 0;
		uint64_t lastStallDumpUs = nowUs();
		while (completed < streamCount)
		{
			bool progressed = false;
			completed = 0;
			for (auto& streamState : active)
			{
				if (streamState.phase != GenericPhase::complete)
				{
					progressed = processClientBidiStream(streamState) || progressed;
				}
				if (streamState.phase == GenericPhase::complete)
				{
					++completed;
				}
			}
			const uint64_t loopNowUs = nowUs();
			if (stallTrace && loopNowUs - lastStallDumpUs >= 1'000'000)
			{
				lastStallDumpUs = loopNowUs;
				fprintf(stderr, "%s debug=client_bidi_loop completed=%" PRIu64 "/%" PRIu64 " progressed=%d",
					Abi::label, completed, streamCount, progressed ? 1 : 0);
				for (const auto& streamState : active)
				{
					fprintf(stderr, " stream=%" PRIu64 " phase=%s requestSent=%" PRIu64 " payload=%" PRIu64
						" response=%" PRIu64 " doneSent=%zu finSent=%d",
						streamState.stream, genericPhaseName(streamState.phase), streamState.requestBytesSent,
						streamState.payloadRemaining, streamState.responseRemaining, streamState.doneSent,
						streamState.finSent ? 1 : 0);
					PacketStreamDebug streamDebug = {};
					if (Abi::streamDebug(engine, connection, streamState.stream, &streamDebug))
					{
						fprintf(stderr,
							" send=%" PRIu64 "/%" PRIu64 "/%" PRIu64 " swin=%" PRIu64 " cwin=%" PRIu64 " rtx=%" PRIu64
							" fin=%d/%d/%d hdata=%d hunacked=%d bif=%" PRIu64 " cwnd=%" PRIu64
							" recv=%" PRIu64 "/%" PRIu64 " chunks=%" PRIu64 " rfin=%d/%" PRIu64 "/%d",
							streamDebug.sendAckOffset, streamDebug.sendSendOffset, streamDebug.sendWriteOffset,
							streamDebug.sendWindow, streamDebug.connSendWindow,
							streamDebug.sendRetransmitCount,
							streamDebug.sendFinQueued ? 1 : 0, streamDebug.sendFinSent ? 1 : 0, streamDebug.sendFinLost ? 1 : 0,
							streamDebug.sendHasData ? 1 : 0, streamDebug.sendHasUnacked ? 1 : 0,
							streamDebug.bytesInFlight, streamDebug.cwnd,
							streamDebug.recvReadPos, streamDebug.recvHighestBuffered, streamDebug.recvChunkCount,
							streamDebug.recvFinKnown ? 1 : 0, streamDebug.recvFinOffset, streamDebug.recvFinished ? 1 : 0);
					}
				}
				fprintf(stderr, "\n");
			}
			if (!progressed)
			{
				++idleLoops;
				if (debugTrace && (idleLoops % 100000) == 0)
				{
					fprintf(stderr, "%s debug=client_bidi_idle loops=%" PRIu64 " completed=%" PRIu64 "/%" PRIu64,
						Abi::label, idleLoops, completed, streamCount);
					for (const auto& streamState : active)
					{
						fprintf(stderr, " stream=%" PRIu64 " phase=%s requestSent=%" PRIu64 " payload=%" PRIu64
							" response=%" PRIu64 " doneSent=%zu finSent=%d",
							streamState.stream, genericPhaseName(streamState.phase), streamState.requestBytesSent,
							streamState.payloadRemaining, streamState.responseRemaining, streamState.doneSent,
							streamState.finSent ? 1 : 0);
					}
					fprintf(stderr, "\n");
				}
				pumpOnce();
			}
			else
			{
				idleLoops = 0;
			}
		}
	}

	void runClientDatagrams(uint64_t operations)
	{
		const size_t payloadSize = static_cast<size_t>(benchmarkScenarioMessageBytes);
		if (payloadSize == 0 || payloadSize > buffer.size())
		{
			fprintf(stderr, "%s invalid DATAGRAM payload size %zu\n", Abi::label, payloadSize);
			abort();
		}

		uint64_t sent = 0;
		uint64_t received = 0;
		const uint64_t maxInFlight = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
		const uint64_t maxAttempts = std::max<uint64_t>(
			4096ULL, operations + (std::max<uint64_t>(operations, maxInFlight) * 64ULL));
		while (received < operations)
		{
			bool progressed = false;
			if (sent >= maxAttempts && received < operations)
			{
				fprintf(stderr, "%s DATAGRAM delivery target not reached received=%" PRIu64 " sent=%" PRIu64 " target=%" PRIu64 "\n",
					Abi::label, received, sent, operations);
				abort();
			}
				// DATAGRAM echo is unreliable; cap outstanding messages instead of
				// adding a full burst every loop and overwhelming one slow path.
				while ((sent - received) < maxInFlight && sent < maxAttempts)
				{
					if (!sendDatagram(connection, buffer.data(), payloadSize))
					{
						break;
					}
					++sent;
				}

			size_t read = 0;
			while (recvDatagram(connection, buffer.data(), buffer.size(), read))
			{
				(void)read;
				++received;
				progressed = true;
				if (received >= operations)
				{
					break;
				}
			}

			if (!progressed)
			{
				pumpOnce();
			}
		}
		benchmarkRecordDatagramClientCounters(sent, received);
	}

	bool processGenericServerStream(GenericServerStream& active)
	{
		switch (active.phase)
		{
		case GenericPhase::readRequest:
		{
			if (benchmarkScenario == BenchmarkScenario::reqresp ||
			    benchmarkScenario == BenchmarkScenario::stream_churn ||
			    benchmarkScenario == BenchmarkScenario::small_payload_pps ||
			    benchmarkScenario == BenchmarkScenario::close_reset_cleanup)
			{
				if (active.requestBytesExpected == 0)
				{
					active.requestBytesExpected = reqRespRequestSize();
				}
				size_t chunk = static_cast<size_t>(std::min<uint64_t>(
					active.requestBytesExpected - active.requestBytesRead, buffer.size()));
				auto [read, fin] = recvSome(active, buffer.data(), chunk);
				(void)fin;
				active.requestBytesRead += read;
				if (active.requestBytesRead == active.requestBytesExpected)
				{
					active.responseRemaining = reqRespResponseSize();
					active.phase = GenericPhase::sendResponse;
				}
				return read > 0;
			}

			auto [read, fin] = recvSome(active, active.request.data() + active.requestBytesRead, active.request.size() - active.requestBytesRead);
			(void)fin;
			active.requestBytesRead += read;
			if (active.requestBytesRead == active.request.size())
			{
				active.requestValue = decodeU64(active.request.data());
				active.payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
					benchmarkScenario == BenchmarkScenario::bidi) ? active.requestValue : 0;
				active.responseRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload) ? 1 : active.requestValue;
				active.phase = benchmarkScenario == BenchmarkScenario::multistream_upload ? GenericPhase::transfer : GenericPhase::sendResponse;
			}
			return read > 0;
		}
			case GenericPhase::transfer:
			{
				if (active.payloadRemaining == 0)
				{
					active.phase = GenericPhase::sendResponse;
					return true;
				}
				size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
				auto [read, fin] = recvSome(active, buffer.data(), chunk);
				active.payloadRemaining -= read;
				if (benchmarkScenario == BenchmarkScenario::multistream_upload && fin)
				{
					active.payloadRemaining = 0;
					active.phase = GenericPhase::sendResponse;
				}
				return read > 0;
			}
		case GenericPhase::sendResponse:
		{
			bool progressed = false;
			if (benchmarkScenario == BenchmarkScenario::bidi && active.payloadRemaining > 0)
			{
				size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.payloadRemaining, buffer.size()));
				auto [read, fin] = recvSome(active, buffer.data(), chunk);
				active.payloadRemaining -= read;
				if (fin)
				{
					active.peerFinReceived = true;
				}
				progressed = read > 0 || progressed;
			}
			if (active.responseRemaining > 0)
			{
				size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.responseRemaining, buffer.size()));
				size_t written = sendSome(active, buffer.data(), chunk);
				active.responseRemaining -= written;
				progressed = written > 0 || progressed;
			}
				if (active.responseRemaining == 0 && active.payloadRemaining == 0)
				{
					if (benchmarkScenario == BenchmarkScenario::bidi)
					{
						active.phase = GenericPhase::readDone;
					}
					else
					{
						active.phase = benchmarkScenario == BenchmarkScenario::multistream_upload
							? GenericPhase::finish
							: GenericPhase::readDone;
					}
				}
				return progressed;
		}
		case GenericPhase::readDone:
		{
			if (active.peerFinReceived)
			{
				active.phase = (benchmarkScenario == BenchmarkScenario::bidi ||
					benchmarkScenario == BenchmarkScenario::multistream_download)
					? GenericPhase::sendAck
					: GenericPhase::finish;
				return true;
			}
			auto [read, fin] = recvSome(active, &active.done + active.doneRead, sizeof(active.done) - active.doneRead);
			active.doneRead += read;
			if (active.doneRead == sizeof(active.done) || fin)
			{
				active.phase = (benchmarkScenario == BenchmarkScenario::bidi ||
					benchmarkScenario == BenchmarkScenario::multistream_download)
					? GenericPhase::sendAck
					: GenericPhase::finish;
			}
			return read > 0 || fin;
		}
		case GenericPhase::sendAck:
		{
			size_t written = sendSome(active, &active.ack + active.ackSent, sizeof(active.ack) - active.ackSent);
			active.ackSent += written;
			if (active.ackSent == sizeof(active.ack))
			{
				if (benchmarkScenario == BenchmarkScenario::bidi)
				{
					if constexpr (Abi::is_zig)
					{
						active.phase = GenericPhase::finish;
					}
					else
					{
						active.phase = GenericPhase::readAck;
					}
				}
				else
				{
					active.phase = GenericPhase::finish;
				}
			}
			return written > 0;
		}
		case GenericPhase::readAck:
		{
			if (benchmarkScenario != BenchmarkScenario::bidi)
			{
				return false;
			}
			auto [read, fin] = recvSome(active, &active.ack + active.ackRead, sizeof(active.ack) - active.ackRead);
			active.ackRead += read;
			if (active.ackRead == sizeof(active.ack) || fin)
			{
				active.phase = GenericPhase::finish;
			}
			return read > 0 || fin;
		}
		case GenericPhase::finish:
			finishStream(active);
			active.phase = GenericPhase::complete;
			return true;
		case GenericPhase::complete:
			return false;
		}
		return false;
	}

	void runServerGenericStreams(void)
	{
		std::vector<uint64_t> conns;
		std::vector<GenericServerStream> streams;
		conns.reserve(benchmarkServerTargetConnections);
		const uint64_t streamsPerConn = benchmarkGenericStreamsPerConnection();
			const uint64_t targetStreams = static_cast<uint64_t>(benchmarkServerTargetConnections) * streamsPerConn;
				uint64_t idleLoops = 0;
				uint64_t lastStallDumpUs = nowUs();

				while (true)
			{
			bool progressed = false;
			while (conns.size() < benchmarkServerTargetConnections)
			{
				uint64_t accepted = UINT64_MAX;
				int result = Abi::acceptConnection(engine, &accepted);
				check(result);
				if (result != 1)
				{
					break;
				}
				conns.push_back(accepted);
				progressed = true;
			}
			for (uint64_t connId : conns)
			{
				while (streams.size() < targetStreams)
				{
					uint64_t acceptedStream = UINT64_MAX;
					int result = Abi::acceptBidi(engine, connId, &acceptedStream, nowUs());
					check(result);
					if (result != 1)
					{
						break;
					}
					streams.push_back(GenericServerStream{.conn = connId, .stream = acceptedStream});
					progressed = true;
				}
			}

			uint64_t completed = 0;
			for (auto& streamState : streams)
			{
				if (streamState.phase != GenericPhase::complete)
				{
					progressed = processGenericServerStream(streamState) || progressed;
				}
				if (streamState.phase == GenericPhase::complete)
				{
					++completed;
				}
			}
				if (completed >= targetStreams)
				{
					if constexpr (Abi::is_zig)
					{
						if (benchmarkScenario == BenchmarkScenario::bidi ||
						    benchmarkScenario == BenchmarkScenario::multistream_download)
						{
							// quic-zig can retain app-send state until terminal ACKs arrive. Once the
							// workload has exchanged its app-level terminal ack, do a bounded drain
							// instead of making server completion depend on late transport cleanup.
							drainTerminalPackets(1000, 2000);
							break;
						}
					}
				if (Abi::hasPendingAppData(engine))
				{
					pumpOnce(1000);
					continue;
				}
				drainTerminalPackets(1000, 100);
				break;
			}
					if (!progressed)
					{
						++idleLoops;
						const uint64_t idleNowUs = nowUs();
						const bool dumpDebug = debugTrace && (idleLoops % 100000) == 0;
						const bool dumpStall = stallTrace && idleNowUs - lastStallDumpUs >= 1'000'000;
						if (dumpDebug || dumpStall)
						{
							lastStallDumpUs = idleNowUs;
							fprintf(stderr, "%s debug=server_generic_idle loops=%" PRIu64 " conns=%zu streams=%zu completed=%" PRIu64 "/%" PRIu64,
								Abi::label, idleLoops, conns.size(), streams.size(), completed, targetStreams);
						for (const auto& streamState : streams)
						{
							fprintf(stderr, " stream=%" PRIu64 " phase=%s payload=%" PRIu64 " response=%" PRIu64 " doneRead=%zu",
								streamState.stream, genericPhaseName(streamState.phase), streamState.payloadRemaining,
								streamState.responseRemaining, streamState.doneRead);
							PacketStreamDebug streamDebug = {};
							if (Abi::streamDebug(engine, streamState.conn, streamState.stream, &streamDebug))
							{
								fprintf(stderr,
									" send=%" PRIu64 "/%" PRIu64 "/%" PRIu64 " swin=%" PRIu64 " cwin=%" PRIu64 " rtx=%" PRIu64
									" fin=%d/%d/%d hdata=%d hunacked=%d bif=%" PRIu64 " cwnd=%" PRIu64
									" recv=%" PRIu64 "/%" PRIu64 " chunks=%" PRIu64 " rfin=%d/%" PRIu64 "/%d",
									streamDebug.sendAckOffset, streamDebug.sendSendOffset, streamDebug.sendWriteOffset,
									streamDebug.sendWindow, streamDebug.connSendWindow,
									streamDebug.sendRetransmitCount,
									streamDebug.sendFinQueued ? 1 : 0, streamDebug.sendFinSent ? 1 : 0, streamDebug.sendFinLost ? 1 : 0,
									streamDebug.sendHasData ? 1 : 0, streamDebug.sendHasUnacked ? 1 : 0,
									streamDebug.bytesInFlight, streamDebug.cwnd,
									streamDebug.recvReadPos, streamDebug.recvHighestBuffered, streamDebug.recvChunkCount,
									streamDebug.recvFinKnown ? 1 : 0, streamDebug.recvFinOffset, streamDebug.recvFinished ? 1 : 0);
							}
						}
						fprintf(stderr, "\n");
					}
					pumpOnce();
				}
				else
				{
					idleLoops = 0;
				}
			}
		}

	void runServerDatagrams(void)
	{
		const size_t payloadSize = static_cast<size_t>(benchmarkScenarioMessageBytes);
		if (payloadSize == 0 || payloadSize > buffer.size())
		{
			fprintf(stderr, "%s invalid DATAGRAM payload size %zu\n", Abi::label, payloadSize);
			abort();
		}

			std::vector<DatagramServerConn> conns;
			conns.reserve(benchmarkServerTargetConnections);
			uint64_t drainDeadlineUs = 0;

			while (drainDeadlineUs == 0 || nowUs() < drainDeadlineUs)
			{
				bool progressed = false;
				while (conns.size() < benchmarkServerTargetConnections)
				{
					uint64_t accepted = UINT64_MAX;
					int result = Abi::acceptConnection(engine, &accepted);
					check(result);
				if (result != 1)
				{
					break;
					}
					conns.push_back(DatagramServerConn{.conn = accepted});
					progressed = true;
				}

				bool allConnectionsComplete = conns.size() >= benchmarkServerTargetConnections;
				for (DatagramServerConn& active : conns)
				{
					size_t read = 0;
					while (recvDatagram(active.conn, buffer.data(), buffer.size(), read))
					{
						(void)read;
						++active.received;
						// Echo every received DATAGRAM. A peer reaching its local
						// target is the only reliable completion signal in this row.
						++active.pendingEchoes;
						progressed = true;
					}

					while (active.pendingEchoes > 0)
					{
						if (!sendDatagram(active.conn, buffer.data(), payloadSize))
						{
							break;
						}
						--active.pendingEchoes;
						++active.echoed;
						progressed = true;
					}

					allConnectionsComplete = allConnectionsComplete &&
						active.echoed >= benchmarkScenarioOperations;
				}

				if (allConnectionsComplete && (drainDeadlineUs == 0 || progressed))
				{
					drainDeadlineUs = nowUs() + 100'000;
				}

				if (!progressed)
				{
					pumpOnce();
				}
		}
	}

	void runClientGenericScenario(uint64_t bytes)
	{
		switch (benchmarkScenario)
		{
			case BenchmarkScenario::reqresp:
				case BenchmarkScenario::stream_churn:
					case BenchmarkScenario::small_payload_pps:
					case BenchmarkScenario::close_reset_cleanup:
						runClientReqRespLike(benchmarkScenarioOperations);
						return;
					case BenchmarkScenario::multistream_download:
					case BenchmarkScenario::multistream_upload:
						runClientMultistream(bytes);
						return;
					case BenchmarkScenario::bidi:
						runClientBidi(bytes);
						return;
			default:
				return;
		}
	}

public:
	~PacketEngineLibrary()
	{
		if (engine != nullptr)
		{
			Abi::engineFree(engine);
			engine = nullptr;
		}
		delete networkHub;
	}

	void instanceSetup(uint16_t localPort, int argc, char *argv[])
	{
		(void)argc;
		(void)argv;
		std::fill(buffer.begin(), buffer.end(), 0x7);
			networkHub = new NetworkHub<mode>(localPort);
				debugTrace = std::getenv("QUICPERF_PACKET_DEBUG") != nullptr;
				stallTrace = std::getenv("QUICPERF_PACKET_STALL_DEBUG") != nullptr;

			typename Abi::config_t config = {};
		Abi::setLibrary(config, libraryKind);
		config.is_server = (mode & Mode::server) != 0;
		config.local_addr = packetAddrFromSockaddr(networkHub->socket.address());
		config.cert_path = tls_cert;
		config.key_path = tls_key;
		config.chain_path = tls_chain;
		config.tls_verify_peer = benchmarkTlsVerifyPeer();
		config.use_bbr = strcmp(benchmarkCongestionProfile, "none") != 0;
		config.connection_window = benchmarkConnectionWindow;
		config.stream_window = benchmarkStreamWindow;
		if constexpr (Abi::is_zig)
		{
			config.connection_window = std::min<uint64_t>(benchmarkConnectionWindow, benchmarkDefaultConnectionWindow);
			config.stream_window = std::min<uint64_t>(benchmarkStreamWindow, benchmarkDefaultStreamWindow);
		}
		config.max_bidi_streams = benchmarkMaxBidiStreams;
		config.max_uni_streams = benchmarkMaxUniStreams;
		config.idle_timeout_ms = benchmarkIdleTimeoutMs;
		config.udp_payload_size = benchmarkUdpPayloadSize;
			if constexpr (Abi::is_zig)
			{
				config.send_backlog_limit = config.stream_window;
				config.disable_pacing = true;
			}
		config.now_us = nowUs();
		engine = Abi::engineNew(&config);
		if (engine == nullptr)
		{
			const char *error = Abi::lastError();
			fprintf(stderr, "%s error: %s\n", Abi::label, error == nullptr ? "unknown" : error);
			abort();
		}
	}

	void connectToServer(struct sockaddr *address)
	{
		if constexpr (mode & Mode::client)
		{
			typename Abi::addr_t remote = packetAddrFromSockaddr(address);
			check(Abi::connect(engine, &remote, nowUs(), &connection));
			while (Abi::isConnected(engine, connection, nowUs()) != 1)
			{
				pumpOnce();
			}
		}
	}

	void openStream(void)
	{
		if constexpr (mode & Mode::client)
		{
			while (true)
			{
				int result = Abi::openBidi(engine, connection, &stream, nowUs());
				check(result);
				if (result == 1)
				{
					break;
				}
				pumpOnce();
			}
		}
	}

		void startPerfTest(uint64_t nBytes = 0)
	{
		if constexpr (mode & Mode::server)
		{
			if (benchmarkScenario == BenchmarkScenario::datagram)
			{
				runServerDatagrams();
			}
			else if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
			{
				runServerGenericStreams();
			}
			else
			{
				runServerConnections();
			}
		}
		else
		{
			if (benchmarkScenario == BenchmarkScenario::datagram)
			{
				runClientDatagrams(benchmarkScenarioOperations);
			}
			else if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
			{
				runClientGenericScenario(nBytes);
			}
			else if (benchmarkIsUpload())
			{
				runClientUpload(nBytes);
			}
			else
			{
				runClientDownload(nBytes);
			}
			}
		}

		void postPerfTest() override
		{
			if constexpr (mode & Mode::client)
			{
				if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
				{
					drainTerminalPackets(1000, 500);
				}
			}
		}
	};

#if defined(QUINNPERF) || defined(NOQPERF) || defined(NEQOPERF) || defined(S2NPERF)
template <Mode mode>
using Quinn = PacketEngineLibrary<mode, RustPacketAbi, QPF_LIBRARY_QUINN>;

template <Mode mode>
using Noq = PacketEngineLibrary<mode, RustPacketAbi, QPF_LIBRARY_NOQ>;

template <Mode mode>
using Neqo = PacketEngineLibrary<mode, RustPacketAbi, QPF_LIBRARY_NEQO>;

template <Mode mode>
using S2n = PacketEngineLibrary<mode, RustPacketAbi, QPF_LIBRARY_S2N>;
#endif

#if defined(QUICZIGPERF)
template <Mode mode>
using QuicZig = PacketEngineLibrary<mode, ZigPacketAbi>;
#endif
