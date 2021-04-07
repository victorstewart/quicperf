#include <linux/tcp.h>
#include <unistd.h>
#include <stdlib.h>

#pragma once

#define SOL_TCP IPPROTO_TCP

template <Mode mode>
class NetworkHub
{

};

class TCPSocket {
public:

	struct sockaddr_in6 *address6;
   socklen_t addressLen;
   int fd;
   
   TCPSocket(uint16_t port)
   {
      fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

   	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const uint32_t[]){ 1'000 * 1500 }, sizeof(uint32_t));
   	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const uint32_t[]){ 1'000 * 1500 }, sizeof(uint32_t));

   	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const int[]){ 1 }, sizeof(int));
   	setsockopt(fd, SOL_TCP, TCP_NODELAY, (const int[]){ 1 }, sizeof(int));

   	addressLen = sizeof(struct sockaddr_in6);

   	address6 = (struct sockaddr_in6 *)calloc(1, addressLen);
	   address6->sin6_family = AF_INET6;
	   address6->sin6_flowinfo = 0;
	   address6->sin6_port = htons(port);
	   address6->sin6_addr = serverAddress;

      bind(fd, (struct sockaddr *)address6, addressLen);
    }
};

template <Mode mode>
class TCPTLS : public QuicLibrary<mode> { 
private:
	
	TCPSocket *socket;
	SSL *ssl;
	BIO *rbio;
	BIO *wbio;

	static constexpr uint32_t bufferBase = 16 * 1500;

	uint8_t wBuffer[bufferBase];
	uint8_t rBuffer[bufferBase * 2];
	uint8_t buffer[bufferBase * 8];

	// static int boringSSLPrintError(const char *str, size_t len, void *ctx)
	// {
	// 	printf("boringSSLPrintError -> %.*s\n", len ,str);
	// 	return 1;
	// }

	int write(int byteCount)
	{
		int bytesSent = SSL_write(ssl, wBuffer, byteCount);
		// BIO_read always fully consumes the rbio with these buffer sizes
		send(socket->fd, buffer, BIO_read(rbio, buffer, sizeof(buffer)), 0);

		return bytesSent;
	}

	int read(void)
	{
		int bytesRead = 0;
		int result;

		result = recv(socket->fd, rBuffer, sizeof(rBuffer), 0);
		
		if (result > 0)
		{
			result = BIO_write(wbio, rBuffer, result);

			while (BIO_ctrl_pending(wbio) > 0)
			{
				result = SSL_read(ssl, buffer, sizeof(buffer));
				if (result > 0) bytesRead += result;
			}
		}

		return bytesRead;
	}

public:

	void instanceSetup(uint16_t localPort, int argc, char *argv[])
	{
		socket = new TCPSocket(localPort);

		ssl = SSL_new(TLS::getTLSCtx());

		rbio = BIO_new(BIO_s_mem());
	 	wbio = BIO_new(BIO_s_mem());

	 	BIO_set_mem_eof_return(rbio, -1);
		BIO_set_mem_eof_return(wbio, -1);

		SSL_set_bio(ssl, wbio, rbio);

		if constexpr (mode & Mode::server)
		{
			SSL_set_accept_state(ssl);
			listen(socket->fd, SOMAXCONN);
		}
		else
		{
			SSL_set_connect_state(ssl);
		}
	}

	void connectToServer(struct sockaddr *address)
	{
		// establish TCP connection
		connect(socket->fd, address, sizeof(struct sockaddr_in6));
	}

	void openStream(void)
	{
		// establish TLS connection

		write(0);
		read();
		write(0);
		sleep(1);
	}

	void startPerfTest(uint64_t nBytes)
	{
		if constexpr (mode & Mode::client)
		{
			uint64_t bytesInFlight = nBytes;

			*(uint64_t *)wBuffer = nBytes;
			write(8);

			int result;

			do
			{
				result = read();
				if (result > 0) bytesInFlight -= result;

			} while (bytesInFlight > 0);
		}
		else
		{
		// establish TCP connection
			int peerfd = accept(socket->fd, NULL, NULL);

			// hack for now lol.
			socket->fd = peerfd;

		// establish TLS connection

			read();
			write(0);
			read();

		// wait for bytes in flight

			read();
			uint64_t bytesToSend = *(uint64_t *)buffer;

		// send that many bytes

			int result;

			do
			{
				result = write(sizeof(wBuffer) > bytesToSend ? bytesToSend : sizeof(wBuffer));
				if (result > 0) bytesToSend -= result;

			} while (bytesToSend > 0);
		}
	}
};