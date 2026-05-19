#include <linux/tcp.h>
#include <openssl/rand.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <vector>

#pragma once

#define SOL_TCP IPPROTO_TCP

template <Mode mode>
class NetworkHub {
};

static void tuneTcpSocket(int fd)
{
  uint32_t socketWindow = static_cast<uint32_t>(benchmarkConnectionWindow);
  setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &socketWindow, sizeof(socketWindow));
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &socketWindow, sizeof(socketWindow));
  benchmarkRecordSocketBuffers(fd);

  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
  setsockopt(fd, SOL_TCP, TCP_QUICKACK, &one, sizeof(one));

  const char *cc = benchmarkCongestionProfileUsesCubic() ? "cubic" : "bbr";
  setsockopt(fd, SOL_TCP, TCP_CONGESTION, cc, strlen(cc) + 1);
}

static void failSyscall(const char *operation)
{
  fprintf(stderr, "%s failed: errno=%d\n", operation, errno);
  assert(0);
  abort();
}

class TCPSocket {
public:

  struct sockaddr_in6 *address6;
  socklen_t addressLen;
  int fd;

  TCPSocket(uint16_t port)
  {
    fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
    {
      failSyscall("socket");
    }

    tuneTcpSocket(fd);

    addressLen = sizeof(struct sockaddr_in6);

    address6 = (struct sockaddr_in6 *)calloc(1, addressLen);
    address6->sin6_family = AF_INET6;
    address6->sin6_flowinfo = 0;
    address6->sin6_port = htons(port);
    address6->sin6_addr = localAddress;

    if (bind(fd, (struct sockaddr *)address6, addressLen) != 0)
    {
      failSyscall("bind");
    }
  }
};

template <Mode mode>
class TCPTLS : public QuicLibrary<mode> {
private:

  TCPSocket *socket = nullptr;
  SSL *ssl = nullptr;

  alignas(64) uint8_t sendBuffer[benchmarkTcpTlsBufferSize];
  alignas(64) uint8_t recvBuffer[benchmarkTcpTlsBufferSize];

  static void failSsl(SSL *ssl, int result, const char *operation)
  {
    int error = SSL_get_error(ssl, result);
    fprintf(stderr, "%s failed: ssl_error=%d errno=%d\n", operation, error, errno);
    TLS::printErrorsIfAny();
    assert(0);
    abort();
  }

  SSL *newSsl(void)
  {
    SSL *active = SSL_new(TLS::getTLSCtx());
    if (active == nullptr)
    {
      fprintf(stderr, "SSL_new failed\n");
      TLS::printErrorsIfAny();
      assert(active != nullptr);
      abort();
    }
    SSL_set_mode(active, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return active;
  }

  void writeAll(SSL *active, const uint8_t *data, size_t length)
  {
    size_t offset = 0;
    while (offset < length)
    {
      size_t chunk = std::min<size_t>(length - offset, static_cast<size_t>(INT_MAX));
      int result = SSL_write(active, data + offset, static_cast<int>(chunk));
      if (result > 0)
      {
        offset += static_cast<size_t>(result);
        continue;
      }

      int error = SSL_get_error(active, result);
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
      {
        continue;
      }

      failSsl(active, result, "SSL_write");
    }
  }

  void writeAll(const uint8_t *data, size_t length)
  {
    writeAll(ssl, data, length);
  }

  size_t readSome(SSL *active, uint8_t *data, size_t capacity)
  {
    for (;;)
    {
      int result = SSL_read(active, data, static_cast<int>(std::min<size_t>(capacity, static_cast<size_t>(INT_MAX))));
      if (result > 0)
      {
        return static_cast<size_t>(result);
      }

      int error = SSL_get_error(active, result);
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
      {
        continue;
      }

      failSsl(active, result, "SSL_read");
    }
  }

  size_t readSome(uint8_t *data, size_t capacity)
  {
    return readSome(ssl, data, capacity);
  }

  void readExact(SSL *active, uint8_t *data, size_t length)
  {
    size_t offset = 0;
    while (offset < length)
    {
      offset += readSome(active, data + offset, length - offset);
    }
  }

  void readExact(uint8_t *data, size_t length)
  {
    readExact(ssl, data, length);
  }

  void finishHandshakeClient(void)
  {
    for (;;)
    {
      int result = SSL_connect(ssl);
      if (result == 1)
      {
        return;
      }

      int error = SSL_get_error(ssl, result);
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
      {
        continue;
      }

      failSsl(ssl, result, "SSL_connect");
    }
  }

  void finishHandshakeServer(SSL *active)
  {
    for (;;)
    {
      int result = SSL_accept(active);
      if (result == 1)
      {
        return;
      }

      int error = SSL_get_error(active, result);
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
      {
        continue;
      }

      failSsl(active, result, "SSL_accept");
    }
  }

  SSL *acceptClient(void)
  {
    int peerfd = accept(socket->fd, NULL, NULL);
    if (peerfd < 0)
    {
      failSyscall("accept");
    }
    tuneTcpSocket(peerfd);

    SSL *peer = newSsl();
    SSL_set_accept_state(peer);
    SSL_set_fd(peer, peerfd);
    finishHandshakeServer(peer);
    return peer;
  }

  void runServerConnection(SSL *peer)
  {
    uint64_t request = 0;
    readExact(peer, reinterpret_cast<uint8_t *>(&request), sizeof(request));
    uint64_t bytesToSend = bswap_64(request);

    if (benchmarkIsUpload())
    {
      while (bytesToSend > 0)
      {
        size_t bytesRead = readSome(peer, recvBuffer, sizeof(recvBuffer));
        bytesToSend -= std::min<uint64_t>(bytesToSend, bytesRead);
      }
      uint8_t ack = 0;
      writeAll(peer, &ack, sizeof(ack));
      return;
    }

    while (bytesToSend > 0)
    {
      size_t sendLength = std::min<uint64_t>(bytesToSend, sizeof(sendBuffer));
      writeAll(peer, sendBuffer, sendLength);
      bytesToSend -= sendLength;
    }
  }

  void runServerConnections(void)
  {
    std::vector<SSL *> peers;
    peers.reserve(benchmarkServerTargetConnections);
    for (uint32_t i = 0; i < benchmarkServerTargetConnections; ++i)
    {
      peers.push_back(acceptClient());
    }

    for (SSL *peer : peers)
    {
      runServerConnection(peer);
      SSL_shutdown(peer);
      SSL_free(peer);
    }
  }

public:

  void instanceSetup(uint16_t localPort, int argc, char *argv[])
  {
    signal(SIGPIPE, SIG_IGN);

    socket = new TCPSocket(localPort);

    RAND_bytes(sendBuffer, sizeof(sendBuffer));

    if constexpr (mode & Mode::server)
    {
      if (listen(socket->fd, SOMAXCONN) != 0)
      {
        failSyscall("listen");
      }
    }
    else
    {
      ssl = newSsl();
      SSL_set_connect_state(ssl);
    }
  }

  void connectToServer(struct sockaddr *address)
  {
    if (connect(socket->fd, address, sizeof(struct sockaddr_in6)) != 0)
    {
      failSyscall("connect");
    }
    tuneTcpSocket(socket->fd);
    SSL_set_fd(ssl, socket->fd);
  }

  void openStream(void)
  {
    if constexpr (mode & Mode::client)
    {
      finishHandshakeClient();
    }
  }

  void startPerfTest(uint64_t nBytes)
  {
    if constexpr (mode & Mode::client)
    {
      uint64_t bytesRemaining = nBytes;
      uint64_t request = bswap_64(nBytes);

      writeAll(reinterpret_cast<uint8_t *>(&request), sizeof(request));

      if (benchmarkIsUpload())
      {
        while (bytesRemaining > 0)
        {
          size_t sendLength = std::min<uint64_t>(bytesRemaining, sizeof(sendBuffer));
          writeAll(sendBuffer, sendLength);
          bytesRemaining -= sendLength;
        }
        uint8_t ack = 0;
        readExact(&ack, sizeof(ack));
        return;
      }

      while (bytesRemaining > 0)
      {
        size_t bytesRead = readSome(recvBuffer, sizeof(recvBuffer));
        bytesRemaining -= std::min<uint64_t>(bytesRemaining, bytesRead);
      }
    }
    else
    {
      runServerConnections();
    }
  }
};
