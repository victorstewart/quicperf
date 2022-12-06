# *** will fix build errors + update all libraries to current versions soon ***

# quicperf

this project is meant to facilitate quic server performance research and to establish absolute benchmarks of performance amongst implementations.

#### **building**

     cd quicperf && cmake -S . -B build && cmake --build build
     
this will create a build folder in the project directory then download and compile all dependencies and finally compile and link the binaries (**lsperf**, **picoperf**, **quicheperf**, **ngtcp2perf**, **tcpperf**) and copy them into the project directory

#### **running**
     
first run a server instance, then run a client instance. the binaries follow the below pattern:
     
     ./binary mode (client or server) networking (iouring or syscall) serverIpAddress (any, loopback, or ipv6)
     
for example...
     
     ./picoperf server syscall loopback
     ./picoperf client syscall loopback
     
#### **results**

the client will print the results....

     root@clr-df9e289c0de04eb2a0cfc75803a0b93e~/quicperf # ./picoperf client syscall
     1.804000 seconds
     4.434590 Gb/s

     root@clr-df9e289c0de04eb2a0cfc75803a0b93e~/quicperf # ./picoperf client iouring
     2.012000 seconds
     3.976143 Gb/s

#### **current limitations**

1) Linux only
2) tcp+tls performance is 30% higher when letting boringssl manage the socket IO and BIOs than when doing so manually. suspect they might be avoiding copies. 
3) no GRO or GSO but will be added
