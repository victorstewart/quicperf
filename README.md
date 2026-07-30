# quicperf

quicperf is a Linux benchmark for publication-grade, fixed-treatment comparison
of QUIC servers through one shared C++ packet-I/O, timing, workload, resource,
and measurement contract.

The [qualified V2.3 results](docs/latest-results.md) contain 4,320/4,320 valid
trials across 12 servers and 15 scenarios. There is no global leaderboard:
results are scenario-specific, simultaneous, and conditional on the exact host
and treatment. Their canonical terminal status is `publication_qualified`.

## Primary estimand

V2.3 estimates fixed-treatment server performance with:

- one isolated server physical core;
- four isolated reference-client physical cores;
- exactly 16 active connections;
- an equal 50/50 `ngtcp2perf`/`picoperf` reference-client mixture;
- the common C++ `iouring` UDP backend for every server and client;
- two independently started sessions and 24 paired rows per retained family.

It does not estimate maximum capacity, memory scaling, long-tail latency,
syscall-backend performance, or same-stack client/server performance. The
`syscall` backend and `tools/run-benchmarks.sh` remain developer diagnostics;
they cannot create publication evidence.

## Implementations and scenarios

The frozen servers are `ngtcp2perf`, `lsperf`, `tquicperf`, `quicheperf`,
`picoperf`, `xquicperf`, `quinnperf`, `s2nperf`, `neqoperf`, `noqperf`,
`quiczigperf`, and `mvfstperf`.

The frozen scenarios are download, upload, multistream download, multistream
upload, bidirectional transfer, small-payload packet rate, DATAGRAM,
request/response, stream churn, connect, resumed connect, 0-RTT
request/response, deterministic loss recovery, bounded flow control, and
close/reset cleanup.

All measured UDP sockets, batching, GSO/GRO, loss injection, timers, and event
loops are owned by the common C++ core. Rust and Zig transports are packet
engines behind the same borrowed-buffer boundary. `tcpperf` is a diagnostic
TCP+TLS sidecar, not a QUIC result row.

## Build

Prerequisites are a recent Clang or GCC toolchain, CMake, Git, Python 3,
Rust/Cargo, Zig, Depo, Linux io_uring headers, and the pinned dependency
toolchains declared by the repository.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel "$(nproc)"
ctest --test-dir build --output-on-failure
python3 -m unittest discover -s tests -p 'test_*.py'
```

Publication builds additionally require the native release flags and exact
binary/dependency identities attested by the campaign manifest.

## Canonical publication workflow

Publication requires a dedicated qualified Linux host. The transactional
launcher reports any boot isolation work, requests permission before temporary
host-policy changes, and restores only the settings it changed.

```sh
tools/run-publication-host -- \
  tools/quicperfctl doctor --profile profiles/v2.3/publication.json

tools/run-publication-host -- \
  tools/quicperfctl suite run --out .run/publication-v2.3
```

The suite performs exact-identity interoperability, host-stability and
four-client-core headroom admission, two resumable primary sessions, analysis,
finalization, export, and checksums. Resume after interruption with:

```sh
tools/run-publication-host -- \
  tools/quicperfctl suite resume --suite-dir .run/publication-v2.3
```

A missing physical gate is `NOT_RUN`, never a pass. A gate or deadline failure
ends nonpublication with no diagnostic fallback. See the
[operator guide](docs/harness-v2.md) before running.

## Documentation and data

- [Latest qualified results](docs/latest-results.md)
- [V2.3 scientific contract](docs/methodology.md)
- [Operator guide](docs/harness-v2.md)
- [V2.3 migration and hard cutover](docs/migration-v2.3.md)
- [Schemas and control protocol](schemas/README.md)
- [Citation metadata](CITATION.cff)
- [Data license](DATA-LICENSE)

Code is Apache-2.0. Benchmark data is CC BY 4.0. Committed TLS private keys are
public test fixtures and are unsafe for production; see [tls/README.md](tls/README.md).
