# quicperf

`quicperf` is a Linux loopback benchmark harness for comparing QUIC server
implementations under shared application workloads, shared TLS material, shared
socket backends, and a shared saturation policy.

It is for implementers and performance engineers who need like-for-like QUIC
measurements without each stack bringing its own benchmark loop.

- Methodology: [docs/methodology.md](docs/methodology.md)
- Current results: [docs/latest-results.md](docs/latest-results.md)

## Scenarios

| Scenario | Metric | Purpose |
|---|---|---|
| `download` | `throughput_gbps` | Server-to-client bulk transfer. |
| `upload` | `throughput_gbps` | Client-to-server bulk transfer. |
| `connect` | `connections_per_second` | Full handshake plus bidi stream creation. |
| `reqresp` | `requests_per_second` | Fresh-stream request/response lifecycle cost. |
| `stream_churn` | `streams_per_second` | Repeated stream open/send/receive/finish overhead. |
| `multistream_download` | `throughput_gbps` | Concurrent server-to-client streams on one connection. |
| `multistream_upload` | `throughput_gbps` | Concurrent client-to-server streams on one connection. |
| `bidi` | `throughput_gbps` | Simultaneous upload and download on one connection. |
| `small_payload_pps` | `messages_per_second` | Tiny-message packet/API overhead. |
| `loss_recovery` | `throughput_gbps` | Deterministic loss through `NetworkHub`. |
| `flow_control` | `throughput_gbps` | Small-window flow-control pressure. |
| `idle_footprint` | `server_rss_delta_bytes_per_connection` | Server RSS delta per held idle connection. |
| `close_reset_cleanup` | `streams_per_second` | Graceful fresh-stream cleanup cost. |
| `datagram` | `messages_per_second` | Capability row for app DATAGRAM echo. |
| `resumed_connect` | `connections_per_second` | Accepted CLI row; unsupported until session-ticket APIs are wired. |
| `zero_rtt_reqresp` | `requests_per_second` | Accepted CLI row; unsupported until 0-RTT APIs are wired. |

Unsupported capability rows exit cleanly as `unsupported` instead of running a
different workload under the requested label.

## Implementations

| Binary | Stack | Notes |
|---|---|---|
| `ngtcp2perf` | ngtcp2 | Native adapter |
| `lsperf` | LSQUIC | Native adapter |
| `tquicperf` | TQUIC | Native adapter |
| `quicheperf` | quiche | Native adapter |
| `picoperf` | picoquic | Native adapter |
| `xquicperf` | XQUIC | Native adapter |
| `quinnperf` | Quinn | Rust packet engine; C++ owns UDP I/O |
| `s2nperf` | s2n-quic | Rust packet engine; C++ owns UDP I/O |
| `neqoperf` | Neqo | Rust packet engine; C++ owns UDP I/O |
| `noqperf` | noq | Rust packet engine; C++ owns UDP I/O |
| `quiczigperf` | quic-zig | Zig packet engine; C++ owns UDP I/O |
| `mvfstperf` | mvfst | Folly/mvfst transport; C++ owns UDP I/O |
| `tcpperf` | TCP+TLS | Sidecar baseline only; excluded from QUIC result tables |

Packet-engine adapters use quicperf-maintained fork branches:

| Dependency | Branch |
|---|---|
| `victorstewart/quinn` | `quicperf-c-abi` |
| `victorstewart/s2n-quic` | `quicperf-c-abi` |
| `victorstewart/neqo` | `quicperf-c-abi` |
| `victorstewart/noq` | `quicperf-c-abi` |
| `victorstewart/quic-zig` | `quicperf-ed25519-tls` |

`mvfstperf` uses upstream mvfst/Fizz/Folly Depofiles.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel "$(nproc)"
```

Release builds use `-O3`, native CPU flags where available, and LTO by default.
Rust packet engines build in Cargo release mode with native CPU flags and LTO;
the Zig packet engine builds with `ReleaseFast`.

The build also runs `tools/audit-cpp-io-boundary.sh`, which rejects measured
adapter code that bypasses the shared C++ UDP I/O path.

## Run One Row

Server:

```sh
./build/bin/ngtcp2perf server syscall loopback download
```

Client:

```sh
./build/bin/ngtcp2perf client syscall loopback download
```

General form:

```text
./build/bin/<binary> <server|client> <syscall|iouring> <any|loopback|ipv6> [scenario]
```

`tcpperf` is syscall-only.

## Smoke

```sh
tools/run-mechanism-workload-smoke.sh
tools/run-high-value-workload-smoke.sh
tools/run-tls-verify-audit.sh
```

The first command smokes the all-primary mechanism rows. The second adds
capability rows and accepts only explicit unsupported capability gaps. The TLS
audit verifies the shared Ed25519 chain and wrong-chain negative controls.

## Publication

```sh
QUICPERF_ADAPTIVE_BLOCK_SIZE=5 \
QUICPERF_ADAPTIVE_MIN_BLOCKS=4 \
QUICPERF_ADAPTIVE_MIN_SAMPLES=20 \
QUICPERF_ADAPTIVE_CONFIRM_BLOCKS=2 \
QUICPERF_ADAPTIVE_MAX_SAMPLES=120 \
QUICPERF_ADAPTIVE_BOOTSTRAP_ITERS=5000 \
QUICPERF_TEST_BYTES=1073741824 \
tools/run-adaptive-publication-suite.py
```

The adaptive runner uses randomized discovery blocks, bounded convergence,
statistical saturation selection, and confirmatory holdout blocks. `not_ready`
rows are inspectable but not publishable clean result rows.

Important artifacts:

| File | Purpose |
|---|---|
| `adaptive-samples.tsv` | Raw sample source of truth |
| `row-stats.tsv` | Discovery, confirm, and combined row stats |
| `publication-results.tsv` | Selected result rows |
| `publication-curve.tsv` | Client-count curves |
| `publication-row-audit.tsv` | Gate audit for publication rows |
| `saturation-decisions.tsv` | Saturation decisions |

## Controls

Benchmark controls include one pinned userspace server thread, unpinned client
load workers, shared TLS 1.3 Ed25519 material, BBR-family congestion control
where exposed, common `syscall` and `iouring` UDP backends, and C++-owned UDP
I/O for Rust, Zig, and mvfst adapters.

See [docs/methodology.md](docs/methodology.md) for gates, status meanings, and
row selection details.

## Results

Latest published results were collected on May 16, 2026.
Current artifacts and caveats are in [docs/latest-results.md](docs/latest-results.md).
The README intentionally does not duplicate the result table.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).
