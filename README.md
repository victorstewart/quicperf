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
| `datagram` | `datagrams_per_second` | Capability row for delivered app DATAGRAM echo rate. |
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

Packet-engine adapters use quicperf-maintained fork branches where upstream has
not yet absorbed the quicperf C ABI surface:

| Dependency | Branch |
|---|---|
| `victorstewart/quinn` | `quicperf-c-abi` |
| `victorstewart/s2n-quic` | `quicperf-c-abi` |
| `victorstewart/neqo` | `quicperf-c-abi` |
| `victorstewart/noq` | `quicperf-c-abi` |
| `endel/quic-zig` | `main` |

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

## Batch Runs

```sh
QUICPERF_TEST_BYTES=1073741824 \
QUICPERF_REPEAT=5 \
QUICPERF_SCENARIOS="download upload connect flow_control loss_recovery" \
QUICPERF_NETWORKS="syscall iouring" \
QUICPERF_PATH_PROFILES="loopback" \
tools/run-benchmarks.sh
```

Batch output is written under `.run/quicperf-<timestamp>/`.

The main summary file is:

```text
.run/quicperf-<timestamp>/summary.tsv
```

Each run also writes structured raw samples to:

```text
.run/quicperf-<timestamp>/raw-samples.tsv
```

Summary rows include `samples`, `min`, `p50`, `p90`, `p99`, and `max`.
`p50` is the central publication statistic. `p90` and `p99` are bad-tail
statistics: for throughput/rate metrics they use the low tail, and for
lower-is-better metrics they use the high tail.

`QUICPERF_NETWORKS` selects the socket backend (`syscall` or `iouring`).
`QUICPERF_PATH_PROFILES` selects the delivery path and defaults to `loopback`.
Namespace-backed WAN profiles run the client and server in separate network
namespaces through a router namespace with `tc netem` delay, jitter, loss,
queue, and rate shaping applied before the handshake:

```sh
tools/quicperf_network_path.py list
tools/quicperf_network_path.py show lte-good

QUICPERF_BINARIES=picoperf \
QUICPERF_SCENARIOS="download connect" \
QUICPERF_NETWORKS=syscall \
QUICPERF_PATH_PROFILES="dc-fabric-1ms lte-good 5g-sub6-good" \
tools/run-benchmarks.sh
```

Non-loopback path profiles require root or `CAP_NET_ADMIN`, `ip netns`, and
`tc`. The path setup also installs static IPv6 neighbor entries before shaping is
enabled, avoiding cold neighbor-discovery latency in per-sample namespaces. For
WAN throughput scenarios, default flow-control windows are promoted to a bounded
BDP-derived profile so congestion control sees the shaped bottleneck instead of
an artificial receive-window cap. The `flow_control` scenario keeps its
intentionally small windows unless explicitly overridden.

Validate the shaped path profiles before using them for publication rows:

```sh
tools/quicperf_network_validate.py --samples 10 --ping-count 100 --require-idle-host
```

The validator writes qdisc snapshots, expected BDP/queue metadata, ping
RTT/loss/jitter checks, and raw TCP/UDP baselines under
`.run/network-profile-validation-<utc>/`. See
`docs/network-profile-validation.md` for the profile audit, acceptance criteria,
and source basis.

Public cellular traces can be converted into selectable path profiles with
`tools/quicperf_cellular_profiles.py`. It directly supports UCC 5G, UCC 4G LTE,
and UMN 5Gophers walking-loop traces. Raw public archives stay in ignored
`.data/`; compact generated profile packs are loaded from `profiles/network/*.json`.

Loopback publication rows use CUBIC for every adapter and record the effective
controller in `adapter_features`/`congestion_controller` result columns. For
non-loopback WAN runs, `QUICPERF_CONGESTION_PROFILE=path-auto` selects `cubic`
on the 10G/0.5ms datacenter profile and current BBR elsewhere where the library
exposes BBR. `picoperf` also accepts picoquic-specific `dcubic`, `newreno`,
`prague`, or `c4` values for targeted controller A/B runs.
`path-auto` also enables picoquic's BDP/cwnd seed on non-loopback
path profiles when RTT and rate metadata are available, and applies that seed
immediately to the sender so 1 MiB fresh downloads do not spend most of the row
waiting for ACK-derived seed validation. `QUICPERF_PICOQUIC_PACKET_TRAIN=1`
enables picoquic packet-train mode, `QUICPERF_PICOQUIC_BDP_FRAME=0` disables
picoquic's BDP transport extension for A/B runs,
`QUICPERF_PICOQUIC_BDP_SEED=0` disables the path-derived seed, and
`QUICPERF_PICOQUIC_BDP_SEED_IMMEDIATE=0` disables immediate sender seeding. The
shared picoquic transfer waits for an
application-level completion exchange so lossy WAN rows cannot pass because the
server exited after enqueueing data that the client never received.

## Smoke

To smoke the ten all-primary production mechanism workloads across every
primary QUIC binary and both network backends:

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
statistical saturation selection, and confirmatory holdout blocks. It stops a
client-count curve at the first converged adjacent step that does not materially
improve p50, so a row that peaks at 1 client will stop after checking 2 clients
instead of continuing up the curve. `not_ready` rows are inspectable but not
publishable clean result rows because they still need runnable work.

Important artifacts:

| File | Purpose |
|---|---|
| `adaptive-samples.tsv` | Raw sample source of truth |
| `row-stats.tsv` | Discovery, confirm, and combined row stats |
| `publication-results.tsv` | Selected result rows |
| `publication-curve.tsv` | Client-count curves |
| `publication-row-audit.tsv` | Gate audit for publication rows |
| `saturation-decisions.tsv` | Saturation decisions |

## Scoring

The primary ranking is normalized within each like-for-like scenario, network
backend, path profile, and metric group.

```text
score = 100 * (0.60 * capacity_index
             + 0.25 * curve_efficiency
             + 0.15 * client_count_efficiency)
```

- `capacity_index`: selected row p50 versus the best comparable p50
- `curve_efficiency`: normalized p50 across the client-count curve through saturation
- `client_count_efficiency`: reward for saturating with fewer load-generator clients

The composite score is a summary, not a replacement for raw `p50`, bad-tail
`p90`/`p99`, confidence interval, spread, and saturation data. Adaptive
rankings also publish pairwise ties and rank bands; point ranks should not be
read as decisive when the intervals overlap. `p99` is visibility-only unless the
row has at least 300 measured samples.

## Controls

Benchmark controls include one pinned userspace server thread, unpinned client
load workers, shared TLS 1.3 Ed25519 material, loopback CUBIC for every adapter,
common `syscall` and `iouring` UDP backends, default UDP GSO/GRO on the
`iouring` path, and C++-owned UDP I/O for Rust, Zig, and mvfst adapters.

See [docs/methodology.md](docs/methodology.md) for gates, status meanings, and
row selection details.

## Results

Latest published results were collected on May 16, 2026.
Current artifacts and caveats are in [docs/latest-results.md](docs/latest-results.md).
The README intentionally does not duplicate the result table.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).
