# Benchmark Methodology

This document is the benchmark contract. `README.md` is the entry point;
`docs/latest-results.md` is the current result index.

## Implementations

Benchmarked QUIC binaries:

`ngtcp2perf`, `lsperf`, `tquicperf`, `quicheperf`, `picoperf`, `xquicperf`,
`quinnperf`, `s2nperf`, `neqoperf`, `noqperf`, `quiczigperf`, `mvfstperf`.

`tcpperf` is a TCP+TLS sidecar baseline and is excluded from QUIC result tables.

## Workloads

Default workloads:

| Scenario | Metric | Contract |
|---|---|---|
| `download` | `throughput_gbps` | 8-byte request, server-to-client bulk response. |
| `upload` | `throughput_gbps` | 8-byte request plus client-to-server bulk body. |
| `connect` | `connections_per_second` | Full handshake plus bidirectional stream creation. |
| `reqresp` | `requests_per_second` | Repeated fresh-stream request/response. |
| `stream_churn` | `streams_per_second` | Repeated stream open/send/receive/finish. |
| `multistream_download` | `throughput_gbps` | Concurrent server-to-client streams on one connection. |
| `multistream_upload` | `throughput_gbps` | Concurrent client-to-server streams on one connection. |
| `bidi` | `throughput_gbps` | Simultaneous upload and download on one connection. |
| `small_payload_pps` | `messages_per_second` | Repeated tiny messages. |
| `loss_recovery` | `throughput_gbps` | Download through deterministic `NetworkHub` loss. |
| `flow_control` | `throughput_gbps` | Download under small stream/connection windows. |
| `idle_footprint` | `server_rss_delta_bytes_per_connection` | Server RSS delta per held idle connection. |
| `close_reset_cleanup` | `streams_per_second` | Graceful fresh-stream FIN cleanup profile. |

Capability rows:

| Scenario | Metric | Status |
|---|---|---|
| `datagram` | `datagrams_per_second` | Delivered app DATAGRAM echo rate for `neqoperf`, `noqperf`, `quicheperf`, `quiczigperf`, `quinnperf`, and `s2nperf`; other adapters return `unsupported`. |
| `resumed_connect` | `connections_per_second` | Accepted CLI row; unsupported until session-ticket capture/replay is exposed uniformly. |
| `zero_rtt_reqresp` | `requests_per_second` | Accepted CLI row; unsupported until 0-RTT accepted/rejected controls are exposed uniformly. |

Unsupported rows exit with code `77` and write an explicit reason. They are not
silently remapped to another workload.

Current non-graceful close/reset subprofiles are not primary rows. They require
uniform RESET_STREAM, STOP_SENDING, CONNECTION_CLOSE, and abrupt-peer controls
before promotion.

### DATAGRAM Contract

`datagram` measures delivered application DATAGRAM echo rate. The client queues
DATAGRAMs up to the shared in-flight cap, flushes once, drains once, receives
echoed DATAGRAMs, and repeats until the operation count is reached. The server
uses the same cycle: drain once, queue echoes for the batch, then flush once.

The harness records sent, received, unreturned, delivery ratio, UDP packets,
send submit/syscall batches, receive polls, and DATAGRAMs per UDP packet. Rows
must pass the delivery-ratio gate before publication.

Packet-engine adapters must not flush or poll once per app DATAGRAM. C++ owns
the UDP socket, backend, batching, and timeout loop for DATAGRAM rows just like
the stream workloads.

## Output Schema

`tools/run-benchmarks.sh` writes:

- `summary.tsv`: one row per binary/scenario/network/client-thread/metric group
- `raw-samples.tsv`: one structured row per measured attempt
- `run-meta.tsv`: per-attempt status, logs, timing, and run labels

The adaptive publication runner appends raw rows to `adaptive-samples.tsv`.
Measured rows carry metric values; unsupported and failed rows carry status,
reason, and log metadata.

Summary columns include `samples`, `min`, `p50`, `p90`, `p99`, and `max`.
`p50` uses a true median and is the publication statistic. `p90` and `p99` are
visibility columns. `p99` is not claimable unless a row has at least 300 samples.

## Saturation

The adaptive runner normally searches client counts `1..32` with
`server_connections == client_threads`.

Selection rules:

- add a higher client count only after the current count has enough samples
- pick the lowest client count statistically within tolerance of the best p50
- default tolerance: `1%`
- default confidence: `95%`
- plateau requires two higher statistically non-improving client counts
- the selected row means fewest clients needed to saturate one server thread

Saturation status:

- `ready`: convergence, saturation probability, and plateau sentinels passed
- `edge`: highest tested client count might still be materially better
- `not_ready`: convergence or saturation gates failed
- `bounded`: a higher configured row failed or became unsupported
- `unsupported`: no configured row completed

Only `ready` rows are clean publishable rows.

## Publication Gates

Use `tools/run-adaptive-publication-suite.py` for publishable rows.

Default flow:

- randomized discovery blocks across active rows
- 5 measured samples per block
- minimum 4 discovery blocks and 20 discovery samples
- maximum 120 discovery samples unless overridden
- randomized confirmatory holdout after provisional convergence
- statistical saturation selection before publication
- terminal classification for persistent high variance or nonstationarity

Default gates:

| Gate | Default |
|---|---:|
| Bulk p50 CI relative width | <= 3% |
| Connect/request/lifecycle p50 CI relative width | <= 5% |
| Impaired-network p50 CI relative width | <= 8% |
| p20/p80 middle-spread ratio | <= 1.15 |
| Block-median ratio | <= 1.10 |
| Absolute drift | <= 3% |
| Saturation confidence | >= 95% |
| Plateau sentinels | 2 |

Severe high-variance classification can stop rows after at least 6 discovery
blocks and 30 samples when they are far outside stability gates. Persistent
high variance can stop rows after at least 8 blocks and 40 samples without
material improvement.

`publication-results.tsv` is the selected-row table. `publication-curve.tsv`
keeps the 1-client row and measured curve through saturation or boundary.
`publication-row-audit.tsv` preserves gate results for publication rows.

A `not_ready` run can be shared only with status, CI, spread, and caveats
visible. Do not present it as an audited result.

`tools/run-publication-suite.py` delegates to the adaptive runner by default.
The old fixed `3 x 10` runner is only a compatibility smoke path:
`QUICPERF_FIXED_PUBLICATION_COMPAT=1`.

## Controls

- one pinned userspace server thread
- unpinned client workers used only for load generation
- hidden userspace helper threads blocked after configured workers exist
- kernel io_uring workers reported separately
- shared TLS 1.3 Ed25519 certificate/key/chain by default
- verified TLS requires `tools/run-tls-verify-audit.sh`
- BBR-family congestion control where the library exposes it
- shared window, stream-limit, and workload profiles where APIs permit
- server app-level completion before client/server exit
- true per-connection/per-stream server state for multi-client rows
- fresh random loopback port blocks by default

P-256 is still selectable with explicit `QUICPERF_TLS_CERT`,
`QUICPERF_TLS_KEY`, `QUICPERF_TLS_CHAIN`, and
`QUICPERF_TLS_CERT_PROFILE=p256`.

## Backend Rules

- `syscall`: shared traditional UDP socket path
- `iouring`: shared Linux io_uring UDP path with registered socket fd, larger
  CQ, taskrun flags, provided buffers, and multishot `recvmsg`
- C++ owns socket creation, receive, send, batching, backend selection, and
  timeout scheduling for measured adapters
- `tools/audit-cpp-io-boundary.sh` is part of the build graph
- `tcpperf` remains syscall-only
- UDP GSO/GRO, SQPOLL, NAPI busy polling, and zerocopy receive are outside the
  default apples-to-apples rows
