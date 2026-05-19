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
| `datagram` | `datagrams_per_second` | Delivered app DATAGRAM echo rate for `lsperf`, `mvfstperf`, `neqoperf`, `ngtcp2perf`, `noqperf`, `picoperf`, `quicheperf`, `quiczigperf`, `quinnperf`, `s2nperf`, and `xquicperf`; other adapters return `unsupported` until the quicperf adapter exposes the same contract. |
| `resumed_connect` | `connections_per_second` | Accepted CLI row; unsupported until session-ticket capture/replay is exposed uniformly. |
| `zero_rtt_reqresp` | `requests_per_second` | Accepted CLI row; unsupported until 0-RTT accepted/rejected controls are exposed uniformly. |

Unsupported rows exit with code `77` and write an explicit reason. They are not
silently remapped to another workload, and they are quicperf adapter-contract
markers rather than upstream library feature claims.

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

`tquicperf` remains unsupported for this row because the current local TQUIC C
header exposes UDP datagram and PMTU controls, but no application QUIC DATAGRAM
send/read API that matches this contract.

## Output Schema

Current metrics are `throughput_gbps`, `connections_per_second`, `requests_per_second`,
`streams_per_second`, `messages_per_second`, and `idle_connections`. Publication scoring only
normalizes within the same scenario, network backend, path profile, and metric group.

`tools/run-benchmarks.sh` writes one `summary.tsv` row per
binary/library/scenario/network/path-profile/client-thread/metric group and writes
`raw-samples.tsv` for every invocation. When invoked by the adaptive publication
runner it appends the same structured rows to `adaptive-samples.tsv`: measured
rows carry metric values, while unsupported, failed, and thread-check rows carry
status/reason/log metadata with a blank value.

`network` is the socket backend dimension (`syscall` or `iouring`). `path_profile`
is the packet-delivery path dimension. The default is `loopback`; namespace-backed
profiles such as `dc-fabric-1ms`, `lte-good`, and `5g-sub6-good` run through a
router namespace with `tc netem` shaping for RTT, jitter, loss, queue depth, and
uplink/downlink rate. The runner starts the shaped path before the server and
client start, so handshake, RTT estimation, ACK timing, PTO, congestion control,
and loss recovery observe the simulated path directly.
The namespace setup installs static IPv6 neighbor entries before shaping is
enabled, so benchmark rows do not measure cold NDP resolution artifacts.
Before publication, non-loopback path profiles must pass
`tools/quicperf_network_validate.py --require-idle-host`; the validator records
qdisc snapshots before and after traffic, expected BDP/queue metadata, ping
RTT/loss/jitter checks, and raw TCP/UDP baselines. The detailed acceptance
criteria and source-backed profile audit live in
`docs/network-profile-validation.md`.
Public cellular trace archives are kept outside git under `.data/`; compact
derived UCC 5G, UCC 4G LTE, and UMN 5Gophers path-profile packs generated by
`tools/quicperf_cellular_profiles.py` are loaded from `profiles/network/*.json`
alongside the base WAN profile file.

For WAN throughput rows, the benchmark promotes default flow-control windows to a
bounded bandwidth-delay-product profile derived from the active path's RTT and
maximum configured rate. This prevents connection or stream windows from hiding
the actual bottleneck. The `flow_control` scenario remains intentionally
window-limited unless the caller explicitly selects a different window profile.

Loopback rows use CUBIC for every adapter and publish the effective controller
in `adapter_features` and `congestion_controller` columns. `picoperf` exposes
picoquic congestion-control selection through `QUICPERF_CONGESTION_PROFILE`;
for non-loopback targeted A/B runs, explicit values `cubic`, `dcubic`,
`newreno`, `prague`, and `c4` are available.
The `path-auto` profile is a benchmark policy for short-transfer WAN rows: it
selects `cubic` on the 10G/0.5ms datacenter profile and current BBR elsewhere
where the library exposes BBR.
When RTT and configured rate metadata are available, `path-auto` also enables
picoquic's BDP/cwnd seed on non-loopback profiles and applies it
immediately to the sender. This is a benchmark policy for known simulated paths,
not an assertion that an unknown fresh Internet path can safely start at that
window. Picoquic packet-train mode and the BDP transport extension are
controlled by `QUICPERF_PICOQUIC_PACKET_TRAIN` and
`QUICPERF_PICOQUIC_BDP_FRAME`; `QUICPERF_PICOQUIC_BDP_SEED=0` disables the
path-derived seed and `QUICPERF_PICOQUIC_BDP_SEED_IMMEDIATE=0` disables
immediate sender seeding for A/B runs. The shared picoquic transfer includes a
one-byte app completion exchange after payload delivery so impaired-path rows
require client-side receipt, not merely server-side enqueue.

Summary statistics:

The adaptive publication runner appends raw rows to `adaptive-samples.tsv`.
Measured rows carry metric values; unsupported and failed rows carry status,
reason, and log metadata.

Summary columns include `samples`, `min`, `p50`, `p90`, `p99`, and `max`.
`p50` uses a true median and is the publication statistic. `p90` and `p99` are
bad-tail visibility columns: for higher-is-better throughput and rate metrics,
`p90`/`p99` report the lower tail; for lower-is-better metrics, they report the
upper tail. `p99` is not claimable unless a row has at least 300 samples.

## Saturation

The adaptive runner normally searches client counts `1..32` with
`server_connections == client_threads`.

Selection rules:

- add a higher client count only after the current count has enough samples
- pick the lowest client count statistically within tolerance of the best p50
- default tolerance: `1%`
- default confidence: `95%`
- stop at the first ready adjacent client-count step that does not improve p50
  by more than the configured minimum incremental improvement
- the selected row means fewest clients needed to saturate one server thread

Saturation status:

- `ready`: convergence, saturation probability, and adjacent-increment plateau
  boundary passed
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
| Minimum incremental client-count improvement | > 1% |

Severe high-variance classification can stop rows after at least 6 discovery
blocks and 30 samples when they are far outside stability gates. Persistent
high variance can stop rows after at least 8 blocks and 40 samples without
material improvement.

`publication-results.tsv` is the selected-row table. `publication-curve.tsv`
keeps the 1-client row and measured curve through saturation or boundary for
each binary/scenario/network/path-profile row.
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
- loopback CUBIC congestion control for every adapter
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
  CQ, taskrun flags, provided buffers, multishot `recvmsg`, default UDP GSO, and
  default UDP GRO
- C++ owns socket creation, receive, send, batching, backend selection, and
  timeout scheduling for measured adapters
- `tools/audit-cpp-io-boundary.sh` is part of the build graph
- `tcpperf` remains syscall-only
- The shared GSO path coalesces compatible same-destination QUIC packets after
  deterministic loss filtering, so `loss_recovery` still drops at the QUIC
  packet unit. Received UDP GRO packets are split back into QUIC-packet
  deliveries before adapter callbacks.
- The default GSO train is 8 UDP segments, bounded by a 64-segment buffer and
  the UDP payload limit for explicit tuning with `QUICPERF_UDP_GSO_SEGMENTS`.
- SQPOLL, NAPI busy polling, and zerocopy receive are outside the default
  apples-to-apples rows.
