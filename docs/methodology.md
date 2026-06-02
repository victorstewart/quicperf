# Benchmark Methodology

This document is the benchmark contract. `README.md` is the entry point;
`docs/latest-results.md` is the current result index.

## Implementations

Benchmarked QUIC binaries:

`ngtcp2perf`, `lsperf`, `tquicperf`, `quicheperf`, `picoperf`, `xquicperf`,
`quinnperf`, `s2nperf`, `neqoperf`, `noqperf`, `quiczigperf`, `mvfstperf`.

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
| `datagram` | `datagrams_per_second` | Delivered app DATAGRAM echo rate. |

Session capability workloads:

| Scenario | Metric | Status |
|---|---|---|
| `resumed_connect` | `connections_per_second` | Session-ticket resumption connection setup. |
| `zero_rtt_reqresp` | `requests_per_second` | 0-RTT request/response with accepted/rejected state captured by the adapter contract. |

Publication rows use a two-stage fixed design: a bounded scout chooses client
threads and workload shape, then fixed randomized publication blocks collect the
predeclared measured samples without adaptive extension.

Unsupported rows exit with code `77` and write an explicit reason. They are not
silently remapped to another workload, and they are quicperf adapter-contract
markers rather than upstream library feature claims.

Current non-graceful close/reset subprofiles are not primary rows. They require
uniform RESET_STREAM, STOP_SENDING, CONNECTION_CLOSE, and abrupt-peer controls
before promotion.

### DATAGRAM Contract

`datagram` measures delivered application DATAGRAM echo rate. The operation
count is the client accepted-send budget, not required echo delivery. The client
sends until the budget is accepted by the library, then sends a reliable
per-connection done marker and drains for a bounded interval, ending earlier if
all sent sequence numbers are echoed.

DATAGRAM frame size is negotiated through the QUIC DATAGRAM transport parameter,
and the harness caps the application payload to the adapter's negotiated or
effective payload limit before sending. Adapters without a public effective
DATAGRAM MSS API use a conservative packet-payload cap under the QUIC minimum
1200-byte UDP payload. Local send and receive queue capacity is a library-local
public configuration request and write backpressure is the effective queue
limit.

Each DATAGRAM carries a sequence number. The harness records accepted sends,
unique echoes received, unreturned/lost DATAGRAMs, delivery ratio, UDP packets,
send submit/syscall batches, receive polls, and DATAGRAMs per UDP packet.
Delivery ratio is reported, not used to make an unreliable primitive reliable.

Packet-engine adapters must not flush or poll once per app DATAGRAM. C++ owns
the UDP socket, backend, batching, and timeout loop for DATAGRAM rows just like
the stream workloads.

## Output Schema

Current metrics are `throughput_gbps`, `connections_per_second`,
`requests_per_second`, `streams_per_second`, `messages_per_second`,
`datagrams_per_second`, and `server_rss_delta_bytes_per_connection`.
Public comparisons are interpreted only within the same scenario, network
backend, path profile, and metric group.

`tools/run-benchmarks.sh` writes one `summary.tsv` row per
binary/library/scenario/network/path-profile/client-thread/metric group and
writes `raw-samples.tsv` for every invocation. Publication runners append the
same structured rows to `adaptive-samples.tsv`: measured rows carry metric
values, while unsupported, failed, and thread-check rows carry status/reason/log
metadata with a blank value.

### Fixed Publication Design

The publication protocol separates planning from measurement:

- scout data is non-publication data and is written to `saturation-scout.tsv`
- scout grid: `1,2,4,8,16` client threads, 3 short samples per point
- scout selection: choose the lowest thread count within 2% of the scout best
  where the next grid point improves by less than 2%
- successful scout output is cached as the default plan with a fingerprint of
  dependency pins, benchmark-touching harness code, and scout scope; the scout is
  regenerated only when that fingerprint changes or refresh is forced
- `benchmark-plan.tsv` declares mode, duration/work, samples, warmup, blocks,
  client threads, and timeout before publication starts
- publication uses 20 measured samples, 1 warmup, and 5 randomized blocks by
  default
- publication never extends sample count or changes client threads based on
  CI/spread/drift during the same run

Rate workloads use duration mode by policy: `download`, `upload`,
`multistream_download`, `multistream_upload`, `bidi`, `loss_recovery`,
`flow_control`, `small_payload_pps`, `datagram`, `reqresp`, `stream_churn`,
`close_reset_cleanup`, and `zero_rtt_reqresp`. Count-semantics workloads
(`connect`, `resumed_connect`, `idle_footprint`) use fixed counts or fixed idle
hold time. Connection lifecycle rows cap each measured sample at 128 handshakes
to keep one process sample from becoming a lifecycle-churn stress test.

This follows established benchmark practice: warmup/calibration/scout work is
separate from measured data, and repeated reruns until significance are avoided.
Sources: Google Benchmark user guide
https://google.github.io/benchmark/user_guide.html, Criterion.rs analysis
https://bheisler.github.io/criterion.rs/book/analysis.html, Go benchmarks
https://pkg.go.dev/testing, pytest-benchmark calibration
https://pytest-benchmark.readthedocs.io/en/latest/calibration.html, benchstat
guidance https://pkg.go.dev/golang.org/x/perf/cmd/benchstat, and
Kalibera/Jones uncertainty framing https://arxiv.org/abs/2007.10899.

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
RTT/loss/jitter checks, and qdisc snapshots. The detailed acceptance
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

The fixed publication runner appends raw rows to `adaptive-samples.tsv` for
schema compatibility. Measured rows carry metric values; unsupported and failed
rows carry status, reason, and log metadata.

Summary columns include `samples`, `min`, `p50`, `p90`, `p99`, and `max`.
`p50` uses a true median and is the publication statistic. `p90` and `p99` are
bad-tail visibility columns: for higher-is-better throughput and rate metrics,
`p90`/`p99` report the lower tail; for lower-is-better metrics, they report the
upper tail. `p99` is not claimable unless a row has at least 300 samples.

## Saturation

Scout uses `server_connections == client_threads` and the fixed grid
`1,2,4,8,16`; 16 client threads is the maximum accepted by fixed plans and
direct smoke runs. The selected row means the fewest load-generator client threads
needed to reach the scout plateau for one server thread. Scout samples are never
publication samples.

## Publication Gates

Use `tools/run-saturation-scout.py` followed by
`tools/run-fixed-publication-suite.py --plan benchmark-plan.tsv` for
publication rows.

Default flow:

- bounded scout writes `saturation-scout.tsv`
- fixed plan writes `benchmark-plan.tsv`
- successful scout output is cached with a benchmark-relevant fingerprint and
  reused until dependency pins, benchmark-touching harness code, or scout scope
  changes
- one unmeasured warmup per row by default
- 20 measured publication samples per selected row
- 5 randomized blocks, 4 measured samples per row per block
- no optional stopping or adaptive extension during publication
- CI, spread, drift, and outliers are audit labels, not same-run sampling triggers

Default gates:

| Gate | Default |
|---|---:|
| Bulk p50 CI relative width | <= 3% |
| Connect/request/lifecycle p50 CI relative width | <= 5% |
| Impaired-network p50 CI relative width | <= 8% |
| p20/p80 middle-spread ratio | <= 1.15 |
| Block-median ratio | <= 1.10 |
| Absolute drift | <= 3% |
| Scout selected-vs-best tolerance | within 2% |
| Next scout grid improvement | < 2% |

Status fields:

- `measurement_status`: `complete`, `failed`, or `unsupported`
- `audit_status`: `clean`, `noisy`, or `tail_insufficient`
- `publication_status`: `publishable`, `inconclusive`, `failed`, or
  `unsupported`

A completed 20-sample row with CI, spread, or drift problems is
`inconclusive`/`noisy`; it is not called `not_ready` and it is not extended in
the same publication run. Public result pages may still show these completed
rows when their status is visible. `p99` remains diagnostic unless a separate
tail campaign has at least 300 samples.

`publication-results.tsv` is the selected-row table. `publication-row-audit.tsv`
preserves gate details for publication rows. `pairwise-comparisons.tsv`
compares publishable rows only; noisy completed rows remain visible in the
selected-row tables with their audit status.

## Controls

- one pinned userspace server thread
- unpinned client workers used only for load generation
- hidden userspace helper threads blocked after configured workers exist
- kernel io_uring workers reported separately
- shared TLS 1.3 Ed25519 certificate/key/chain by default
- verified TLS requires `tools/run-tls-verify-audit.sh`
- loopback CUBIC congestion control for every adapter
- shared public window, stream-limit, and workload requests where APIs permit;
  negotiated or clamped library policy is reported, not overridden
- server app-level completion before client/server exit
- true per-connection/per-stream server state for multi-client rows
- fresh random loopback port blocks by default
- no parallel measured loopback rows unless isolated CPU lanes, server core
  isolation, IRQ/noise audit, and one-lane-vs-N-lane A/B equivalence are proven

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
- The shared GSO path coalesces compatible same-destination QUIC packets after
  deterministic loss filtering, so `loss_recovery` still drops at the QUIC
  packet unit. Received UDP GRO packets are split back into QUIC-packet
  deliveries before adapter callbacks.
- The default GSO train is 8 UDP segments, bounded by a 64-segment buffer and
  the UDP payload limit for explicit tuning with `QUICPERF_UDP_GSO_SEGMENTS`.
- SQPOLL, NAPI busy polling, and zerocopy receive are outside the default
  apples-to-apples rows.
