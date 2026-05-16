# Network Profile Validation and Design Audit

## Current Determination

The namespace-backed profiles are validated production-grade IP-layer lab
profiles for the preserved run
`.run/network-profile-validation-full-20260516T201413Z/`: all 21 non-loopback
profiles passed with saved idle-host preflight, qdisc snapshots, qdisc JSON
checks, ping probes, raw TCP/UDP baselines, and BDP/queue metadata. The profiles
replicate application-visible path dynamics: RTT, jitter, loss, bottleneck rate,
rate variation, queue depth, and BDP. They are not a full LTE/5G radio access
network, scheduler, HARQ, RLC, or carrier-core emulator.

## Validation Gate

Run this gate before using non-loopback profiles for a publication matrix:

```sh
tools/quicperf_network_validate.py \
  --profiles all-non-loopback \
  --samples 3 \
  --ping-count 100 \
  --probe-timeout 300 \
  --require-idle-host
```

Each run writes `.run/network-profile-validation-<utc>/` with:

- `manifest.json`, `results.json`, and `summary.tsv`
- `host-preflight.txt`
- per-profile `profile.json`, `expectations.json`, `trace-audit.json`, `state.json`
- per-profile `qdisc-before.json`, `qdisc-after.json`, and qdisc validation JSON
- `snapshot-before.txt`, `snapshot-after.txt`, and compatibility `snapshot.txt`
- raw `ping.txt`, TCP sender/receiver logs, and UDP sender/receiver logs

Promotion criteria:

- The idle-host preflight must pass; otherwise the run exits before shaping.
- Every profile must produce qdisc snapshots before and after probe traffic, and
  qdisc JSON checks must match the profile-derived delay, jitter, loss, rate, and
  queue limits.
- Ping RTT, jitter, and loss must match the derived profile envelope.
- Raw TCP must not exceed the shaped bottleneck by more than 25 percent.
- Raw UDP must not exceed the sender target by more than 25 percent, and loss
  must stay inside the profile-specific envelope.
- With 3 or more samples, probe throughput coefficient of variation above 0.35
  is a warning requiring investigation before publication use for static paths.
- Any `fail` status blocks use. Any `warn` status must be either fixed or
  explicitly accepted in the publication notes with the artifact path.

The validator uses adaptive TCP sizes, UDP targets/payloads, and ping intervals
so validation traffic does not overdrive low-rate dynamic traces while still
recording raw TCP and UDP behavior outside QUIC.

## Public Cellular Dynamics Workflow

Raw public datasets live under `.data/` and are intentionally ignored by git.
The tracked source of truth is the generator plus compact derived profiles:

```sh
mkdir -p .data/public-cellular/ucc-5g
curl -L --fail \
  -o .data/public-cellular/ucc-5g/5G-production-dataset.zip \
  https://raw.githubusercontent.com/uccmisl/5Gdataset/master/5G-production-dataset.zip

tools/quicperf_cellular_profiles.py \
  --name 5g-ucc-driving-replay \
  --mobility Driving \
  --window most-variable \
  --max-steps 90 \
  --zero-as-outage
```

`tools/quicperf_cellular_profiles.py` supports the UCC 5G production dataset,
the UCC 4G LTE dataset, and the UMN 5Gophers walking trace directly. It also
accepts normalized CSVs with
`timestamp_ms` or `time_s`, `downlink_bps` or `downlink_mbps`, `uplink_bps` or
`uplink_mbps`, optional `rtt_ms`, `jitter_ms`, `loss_percent`, `speed_kph`,
`cell_id`, and `state`. That normalized path is the intended adapter for MONROE,
Lumos5G, FCC, POWDER, and other public traces after their original
schemas are converted.

The UCC 5G archive exposes `Static` and `Driving` traces only; it does not have
a pedestrian or walking trace directory. Do not create a `5g-ucc-pedestrian-*`
profile from UCC data. `5g-5gophers-walking-loop` is the separate 5G pedestrian
profile derived from UMN 5Gophers.

Generated cellular dynamics profiles are stored in
`profiles/network/cellular-dynamics-profiles.json`. The profile loader merges
all `profiles/network/*.json` files, so these profiles can be used anywhere
`QUICPERF_PATH_PROFILES` is accepted.

## Design Basis

Linux `tc netem` is the right primitive for this scope because it directly
supports delay, jitter, correlation, loss, rate, and queue limit. The upstream
manual also warns that rate and delay are limited by kernel timer granularity and
that TCP realism depends on putting netem at the receiver ingress path. Our
router namespace applies shaping in both directions before either endpoint sees
the peer, which keeps handshake, ACK timing, loss recovery, flow control, and
congestion control inside the shaped path.

The datacenter profiles are calibrated as conventional software-shaped VM or
datacenter paths, not RDMA-class compact-placement paths. Google Cloud documents
same-zone C2 VM RTTs below 55 us p50 and 80 us p99, and AWS ENA supports much
higher bandwidth classes than 10G on many instances. The 0.5 ms and 1.0 ms
profiles are therefore intentionally conservative for local lab repeatability.

The LTE profiles are calibrated against IMT-Advanced/LTE-Advanced capability
targets and real-world access-path behavior. ITU-R M.2134 names 100 Mbit/s high
mobility and 1 Gbit/s low mobility research targets, while LTE-Advanced targets
1 Gbit/s downlink and 500 Mbit/s uplink peak rates. Our LTE rows are much lower
than peak by design: they model app-visible user throughput, jitter, radio/core
path delay, and capacity movement.

The 5G profiles are calibrated against IMT-2020 eMBB targets and observed mobile
network behavior. ITU-R M.2410 defines 20 Gbit/s downlink and 10 Gbit/s uplink
peak data-rate minimum requirements, with dense-urban user-experienced targets
of 100 Mbit/s downlink and 50 Mbit/s uplink. The 5G sub-6 profile sits near that
user-experienced range, while the mmWave-style profile intentionally models a
high-bandwidth burst profile with obstruction drops.

Ofcom's 2025 Mobile Matters report and Opensignal market reports are the right
ongoing calibration sources for deployed-user behavior because they measure user
experience, not only radio-interface peak capability. Use them to refresh market
specific variants when publication needs a named geography or carrier mix.

## Profile Audit

| Profile | Intent | Current parameters | Audit result |
| --- | --- | --- | --- |
| `dc-fabric-10g` | Conservative same-DC or VM fabric path. | 0.5 ms RTT, 10G symmetric, 0 loss, 1.0 BDP queue. | Fair for software-shaped datacenter benchmarking. Do not describe as rack-local RDMA or compact-placement fabric. |
| `dc-fabric-1ms` | Repeatable fallback datacenter profile when sub-ms shaping is noisy. | 1.0 ms RTT, 10G symmetric, 0 loss, 1.0 BDP queue. | Fair and conservative. Prefer this for publication if 0.5 ms netem timing is unstable. |
| `lte-good` | Good LTE access path with mobile capacity movement. | 45 ms RTT, 8 ms one-way jitter, 0.08 percent one-way loss, 53.9/12.8 Mbps trace-average down/up. | Plausible field-like LTE profile. Production use requires validation artifacts because it is below peak capability by design. |
| `lte-congested` | Adverse LTE edge/congestion resilience profile. | 100 ms RTT, 25 ms one-way jitter, 0.7 percent one-way loss, 8.9/2.5 Mbps trace-average down/up. | Fair as a named adverse profile, not as median LTE. Keep the `congested` label in all reports. |
| `5g-sub6-good` | Good 5G sub-6 eMBB path. | 20 ms RTT, 3 ms one-way jitter, 0.02 percent one-way loss, 256.6/49.3 Mbps trace-average down/up. | Plausible and aligned with user-experienced 5G eMBB targets. Needs validation to prove host qdisc delivery. |
| `5g-mmwave-bursty` | High-bandwidth mmWave-style path with obstruction drops. | 15 ms RTT, 5 ms one-way jitter, 0.05 percent one-way loss, 1.30G/132.7 Mbps trace-average down/up. | Plausible as a burst/obstruction lab profile. Do not claim physical mmWave scheduler fidelity without a richer RAN model. |
| `5g-ucc-static-replay` | Public 5G static trace replay. | 90-step UCC static download window with per-step rate, delay, jitter, loss, and queue dynamics. | Data-derived candidate. Must pass idle-host validation before publication use. |
| `5g-ucc-driving-replay` | Public 5G driving trace replay. | 90-step UCC driving download window with per-step dynamics and cell-change outage events. | Data-derived candidate for mobility-sensitive rows. Must pass idle-host validation before publication use. |
| `5g-ucc-driving-congested` | Public 5G adverse driving window. | 90-step UCC driving window selected by lowest median downlink. | Data-derived adverse candidate. Label as adverse/congested in reports. |
| `5g-ucc-static-good` | Public 5G good static window. | 90-step UCC static download window selected by highest median downlink. | Data-derived good-path candidate. Must pass idle-host validation before publication use. |
| `5g-ucc-driving-good` | Public 5G good driving window. | 90-step UCC driving download window selected by highest median downlink. | Data-derived good mobility candidate. Must pass idle-host validation before publication use. |
| `5g-ucc-driving-handover-heavy` | Public 5G frequent-handover mobility window. | 120-step UCC driving download window with cell-change outage events. | Data-derived mobility stress candidate. |
| `5g-ucc-driving-bursty-high` | Public 5G bursty high-ceiling driving window. | 90-step UCC driving download window selected for high rate ceiling and sharp variation. | Data-derived burst sensitivity candidate. |
| `5g-ucc-video-app-shaped` | Public 5G video app-shaped behavior. | 120-step UCC Netflix driving window preserving buffering and app-idle periods. | App-shaped profile, not a pure access-capacity profile. Keep this label in reports. |
| `5g-5gophers-walking-loop` | Public 5G pedestrian walking-loop replay. | 120-step UMN 5Gophers walking-loop window filtered to 5G samples, with cell-change outage events. | Data-derived pedestrian candidate. Source is 5Gophers, not UCC. |
| `lte-ucc-static-good` | Public 4G LTE good static window. | 90-step UCC LTE static window selected by highest median downlink. | Data-derived LTE good-path candidate. |
| `lte-ucc-pedestrian-replay` | Public 4G LTE pedestrian mobility replay. | 90-step UCC LTE pedestrian window with cell-change dynamics. | Data-derived pedestrian mobility candidate. |
| `lte-ucc-car-replay` | Public 4G LTE car mobility replay. | 90-step UCC LTE car window with frequent cell changes. | Data-derived car mobility candidate. |
| `lte-ucc-tram-handover` | Public-transit LTE handover stress. | 90-step UCC LTE bus/public-transit window used as a tram-like handover profile because the archive exposes bus rather than tram traces. | Data-derived transit handover candidate; source caveat must remain visible. |
| `lte-ucc-train-adverse` | Public 4G LTE train adverse mobility. | 120-step UCC LTE train window with high-speed mobility, low-throughput periods, and handover events. | Data-derived adverse high-speed candidate. |
| `lte-ucc-congested` | Public 4G LTE congested adverse window. | 90-step UCC LTE adverse pedestrian window selected by lowest median downlink. | Data-derived congested candidate. |

## Fairness Rules

- A profile must never be tuned for one QUIC library.
- Publication comparisons must either run a fixed congestion controller across
  the matrix or explicitly label a separate `path-auto` policy run.
- The validation gate is CC-independent: ping, raw TCP, and raw UDP execute
  outside QUIC so they prove the path before any library result is trusted.
- The same profile JSON, validation artifacts, and benchmark command line must
  be retained with every publication run.

## Sources

- Linux `tc-netem(8)`: https://man7.org/linux/man-pages/man8/tc-netem.8.html
- Linux `tc-tbf(8)`: https://man7.org/linux/man-pages/man8/tc-tbf.8.html
- ITU-R M.2134 IMT-Advanced requirements: https://www.itu.int/dms_pub/itu-r/opb/rep/r-rep-m.2134-2008-pdf-e.pdf
- ETSI TR 136 913 / 3GPP TR 36.913 LTE-Advanced requirements: https://www.etsi.org/deliver/etsi_tr/136900_136999/136913/14.00.00_60/tr_136913v140000p.pdf
- ITU-R M.2410 IMT-2020 requirements: https://www.itu.int/dms_pub/itu-r/opb/rep/R-REP-M.2410-2017-PDF-E.pdf
- Google Cloud VPC latency and packet-loss documentation: https://cloud.google.com/vpc/docs/vpc
- AWS EC2 enhanced networking documentation: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking.html
- Ofcom Mobile Matters 2025: https://www.ofcom.org.uk/phones-and-broadband/mobile-phones/mobile-matters-download-speeds-connection-rates-and-latency-levels-revealed
- Opensignal USA mobile network reports: https://insights.opensignal.com/reports/2026/01/usa/mobile-network-experience
- UCC 5G production dataset: https://github.com/uccmisl/5Gdataset
- UCC 4G LTE dataset: https://www.ucc.ie/en/misl/research/datasets/ivid_4g_lte_dataset/
- UMN 5Gophers dataset: https://networking.umn.edu/5gophers
