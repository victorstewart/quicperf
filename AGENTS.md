# AGENTS.md

Repository instructions for quicperf. `docs/methodology.md` is the benchmark
contract; change established methodology only with explicit user authorization.

## Working rules

- Work on `main` unless the user names another branch or worktree. Start with
  `git status --short --branch` and preserve unrelated changes.
- Before a fresh run, recheck current profiles, pins, scripts, host state, and
  identities. Never act from an old status summary.
- Prefer the smallest root-cause change and delete obsolete machinery. Keep
  shared modules free of consumer policy and composition roots limited to
  wiring and lifecycle.
- Preserve user-owned dirt and every journal. Never mutate an earlier result to
  fit a later methodology.
- Reuse a build directory only after its source path, compiler, dependency and
  generated graphs, and configuration still match.
- Evaluate eBPF for Linux observability only when its measured benefit justifies
  privilege, verifier, portability, lifecycle, and attack-surface costs; retain
  a simpler fallback where required.

## Dependencies and forks

Refresh dependencies or forks only when the task explicitly requests an
upgrade; a request for fresh results alone does not authorize refresh. Inventory
`depofiles/*.DepoFile`, `rust-packet-ffi/Cargo.{toml,lock}`,
`zig-packet-ffi/build.zig.zon`, and `CMakeLists.txt`. For native sources, compare
pins with upstream via `git ls-remote` or release archives, then update `VERSION`,
`SOURCE`, dependent `DEPENDS VERSION` fields, and compatibility patches together.

Before changing local pins, refresh these maintained branches against upstream:
`victorstewart/{quinn,noq,neqo,s2n-quic}:quicperf-c-abi`. For `endel/quic-zig`,
use `main` while it retains quicperf's Ed25519 TLS and correctness fixes; create
a fork branch only for a new quicperf-only change. Keep required third-party
patches in Depofiles and apply them at build time; never push them upstream
without separate authorization. Verify each refreshed C ABI or source package
through quicperf, not only its upstream build.

## Publication product

The sole publication profile is `profiles/v2.3/publication.json`. Its primary
estimand is fixed-treatment server performance across 12 frozen servers and 15
frozen scenarios, with one common C++ `iouring` backend, one isolated server
core, four isolated client cores, exactly 16 active connections, an equal
`ngtcp2perf`/`picoperf` reference-client mixture, two independently started
sessions yielding 24 raw rows and 12 paired superblocks, and exact 4,096
common-sign max-absolute-t inference.

Capacity, memory, tail, symmetric, all-confirmatory, syscall treatment, scout,
adaptive selection, legacy translation, unqualified-host fallback, and
outcome-dependent rescheduling are not publication paths. `tools/run-benchmarks.sh`
and syscall are developer diagnostics only; diagnostic or scout samples never
enter publication statistics, rankings, or tables.

`tools/quicperfctl` is the only publication coordinator, and its SQLite journal
is authoritative. A resume requires identical immutable source, binary, build,
host-policy, spec, schedule, and analysis identities. Logs and exports are never
state or sample inputs.

Primary QUIC binaries are `ngtcp2perf`, `lsperf`, `tquicperf`, `quicheperf`,
`picoperf`, `xquicperf`, `quinnperf`, `s2nperf`, `neqoperf`, `noqperf`,
`quiczigperf`, and `mvfstperf`. `tcpperf` is a TCP+TLS sidecar and stays out of
QUIC tables unless explicitly requested. Use concrete implementation labels,
not `Primary QUIC row`.

## Fairness and validity

- C++ owns measured UDP socket creation, receive/send, batching, backend
  selection, loss, clocks, timeout scheduling, and the event loop. Rust, Zig,
  mvfst, and native adapters use equivalent shared-I/O boundaries.
- GSO/GRO is the `iouring` default. DATAGRAM rows require batch-equivalent loops
  and agreement in sent, received, unreturned/lost, delivery ratio, UDP packet,
  send-batch, receive-poll, and DATAGRAM-per-packet accounting. Fix accounting,
  loss filtering, or receive splitting; never quarantine a semantic gap.
  `loss_recovery` drops at QUIC-packet granularity under GSO.
- `idle_footprint` publishes `server_rss_delta_bytes_per_connection`, never a
  placeholder `idle_connections` row. `picoperf`'s default BBR means picoquic's
  current `bbr` algorithm string.
- Endpoint workload windows, reset, negotiated settings, terminal events,
  cleanup, thermal ceiling, zero throttling, host policy, isolation, and
  identity gates fail closed.
- Unsupported rows indicate an adapter-contract gap unless upstream/local API
  evidence proves a library limitation. Name the primary estimand on every
  result; never imply generic, client-invariant, or global ranking semantics.

## Network and artifacts

Loopback is the only V2.3 publication path. Separately authorized non-loopback
diagnostics require root or `CAP_NET_ADMIN`, `ip netns`, and `tc`; validate the
path and idle host before interpreting them. Keep raw traces in ignored `.data/`;
only compact generated profile packs belong in `profiles/network/*.json`.

Only the deterministic V2.3 publisher may populate `docs/results/v2/<id>/`, and
only from an immutable `publication_qualified` campaign. Public docs link
committed immutable compact artifacts, never `.run/`. Do not commit journals,
samples, raw health streams, events, logs, build products, `.run`, `.data`,
`.tasks`, or large evidence; put full evidence in checksummed release assets.

Keep one canonical public results page unless asked otherwise. Use full words,
readable scenario tables, correct metric direction, and no mostly-empty `n/a`
tables. Show simultaneous intervals/classifications, variance misses, and
client/session sensitivity; mark unsupported or nonpublishable rows explicitly
and place unsupported rows after measured rows. Never invent a global
leaderboard. Retract or quarantine implausible tables when fairness is challenged
or audit evidence is incomplete.

## Verification and evidence

Run checks proportionate to the task. Broad release builds, test suites, and
mechanism/high-value/TLS smoke audits are required only for release/publication
readiness or changes whose scope reaches them; focused `BUILD_*` toggles are for
diagnosis or narrow dependency proofs. The C++ I/O-boundary audit remains in the
build graph and may not be bypassed.

Performance changes require representative before/after evidence. Library work
requires profiles of library source, not only adapters. Every picoquic source
change needs a recorded profile artifact, expected mechanism, same-build A/B,
p50 delta, and accept/reject decision; if profiles are diffuse, examine stream
lifecycle, receive scheduling, packetization, and allocation.

Unavailable physical gates are `NOT_RUN`, never passed. Never claim an
unobserved check passed or use `publication_qualified` until every deterministic
and physical gate passes for the exact identity.
