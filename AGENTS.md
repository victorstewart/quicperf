# AGENTS.md

Repository instructions for work in quicperf. Preserve established benchmark
contracts unless the user explicitly authorizes a methodology change.

## Start and plan

- Work on `main` unless the user names another branch or worktree.
- Begin with `git status --short --branch`; preserve unrelated changes.
- Read relevant `.tasks/lessons.md` entries before benchmark, dependency,
  documentation, or performance work.
- For coordinated or interruptible work, maintain an ignored
  `.tasks/plan-<slug>.md` with scope, checks, verification, and final review.
- Recheck current profiles, pins, scripts, host state, and identities before a
  fresh run. Do not act from an old status summary.

## Design and editing

- Prefer the smallest root-cause change. Delete obsolete machinery rather than
  adding speculative compatibility paths.
- Keep shared modules free of consumer-specific policy and composition roots
  focused on wiring and lifecycle.
- Preserve user-owned dirt and all journals. Never mutate an earlier result to
  fit a later methodology version.
- Reuse a build directory only after proving its source path, compiler,
  dependency graph, configuration, and generated graph still match.
- Evaluate eBPF when Linux kernel observability, tracing, profiling,
  networking, security, or low-overhead telemetry would materially benefit.
  Use it only when its visibility or performance advantage justifies
  privilege, verifier, portability, lifecycle, and attack-surface costs; retain
  a simpler fallback where deployment requires one.

## Dependencies and forks

Inventory native pins in `depofiles/*.DepoFile`, Rust pins in
`rust-packet-ffi/Cargo.{toml,lock}`, Zig pins in
`zig-packet-ffi/build.zig.zon`, and top-level build inputs in `CMakeLists.txt`.
When the user requests upgrades, refresh quicperf fork branches against their
upstreams before updating local pins. Keep required third-party patches in
Depofiles and apply them at build time; do not push them upstream without
separate authorization. Verify every refreshed C ABI through quicperf itself.

## Supported publication product

The only publication profile is `profiles/v2.3/publication.json`. Its primary
estimand is fixed-treatment server performance with:

- 12 frozen servers and 15 frozen scenarios;
- one common C++ `iouring` backend;
- one isolated server core and four isolated client cores;
- exactly 16 active connections;
- equal `ngtcp2perf`/`picoperf` reference-client mixture;
- two independently started sessions, 24 raw rows and 12 paired superblocks;
- exact 4,096 common-sign max-absolute-t inference.

Capacity, memory, tail, symmetric, all-confirmatory, syscall treatment, scout,
adaptive selection, legacy translation, unqualified-host diagnostic fallback,
and outcome-dependent rescheduling are not supported publication paths.
`tools/run-benchmarks.sh` and syscall remain developer diagnostics only.

`tools/quicperfctl` is the sole publication coordinator. The SQLite journal is
authoritative. Resume requires the exact immutable source, binary, build,
host-policy, spec, schedule, and analysis identity. Logs and exported tables
are never state or sample inputs.

## Fairness and validity

- C++ owns measured UDP sockets, receive/send, batching, backend selection,
  loss, clocks, timeout scheduling, and the event loop.
- Rust, Zig, mvfst, and native adapters use equivalent shared-I/O boundaries.
- DATAGRAM rows must preserve batch-equivalent accounting. Loss recovery drops
  at QUIC-packet granularity under GSO.
- Endpoint workload windows, reset, negotiated settings, terminal events,
  cleanup, thermal ceiling, zero throttling, host policy, isolation, and
  identity gates fail closed.
- Unsupported rows describe an adapter-contract gap unless upstream/local API
  evidence proves a library limitation.
- The primary estimand must be named on every result. Never call it generic,
  client-invariant, or a global ranking.

## Build and verification

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel "$(nproc)"
ctest --test-dir build --output-on-failure
python3 -m unittest discover -s tests -p 'test_*.py'
tools/run-mechanism-workload-smoke.sh
tools/run-high-value-workload-smoke.sh
tools/run-tls-verify-audit.sh
```

The C++ I/O-boundary audit belongs to the build graph and may not be bypassed.
Use focused toggles only for diagnosis. Performance changes require
representative before/after evidence; library optimization requires profiling
the library source, not only its adapter.

Physical gates unavailable on the current host are `NOT_RUN`, never passed.
Continue deterministic implementation work when possible, but do not claim
`publication_qualified`.

## Results

Only the deterministic V2.3 publisher may populate `docs/results/v2/<id>/`,
and only from an immutable campaign whose final status is
`publication_qualified`. Do not commit journals, samples, raw health streams,
events, logs, build products, `.run`, `.data`, `.tasks`, or large evidence.
Full evidence belongs in checksummed release assets.

Public pages must:

- link immutable compact artifacts;
- use readable scenario-specific tables and correct metric direction;
- show simultaneous intervals/classifications, variance misses, and client/
  session sensitivity;
- mark unsupported or nonpublishable rows explicitly;
- never invent a global leaderboard.

## Completion

Never claim an unobserved check passed. Final implementation handoffs include
scope, status, readiness, completed work, observed verification, remaining
work/blockers, and cleanup. Use `publication_qualified` only after every
deterministic and physical gate passes on the exact identity.
