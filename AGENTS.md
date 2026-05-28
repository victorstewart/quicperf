# AGENTS.md

Repository-specific instructions for Codex work in `/root/quicperf`.

## First Checks

- Work on `main` unless the user explicitly names another branch or worktree.
- Start by running `git status --short --branch`; preserve unrelated dirt.
- Read relevant entries in `.tasks/lessons.md` before major benchmark, docs, dependency, or performance work.
- For non-trivial work, create a task-specific `.tasks/plan-<slug>.md` with scope, checklist, verification, and a final review section.
- Do not start a fresh result run from stale assumptions. Recheck current scripts, docs, pins, and branch state.

## Dependency And Fork Refresh

When the user asks for fresh benchmark data or fresh publication results, first confirm whether dependencies and quicperf-maintained forks should be refreshed. If they ask to upgrade, do that before running data.

Inventory dependency state from:

- `depofiles/*.DepoFile`
- `rust-packet-ffi/Cargo.toml`
- `rust-packet-ffi/Cargo.lock`
- `zig-packet-ffi/build.zig.zon`
- `CMakeLists.txt`

For native Depofile sources, compare pinned SHAs/tags with upstream using `git ls-remote` or current release archives. Update `VERSION`, `SOURCE`, dependent `DEPENDS VERSION` fields, and any required compatibility patches together.

For quicperf fork branches, check and rebase/update the fork branch against its upstream before changing local pins:

- `victorstewart/quinn`, branch `quicperf-c-abi`
- `victorstewart/noq`, branch `quicperf-c-abi`
- `victorstewart/neqo`, branch `quicperf-c-abi`
- `victorstewart/s2n-quic`, branch `quicperf-c-abi`
- `endel/quic-zig`, branch `main` if upstream still contains the quicperf Ed25519 TLS and correctness fixes; only recreate a fork branch if a new quicperf-only Zig change is required.

After fork refresh, verify the C ABI or source package still builds through quicperf, not just in the upstream project alone.

## Build And Smoke Gates

Default full release build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel "$(nproc)"
```

Use focused `BUILD_*` toggles only for diagnosis or narrow dependency proofs. Before claiming the repo is ready for fresh results, build all primary benchmark targets that are in scope for the run.

Important smoke/audit commands:

```sh
tools/run-mechanism-workload-smoke.sh
tools/run-high-value-workload-smoke.sh
tools/run-tls-verify-audit.sh
```

The C++ I/O boundary audit is part of the CMake build graph. If it fails, fix the benchmark ownership violation instead of bypassing the audit.

## Fresh Loopback Runs

Use the adaptive runner for publishable or publication-candidate loopback data:

```sh
QUICPERF_PATH_PROFILES=loopback \
QUICPERF_NETWORKS="syscall iouring" \
QUICPERF_TEST_BYTES=1073741824 \
tools/run-adaptive-publication-suite.py
```

Use `tools/run-benchmarks.sh` for targeted row checks, not as a substitute for adaptive publication evidence.

The adaptive runner uses a non-public calibration phase by default. Calibration samples go to `calibration-samples.tsv` and must not be used in publication statistics, curves, rankings, or result tables. The workload plan must be declared before measured discovery samples and recorded in `workload-plan.tsv`.

Default loopback matrix policy:

- publication tier rows use calibrated full adaptive convergence
- capability/lifecycle rows use fixed smoke blocks unless explicitly promoted with `QUICPERF_ADAPTIVE_PROMOTE_SCENARIOS`
- measured loopback rows stay serial unless CPU/core isolation has been implemented and validated
- high variance is not a separate terminal status; rows are `converged`, `not_ready`, `failed`, or `unsupported`

Batch output lives under `.run/`. Key files include:

- `calibration-samples.tsv`
- `calibration-validation-samples.tsv` (scale-up probe evidence; failed
  candidates are not terminal row failures when fallback succeeds)
- `calibration-decisions.tsv`
- `workload-plan.tsv`
- `adaptive-samples.tsv`
- `row-stats.tsv`
- `publication-results.tsv`
- `publication-curve.tsv`
- `publication-row-audit.tsv`
- `saturation-decisions.tsv`

Only publication-tier rows with `publication_status=converged` are clean publishable ranking rows. `not_ready`, failed, unsupported, capability-only, lifecycle-only, or bounded rows may be shared as diagnostics only, with the status and reason visible.

## Benchmark Contract

- Treat `docs/methodology.md` as the benchmark contract.
- Primary QUIC binaries are `ngtcp2perf`, `lsperf`, `tquicperf`, `quicheperf`, `picoperf`, `xquicperf`, `quinnperf`, `s2nperf`, `neqoperf`, `noqperf`, `quiczigperf`, and `mvfstperf`.
- `tcpperf` is a TCP+TLS sidecar baseline; do not include it in QUIC result tables unless the user explicitly asks for sidecar comparison.
- Use concrete implementation labels such as native adapter, Rust packet engine with C++ UDP I/O, Zig packet engine with C++ UDP I/O, mvfst transport, TCP+TLS sidecar, unsupported capability row, or not-publishable result row.
- Do not use vague labels like `Primary QUIC row`.
- Treat unsupported rows as quicperf adapter-contract gaps, not proof that the upstream library lacks the feature. Verify upstream/local APIs before documenting a true library capability gap.

## Fairness Rules

- C++ owns measured UDP socket creation, receive, send, batching, backend selection, and timeout scheduling.
- Rust, Zig, mvfst, and native adapters must be compared through equivalent shared I/O paths.
- DATAGRAM rows must use batch-equivalent drive loops. Compare sent, received, unreturned/lost, delivery ratio, UDP packets, send batches, receive polls, and DATAGRAMs per UDP packet before accepting the numbers.
- GSO/GRO is default on the `iouring` path. Do not quarantine rows to hide semantic gaps; fix packet accounting, loss filtering, and receive splitting so the benchmark contract remains valid.
- `loss_recovery` must drop at the QUIC packet unit even when UDP GSO is enabled.
- `idle_footprint` must publish `server_rss_delta_bytes_per_connection`; do not publish placeholder `idle_connections` rows.
- `picoperf` default BBR means picoquic's current `bbr` algorithm string.

## Performance Work

Performance changes need before/after evidence. For library-specific work, profile the library source itself when that is the stated target.

For picoquic work in particular:

- Do not rely only on `perf.picoquic.h` adapter evidence when the task asks for picoquic-library optimization.
- Every picoquic source change must have a recorded profile artifact, expected mechanism, same-build A/B benchmark, p50 delta, and accept/reject decision.
- If profiles are diffuse, consider design-level costs such as stream lifecycle, receive-path scheduling, packetization, and allocation patterns.

## Result Docs And Artifacts

Public result docs must link committed artifacts, not ignored `.run/` paths. Copy selected result TSVs under `docs/results/<run-id>/` before linking them from `docs/latest-results.md`.

Public tables should be readable:

- one canonical public results page unless the user asks for more
- full words instead of terse status codes
- no mostly-empty `n/a` tables
- sort by the requested metric and correct direction
- unsupported rows clearly marked and placed after measured rows

Retract or quarantine implausible result tables immediately if fairness is challenged or audit evidence is incomplete.

## Network Profiles

Loopback is the default path profile. Non-loopback profiles require root or `CAP_NET_ADMIN`, `ip netns`, and `tc`.

Before publishing non-loopback rows, run the network validator:

```sh
tools/quicperf_network_validate.py --samples 10 --ping-count 100 --require-idle-host
```

Keep raw public trace archives in ignored `.data/`; only compact generated profile packs belong under `profiles/network/*.json`.

## Completion Standard

Before final handoff, report:

- exact commands run
- key artifact paths
- pass/fail status and blockers
- whether data is publishable, diagnostic, or partial
- cleanup performed and concrete cleanup candidates in touched scope

Never claim benchmark, build, or publication success without observed output.
