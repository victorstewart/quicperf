# Loopback Full Matrix 2026-05-25

Run ID: `adaptive-20260525T002622Z-2639460`

Source run directory: `.run/adaptive-20260525T002622Z-2639460`

Launch wrapper: `.run/full-loopback-matrix-20260525T002622Z-25c53ca-dirty`

Git commit recorded by samples: `25c53ca52dde22548d5dfa694abd5b1656bb5ed9`

Working tree status at launch: dirty.

## Status

- Runner status: complete
- Publication status: not ready
- Publication rows: 70 converged, 2 not ready, 0 failed
- Audited publication rows: 127 converged
- Adaptive samples: 8,244 total; 8,242 ok; 2 thread-check failures
- Calibration samples: 144 ok
- Calibration validation samples: 96 ok

The not-ready publication rows are `xquicperf download` on both `syscall` and
`iouring`. Those rows also recorded one failed `t4` sample per backend with
`thread_check_failed missing_server_complete`.

## Files

- `adaptive-samples.tsv`: raw measured adaptive samples
- `row-stats.tsv`: row-level distribution statistics
- `publication-results.tsv`: selected publication rows and gate status
- `publication-row-audit.tsv`: audited row/thread status
- `publication-curve.tsv`: sampled client-thread curve data
- `saturation-decisions.tsv`: adaptive saturation decisions
- `pairwise-comparisons.tsv`: pairwise comparison output
- `rankings-*.tsv`: ranking summaries
- `calibration-*.tsv`: non-public calibration evidence
- `workload-plan.tsv`: fixed measured workload plan selected after calibration
- `adaptive-run-summary.md`: runner summary
- `adaptive-environment.txt`: run environment metadata
- `launch.txt`: detached launch metadata
- `SHA256SUMS`: checksum manifest for this saved artifact set

Per-block client/server logs were not copied into this tracked result directory
because the source block tree contains tens of thousands of files. They remain
under the ignored source run directory while that `.run/` tree exists.
