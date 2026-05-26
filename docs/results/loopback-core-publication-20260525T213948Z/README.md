# Loopback Core Publication Subset 2026-05-25T21:39Z

Run ID: `adaptive-20260525T213948Z-3320776`
Source run directory: `.run/full-matrix-20260525T213948Z`
Path profile: `loopback`
Networks: `syscall`, `iouring`
Congestion controller: `cubic` for every publication row
Recorded git commit: `e36ee55131379fbfd419fbb584e7cadff6502b8d`
Recorded dirty flag in samples: `clean`

## Status

This is the core publication subset (`download`, `upload`, `connect`), not the full scenario matrix.

- Publication status: `converged`
- Publication rows: 72 converged, 0 not ready, 0 failed
- Publication scenarios: connect=24, download=24, upload=24
- Networks: iouring=36, syscall=36
- Audited publication rows: 134
- Adaptive discovery samples: 8,580 total, 8,580 ok
- Sampled thread rows: 429; average samples per sampled thread row: 20.00
- Calibration samples: 144 total, 144 ok
- Calibration validation samples: 96 total, 96 ok
- Workload plan rows: 72

## Files

- `publication-results.tsv`: selected publication rows used by `docs/latest-results.md`
- `publication-curve.tsv`: measured client-thread curve through the selected saturation boundary
- `publication-row-audit.tsv`: gate decisions and diagnostic reasons for audited rows
- `adaptive-samples.tsv`: measured discovery samples only; calibration is excluded
- `calibration-samples.tsv`: non-public calibration probes
- `calibration-validation-samples.tsv`: non-public scale-up validation probes
- `calibration-decisions.tsv`: calibration choices and fallback decisions
- `workload-plan.tsv`: declared measured workload size for each publication row
- `row-stats.tsv`: per-thread row statistics
- `saturation-decisions.tsv`: selected client-thread decisions
- `rankings-*.tsv` and `pairwise-comparisons.tsv`: generated ranking diagnostics
- `adaptive-environment.txt` and `launch.txt`: run configuration metadata
- `SHA256SUMS`: checksums for this published artifact set

Per-block process logs remain in the ignored source run directory while it is retained locally.
