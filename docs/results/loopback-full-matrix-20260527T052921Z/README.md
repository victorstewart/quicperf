# Loopback Full Matrix 2026-05-27T05:29Z

Run ID: `adaptive-20260527T052921Z-440980`
Source run directory: `.run/full-matrix-20260527T052921Z`
Path profile: `loopback`
Networks: `syscall`, `iouring`
Congestion controller: `cubic` for every row
Recorded source commit before this publication commit: `10fffc0b43b84d2200776b221733a2b1a8770219`

## Status

This is the full loopback scenario matrix for the 12 primary QUIC binaries.

- Publication status: `converged`
- Selected rows: 384 converged, 0 not ready, 0 failed
- Row tiers: 240 publication, 96 lifecycle smoke, 48 capability smoke
- Scenarios: 16 scenarios, 24 rows each
- Networks: iouring=192, syscall=192
- Adaptive discovery samples: 23,048 total, 23,048 ok
- Sampled thread rows: 1,282; average samples per sampled thread row: 17.98
- Average samples per selected binary/scenario/network row: 60.02
- Calibration samples: 480 total, 480 ok
- Calibration validation samples: 384 total, 384 ok

## Files

- `publication-results.tsv`: selected rows used by `docs/latest-results.md`
- `publication-curve.tsv`: measured client-thread curves through each saturation boundary
- `publication-row-audit.tsv`: gate decisions and diagnostic reasons
- `adaptive-samples.tsv`: measured discovery samples only; calibration is excluded
- `calibration-samples.tsv`: non-public calibration probes
- `calibration-validation-samples.tsv`: non-public scale-up validation probes
- `calibration-decisions.tsv`: calibration choices and fallback decisions
- `workload-plan.tsv`: declared measured workload size for each row
- `row-stats.tsv`: per-thread row statistics
- `saturation-decisions.tsv`: selected client-thread decisions
- `rankings-*.tsv` and `pairwise-comparisons.tsv`: generated ranking diagnostics
- `adaptive-environment.txt` and `launch.txt`: run configuration metadata
- `SHA256SUMS`: checksums for this published artifact set

Per-block process logs remain in the ignored source run directory while it is
retained locally.
