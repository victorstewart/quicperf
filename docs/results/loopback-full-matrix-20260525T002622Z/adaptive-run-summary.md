# Adaptive Publication Run

- Publication ID: `adaptive-20260525T002622Z-2639460`
- Status: not_ready
- Adaptive samples: `adaptive-samples.tsv`
- Block size: 10
- Discovery minimum: 2 blocks / 20 samples
- Discovery maximum: 120 samples
- Confirmatory holdout: 0 blocks / 0 samples
- Calibration: enabled (2 samples, target 5.000s)
- Tier smoke samples: 2
- Bootstrap iterations: 5000
- Converged result rows: 70
- Failed result rows: 0
- Not-ready result rows: 2
- Audited publication rows: 127

## Incomplete Results

| Status | Binary | Scenario | Network | Path | Selected | Reason |
|---|---|---|---|---|---:|---|
| `not_ready` | `xquicperf` | `download` | `iouring` | `loopback` | 3 | no_incremental_plateau |
| `not_ready` | `xquicperf` | `download` | `syscall` | `loopback` | 3 | no_incremental_plateau |
