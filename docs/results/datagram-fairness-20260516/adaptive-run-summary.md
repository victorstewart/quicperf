# Adaptive Publication Run

- Publication ID: `adaptive-datagram-fairness-inspection-20260516T045211Z`
- Status: not_ready
- Adaptive samples: `adaptive-samples.tsv`
- Block size: 3
- Discovery minimum: 4 blocks / 12 samples
- Discovery maximum: 24 samples
- Confirmatory holdout: 1 blocks / 3 samples
- Bootstrap iterations: 1000
- Ready result rows: 1
- Not-ready result rows: 11
- Audited publication rows: 15

## Not Ready Results

| Binary | Scenario | Network | Selected | Reason |
|---|---|---|---:|---|
| `neqoperf` | `datagram` | `iouring` |  | no_ready_rows;t1:p50_ci_width_0.0744_gt_0.0500;block_median_ratio_1.1091_gt_1.1000 |
| `neqoperf` | `datagram` | `syscall` | 1 | t1:confirm_p50_ci_width_0.1217_gt_0.0750;combined_warning_noisy;p50_ci_width_0.0525_gt_0.0500 |
| `noqperf` | `datagram` | `iouring` | 2 | t3:combined_not_ready_max_samples;drift_-0.0360_gt_0.0300 |
| `quicheperf` | `datagram` | `iouring` |  | no_ready_rows;t1:p50_ci_width_0.0682_gt_0.0500;block_median_ratio_1.2905_gt_1.1000;drift_-0.0426_gt_0.0300 |
| `quicheperf` | `datagram` | `syscall` |  | no_ready_rows;t1:p50_ci_width_0.0516_gt_0.0500 |
| `quiczigperf` | `datagram` | `iouring` |  | no_ready_rows;t1:block_median_ratio_1.1514_gt_1.1000 |
| `quiczigperf` | `datagram` | `syscall` | 3 | sentinels_0_lt_1;max_threads_reached;t1:missing_confirm_stats;t2:missing_confirm_stats;t3:missing_confirm_stats |
| `quinnperf` | `datagram` | `iouring` |  | no_ready_rows;t1:p50_ci_width_0.0527_gt_0.0500;block_median_ratio_1.1189_gt_1.1000;drift_-0.0315_gt_0.0300 |
| `quinnperf` | `datagram` | `syscall` |  | no_ready_rows;t1:p50_ci_width_0.0637_gt_0.0500;block_median_ratio_1.1081_gt_1.1000;drift_-0.0359_gt_0.0300 |
| `s2nperf` | `datagram` | `iouring` | 1 | sentinels_0_lt_1;t2:block_median_ratio_1.2251_gt_1.1000;drift_0.0349_gt_0.0300;t1:missing_confirm_stats;t2:block_median_ratio_1.2251_gt_1.1000;drift_0.0349_gt_0.0300;missing_confirm_stats;block_median_ratio_1.2251_gt_1.1000;drift_0.0349_gt_0.0300 |
| `s2nperf` | `datagram` | `syscall` | 1 | sentinels_0_lt_1;t2:p50_ci_width_0.1038_gt_0.0500;p80_p20_1.3014_gt_1.1500;block_median_ratio_1.3476_gt_1.1000;drift_-0.0340_gt_0.0300;t1:missing_confirm_stats;t2:p50_ci_width_0.1038_gt_0.0500;p80_p20_1.3014_gt_1.1500;block_median_ratio_1.3476_gt_1.1000;drift_-0.0340_gt_0.0300;missing_confirm_stats;p50_ci_width_0.1038_gt_0.0500;p80_p20_1.3014_gt_1.1500;block_median_ratio_1.3476_gt_1.1000;drift_-0.0340_gt_0.0300 |
