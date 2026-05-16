# Adaptive Publication Run

- Publication ID: `adaptive-datagram-fairness-20260516T033029Z`
- Status: not_ready
- Adaptive samples: `adaptive-samples.tsv`
- Block size: 5
- Discovery minimum: 4 blocks / 20 samples
- Discovery maximum: 120 samples
- Confirmatory holdout: 2 blocks / 10 samples
- Bootstrap iterations: 5000
- Ready result rows: 0
- Not-ready result rows: 24
- Audited publication rows: 12

## Not Ready Results

| Binary | Scenario | Network | Selected | Reason |
|---|---|---|---:|---|
| `lsperf` | `datagram` | `iouring` |  | requires_quic_datagram_adapter_api |
| `lsperf` | `datagram` | `syscall` |  | requires_quic_datagram_adapter_api |
| `mvfstperf` | `datagram` | `iouring` |  | requires_quic_datagram_adapter_api |
| `mvfstperf` | `datagram` | `syscall` |  | requires_quic_datagram_adapter_api |
| `neqoperf` | `datagram` | `iouring` | 1 | t1:confirm_p50_ci_width_0.1144_gt_0.0750;confirm_median_delta_0.0807_gt_0.0750;combined_not_ready_nonstationary;p50_ci_width_0.0725_gt_0.0500;block_median_ratio_1.2080_gt_1.1000 |
| `neqoperf` | `datagram` | `syscall` | 1 | t1:combined_warning_noisy;p50_ci_width_0.0524_gt_0.0500 |
| `ngtcp2perf` | `datagram` | `iouring` |  | requires_quic_datagram_adapter_api |
| `ngtcp2perf` | `datagram` | `syscall` |  | requires_quic_datagram_adapter_api |
| `noqperf` | `datagram` | `iouring` |  | no_ready_rows;t1:block_median_ratio_1.1573_gt_1.1000;drift_0.0335_gt_0.0300;persistent_block_median_ratio_recent_1.1361_gt_1.1000;persistent_drift_0.0335_gt_0.0300 |
| `noqperf` | `datagram` | `syscall` | 1 | sentinels_0_lt_2;t2:block_median_ratio_1.1079_gt_1.1000;persistent_block_median_ratio_recent_1.1021_gt_1.1000;t1:missing_confirm_stats;t2:block_median_ratio_1.1079_gt_1.1000;persistent_block_median_ratio_recent_1.1021_gt_1.1000;missing_confirm_stats;block_median_ratio_1.1079_gt_1.1000;persistent_block_median_ratio_recent_1.1021_gt_1.1000 |
| `picoperf` | `datagram` | `iouring` |  | requires_quic_datagram_adapter_api |
| `picoperf` | `datagram` | `syscall` |  | requires_quic_datagram_adapter_api |
| `quicheperf` | `datagram` | `iouring` |  | no_ready_rows;t1:p50_ci_width_0.2033_gt_0.0500;p80_p20_1.2791_gt_1.1500;block_median_ratio_1.2698_gt_1.1000;drift_0.0717_gt_0.0300;severe_block_median_ratio_1.2698_gt_1.2500 |
| `quicheperf` | `datagram` | `syscall` |  | no_ready_rows;t1:p50_ci_width_0.1013_gt_0.0500;p80_p20_1.1910_gt_1.1500;block_median_ratio_1.2565_gt_1.1000;severe_block_median_ratio_1.2565_gt_1.2500 |
| `quiczigperf` | `datagram` | `iouring` | 1 | sentinels_1_lt_2;t3:p50_ci_width_0.0768_gt_0.0500;block_median_ratio_1.1702_gt_1.1000;persistent_block_median_ratio_recent_1.1228_gt_1.1000;t1:missing_confirm_stats;t3:p50_ci_width_0.0768_gt_0.0500;block_median_ratio_1.1702_gt_1.1000;persistent_block_median_ratio_recent_1.1228_gt_1.1000;missing_confirm_stats;p50_ci_width_0.0768_gt_0.0500;block_median_ratio_1.1702_gt_1.1000;persistent_block_median_ratio_recent_1.1228_gt_1.1000 |
| `quiczigperf` | `datagram` | `syscall` |  | no_ready_rows;t1:p50_ci_width_0.0694_gt_0.0500;block_median_ratio_1.1298_gt_1.1000;drift_0.0515_gt_0.0300;persistent_block_median_ratio_recent_1.1298_gt_1.1000;persistent_drift_0.0515_gt_0.0300 |
| `quinnperf` | `datagram` | `iouring` | 1 | sentinels_1_lt_2;t3:block_median_ratio_1.1447_gt_1.1000;persistent_block_median_ratio_recent_1.1091_gt_1.1000;t1:missing_confirm_stats;t3:block_median_ratio_1.1447_gt_1.1000;persistent_block_median_ratio_recent_1.1091_gt_1.1000;missing_confirm_stats;block_median_ratio_1.1447_gt_1.1000;persistent_block_median_ratio_recent_1.1091_gt_1.1000 |
| `quinnperf` | `datagram` | `syscall` | 1 | t1:confirm_p50_ci_width_0.0882_gt_0.0750;confirm_p80_p20_1.2081_gt_1.1500;confirm_not_ready_high_variance;combined_not_ready_nonstationary;block_median_ratio_1.1514_gt_1.1000;drift_-0.0366_gt_0.0300 |
| `s2nperf` | `datagram` | `iouring` |  | no_ready_rows;t1:p50_ci_width_0.0609_gt_0.0500;block_median_ratio_1.1029_gt_1.1000;drift_-0.0384_gt_0.0300;persistent_drift_-0.0384_gt_0.0300 |
| `s2nperf` | `datagram` | `syscall` |  | no_ready_rows;t1:block_median_ratio_1.1683_gt_1.1000;persistent_block_median_ratio_recent_1.1061_gt_1.1000 |
| `tquicperf` | `datagram` | `iouring` |  | requires_quic_datagram_adapter_api |
| `tquicperf` | `datagram` | `syscall` |  | requires_quic_datagram_adapter_api |
| `xquicperf` | `datagram` | `iouring` |  | requires_quic_datagram_adapter_api |
| `xquicperf` | `datagram` | `syscall` |  | requires_quic_datagram_adapter_api |
