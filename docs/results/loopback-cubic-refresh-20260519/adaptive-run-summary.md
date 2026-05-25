# Adaptive Publication Run

- Publication ID: `adaptive-loopback-cubic-refresh-20260519T024014Z-2661494`
- Status: not_ready
- Adaptive samples: `adaptive-samples.tsv`
- Block size: 5
- Discovery minimum: 4 blocks / 20 samples
- Discovery maximum: 120 samples
- Confirmatory holdout: 2 blocks / 10 samples
- Bootstrap iterations: 5000
- Ready result rows: 4
- Not-ready result rows: 68
- Audited publication rows: 57

## Not Ready Results

| Binary | Scenario | Network | Path | Selected | Reason |
|---|---|---|---|---:|---|
| `lsperf` | `connect` | `iouring` | `loopback` | 1 | no_incremental_plateau;t2:block_median_ratio_1.1691_gt_1.1000;persistent_block_median_ratio_recent_1.1381_gt_1.1000;t1:missing_confirm_stats |
| `lsperf` | `connect` | `syscall` | `loopback` | 1 | no_incremental_plateau;t2:p50_ci_width_0.0882_gt_0.0500;p80_p20_1.1507_gt_1.1500;block_median_ratio_1.1446_gt_1.1000;drift_0.1031_gt_0.0300;severe_drift_0.1031_gt_0.0800;t1:missing_confirm_stats |
| `lsperf` | `download` | `iouring` | `loopback` | 1 | incremental_improvement_-54.48pct_le_1.00pct;t2:confirm_p50_ci_width_0.0541_gt_0.0450;confirm_median_delta_0.1967_gt_0.0450;combined_not_ready_nonstationary;p50_ci_width_0.0464_gt_0.0300;block_median_ratio_1.2190_gt_1.1000 |
| `lsperf` | `download` | `syscall` | `loopback` |  | no_ready_rows;t1:block_median_ratio_1.1205_gt_1.1000;persistent_block_median_ratio_recent_1.1008_gt_1.1000 |
| `lsperf` | `upload` | `iouring` | `loopback` | 2 | no_incremental_plateau;t3:p50_ci_width_0.0395_gt_0.0300;drift_0.0404_gt_0.0300;persistent_drift_0.0404_gt_0.0300;t1:missing_confirm_stats;t2:missing_confirm_stats |
| `lsperf` | `upload` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1060_gt_0.0300;p80_p20_1.1506_gt_1.1500;block_median_ratio_1.1458_gt_1.1000;drift_0.0896_gt_0.0300;severe_drift_0.0896_gt_0.0800 |
| `mvfstperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0508_gt_0.0500;block_median_ratio_1.1362_gt_1.1000;drift_-0.0357_gt_0.0300;persistent_drift_-0.0357_gt_0.0300 |
| `mvfstperf` | `connect` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1489_gt_0.0500;block_median_ratio_1.2938_gt_1.1000;drift_0.0485_gt_0.0300;severe_block_median_ratio_1.2938_gt_1.2500 |
| `mvfstperf` | `download` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0321_gt_0.0300;block_median_ratio_1.1099_gt_1.1000;drift_-0.0349_gt_0.0300;persistent_drift_-0.0349_gt_0.0300 |
| `mvfstperf` | `download` | `syscall` | `loopback` |  | no_ready_rows;t1:drift_-0.0406_gt_0.0300;persistent_drift_-0.0406_gt_0.0300 |
| `mvfstperf` | `upload` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0858_gt_0.0300;block_median_ratio_1.1614_gt_1.1000;persistent_block_median_ratio_recent_1.1186_gt_1.1000 |
| `mvfstperf` | `upload` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0445_gt_0.0300;drift_-0.0446_gt_0.0300;persistent_drift_-0.0446_gt_0.0300 |
| `neqoperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:block_median_ratio_1.2064_gt_1.1000;persistent_block_median_ratio_recent_1.1172_gt_1.1000 |
| `neqoperf` | `connect` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0527_gt_0.0500;drift_0.0431_gt_0.0300;persistent_drift_0.0431_gt_0.0300 |
| `neqoperf` | `download` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0561_gt_0.0300;p80_p20_1.2057_gt_1.1500;drift_0.0340_gt_0.0300;persistent_p80_p20_recent_1.1544_gt_1.1500;persistent_drift_0.0340_gt_0.0300 |
| `neqoperf` | `download` | `syscall` | `loopback` | 1 | incremental_improvement_-8.83pct_le_1.00pct;t1:combined_warning_noisy;p50_ci_width_0.0380_gt_0.0300 |
| `neqoperf` | `upload` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0723_gt_0.0300;p80_p20_1.2038_gt_1.1500;block_median_ratio_1.1756_gt_1.1000;persistent_block_median_ratio_recent_1.1756_gt_1.1000;persistent_p80_p20_recent_1.1898_gt_1.1500 |
| `neqoperf` | `upload` | `syscall` | `loopback` |  | no_ready_rows;t1:block_median_ratio_1.1244_gt_1.1000 |
| `ngtcp2perf` | `connect` | `iouring` | `loopback` | 1 | no_incremental_plateau;t2:p50_ci_width_0.2121_gt_0.0500;p80_p20_1.2911_gt_1.1500;block_median_ratio_1.3059_gt_1.1000;drift_-0.1078_gt_0.0300;severe_block_median_ratio_1.3059_gt_1.2500;severe_drift_-0.1078_gt_0.0800;t1:missing_confirm_stats |
| `ngtcp2perf` | `connect` | `syscall` | `loopback` | 1 | no_incremental_plateau;t2:p50_ci_width_0.1304_gt_0.0500;p80_p20_1.2225_gt_1.1500;block_median_ratio_1.3551_gt_1.1000;drift_-0.0463_gt_0.0300;severe_block_median_ratio_1.3551_gt_1.2500;t1:missing_confirm_stats |
| `ngtcp2perf` | `download` | `iouring` | `loopback` | 1 | no_incremental_plateau;t2:p50_ci_width_0.0440_gt_0.0300;drift_-0.0534_gt_0.0300;persistent_drift_-0.0534_gt_0.0300;t1:missing_confirm_stats |
| `ngtcp2perf` | `download` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1531_gt_0.0300;p80_p20_1.1752_gt_1.1500;block_median_ratio_1.2060_gt_1.1000;drift_-0.1187_gt_0.0300;severe_drift_-0.1187_gt_0.0800 |
| `ngtcp2perf` | `upload` | `iouring` | `loopback` | 1 | no_incremental_plateau;t2:p50_ci_width_0.0331_gt_0.0300;block_median_ratio_1.1216_gt_1.1000;persistent_block_median_ratio_recent_1.1216_gt_1.1000;t1:missing_confirm_stats |
| `ngtcp2perf` | `upload` | `syscall` | `loopback` | 1 | no_incremental_plateau;t2:p50_ci_width_0.0365_gt_0.0300;drift_-0.0402_gt_0.0300;persistent_drift_-0.0402_gt_0.0300;t1:missing_confirm_stats |
| `noqperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1163_gt_0.0500;p80_p20_1.1865_gt_1.1500;block_median_ratio_1.3095_gt_1.1000;drift_-0.0553_gt_0.0300;severe_block_median_ratio_1.3095_gt_1.2500 |
| `noqperf` | `connect` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1605_gt_0.0500;p80_p20_1.2083_gt_1.1500;block_median_ratio_1.2532_gt_1.1000;severe_block_median_ratio_1.2532_gt_1.2500 |
| `noqperf` | `upload` | `iouring` | `loopback` | 1 | incremental_improvement_-9.85pct_le_1.00pct;t2:combined_warning_noisy;p50_ci_width_0.0402_gt_0.0300 |
| `noqperf` | `upload` | `syscall` | `loopback` | 1 | incremental_improvement_-9.44pct_le_1.00pct;t2:confirm_not_ready_high_variance;combined_not_ready_outlier;outliers_1 |
| `picoperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1671_gt_0.0500;p80_p20_1.4075_gt_1.1500;block_median_ratio_1.4028_gt_1.1000;drift_-0.1850_gt_0.0300;severe_block_median_ratio_1.4028_gt_1.2500;severe_drift_-0.1850_gt_0.0800 |
| `picoperf` | `connect` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.2958_gt_0.0500;p80_p20_1.3970_gt_1.1500;block_median_ratio_1.4442_gt_1.1000;severe_block_median_ratio_1.4442_gt_1.2500 |
| `picoperf` | `download` | `iouring` | `loopback` | 1 | no_incremental_plateau;t2:p50_ci_width_0.0722_gt_0.0300;p80_p20_1.1536_gt_1.1500;block_median_ratio_1.1942_gt_1.1000;persistent_block_median_ratio_recent_1.1127_gt_1.1000;persistent_p80_p20_recent_1.1538_gt_1.1500;t1:missing_confirm_stats |
| `picoperf` | `download` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0381_gt_0.0300;block_median_ratio_1.1475_gt_1.1000;drift_-0.0320_gt_0.0300;persistent_drift_-0.0320_gt_0.0300 |
| `picoperf` | `upload` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0412_gt_0.0300;drift_0.0826_gt_0.0300;severe_drift_0.0826_gt_0.0800 |
| `picoperf` | `upload` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0573_gt_0.0300;block_median_ratio_1.1571_gt_1.1000;drift_0.0485_gt_0.0300;persistent_drift_0.0485_gt_0.0300 |
| `quicheperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0650_gt_0.0500;block_median_ratio_1.2066_gt_1.1000;drift_0.0375_gt_0.0300;persistent_block_median_ratio_recent_1.1417_gt_1.1000;persistent_drift_0.0375_gt_0.0300 |
| `quicheperf` | `connect` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1875_gt_0.0500;p80_p20_1.2499_gt_1.1500;block_median_ratio_1.2628_gt_1.1000;drift_-0.1368_gt_0.0300;severe_block_median_ratio_1.2628_gt_1.2500;severe_drift_-0.1368_gt_0.0800 |
| `quicheperf` | `download` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0389_gt_0.0300;drift_0.0467_gt_0.0300;persistent_drift_0.0467_gt_0.0300 |
| `quicheperf` | `download` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0517_gt_0.0300;drift_-0.0489_gt_0.0300;persistent_drift_-0.0489_gt_0.0300 |
| `quicheperf` | `upload` | `iouring` | `loopback` | 1 | no_incremental_plateau;t2:block_median_ratio_1.1350_gt_1.1000;t1:missing_confirm_stats |
| `quicheperf` | `upload` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0410_gt_0.0300;block_median_ratio_1.1127_gt_1.1000;persistent_block_median_ratio_recent_1.1122_gt_1.1000 |
| `quiczigperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.2402_gt_0.0500;p80_p20_1.3196_gt_1.1500;block_median_ratio_1.3889_gt_1.1000;drift_-0.1174_gt_0.0300;severe_block_median_ratio_1.3889_gt_1.2500;severe_drift_-0.1174_gt_0.0800 |
| `quiczigperf` | `connect` | `syscall` | `loopback` | 1 | no_incremental_plateau;t2:p50_ci_width_0.1879_gt_0.0500;p80_p20_1.2903_gt_1.1500;block_median_ratio_1.3407_gt_1.1000;severe_block_median_ratio_1.3407_gt_1.2500;t1:missing_confirm_stats |
| `quiczigperf` | `download` | `iouring` | `loopback` | 1 | no_incremental_plateau;t2:p50_ci_width_0.0704_gt_0.0300;block_median_ratio_1.1124_gt_1.1000;persistent_block_median_ratio_recent_1.1124_gt_1.1000;t1:missing_confirm_stats |
| `quiczigperf` | `download` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0686_gt_0.0300;block_median_ratio_1.1402_gt_1.1000;drift_-0.0300_gt_0.0300;persistent_block_median_ratio_recent_1.1310_gt_1.1000;persistent_drift_-0.0300_gt_0.0300 |
| `quiczigperf` | `upload` | `syscall` | `loopback` |  | no_ready_rows;t1:block_median_ratio_1.1707_gt_1.1000 |
| `quinnperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1687_gt_0.0500;p80_p20_1.2163_gt_1.1500;block_median_ratio_1.2860_gt_1.1000;drift_-0.1516_gt_0.0300;severe_block_median_ratio_1.2860_gt_1.2500;severe_drift_-0.1516_gt_0.0800 |
| `quinnperf` | `connect` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0839_gt_0.0500;p80_p20_1.2100_gt_1.1500;block_median_ratio_1.2046_gt_1.1000;persistent_block_median_ratio_recent_1.2046_gt_1.1000;persistent_p80_p20_recent_1.1915_gt_1.1500 |
| `quinnperf` | `download` | `iouring` | `loopback` | 2 | incremental_improvement_-2.65pct_le_1.00pct;t1:combined_warning_noisy;p50_ci_width_0.0374_gt_0.0300 |
| `quinnperf` | `download` | `syscall` | `loopback` | 2 | incremental_improvement_-1.04pct_le_1.00pct;t2:combined_warning_noisy;p50_ci_width_0.0309_gt_0.0300 |
| `quinnperf` | `upload` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0380_gt_0.0300;drift_0.0330_gt_0.0300;persistent_drift_0.0330_gt_0.0300 |
| `s2nperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1142_gt_0.0500;p80_p20_1.1588_gt_1.1500;block_median_ratio_1.2136_gt_1.1000;drift_0.1264_gt_0.0300;severe_drift_0.1264_gt_0.0800 |
| `s2nperf` | `connect` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1419_gt_0.0500;p80_p20_1.2546_gt_1.1500;block_median_ratio_1.2438_gt_1.1000;drift_0.0893_gt_0.0300;severe_drift_0.0893_gt_0.0800 |
| `s2nperf` | `download` | `iouring` | `loopback` | 4 | no_incremental_plateau;t5:p50_ci_width_0.0317_gt_0.0300;block_median_ratio_1.1245_gt_1.1000;outliers_1;persistent_outliers_1;t1:missing_confirm_stats;t2:missing_confirm_stats;t3:missing_confirm_stats;t4:missing_confirm_stats |
| `s2nperf` | `download` | `syscall` | `loopback` | 3 | no_incremental_plateau;t4:p80_p20_1.2013_gt_1.1500;block_median_ratio_1.1663_gt_1.1000;outliers_4;severe_outlier_blocks_3_gte_2;t1:missing_confirm_stats;t2:missing_confirm_stats;t3:missing_confirm_stats |
| `s2nperf` | `upload` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0942_gt_0.0300;block_median_ratio_1.1645_gt_1.1000;drift_0.1093_gt_0.0300;severe_drift_0.1093_gt_0.0800 |
| `s2nperf` | `upload` | `syscall` | `loopback` | 2 | incremental_improvement_-2.74pct_le_1.00pct;t1:combined_warning_noisy;p50_ci_width_0.0311_gt_0.0300;t2:confirm_p50_ci_width_0.0507_gt_0.0450;t3:combined_warning_noisy;p50_ci_width_0.0310_gt_0.0300 |
| `tquicperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1383_gt_0.0500;p80_p20_1.2298_gt_1.1500;block_median_ratio_1.2567_gt_1.1000;drift_0.0497_gt_0.0300;severe_block_median_ratio_1.2567_gt_1.2500 |
| `tquicperf` | `connect` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1258_gt_0.0500;p80_p20_1.2486_gt_1.1500;block_median_ratio_1.2994_gt_1.1000;drift_-0.0449_gt_0.0300;severe_block_median_ratio_1.2994_gt_1.2500 |
| `tquicperf` | `download` | `iouring` | `loopback` | 3 | incremental_improvement_-2.74pct_le_1.00pct;t1:combined_not_ready_nonstationary;p50_ci_width_0.0360_gt_0.0300;block_median_ratio_1.1119_gt_1.1000;t2:confirm_p50_ci_width_0.0476_gt_0.0450;confirm_median_delta_0.0497_gt_0.0450;combined_not_ready_nonstationary;p50_ci_width_0.0376_gt_0.0300;block_median_ratio_1.1061_gt_1.1000;t3:confirm_p50_ci_width_0.0786_gt_0.0450;combined_warning_noisy;p50_ci_width_0.0319_gt_0.0300 |
| `tquicperf` | `download` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1207_gt_0.0300;block_median_ratio_1.1732_gt_1.1000;drift_-0.1004_gt_0.0300;severe_drift_-0.1004_gt_0.0800 |
| `tquicperf` | `upload` | `iouring` | `loopback` | 2 | incremental_improvement_-4.77pct_le_1.00pct;t2:confirm_p50_ci_width_0.0751_gt_0.0450;combined_warning_noisy;p50_ci_width_0.0418_gt_0.0300 |
| `tquicperf` | `upload` | `syscall` | `loopback` | 2 | incremental_improvement_-2.38pct_le_1.00pct;t2:confirm_p50_ci_width_0.1030_gt_0.0450;combined_not_ready_nonstationary;block_median_ratio_1.1627_gt_1.1000;t3:confirm_p50_ci_width_0.0700_gt_0.0450;combined_not_ready_nonstationary;block_median_ratio_1.1030_gt_1.1000 |
| `xquicperf` | `connect` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.1212_gt_0.0500;p80_p20_1.1989_gt_1.1500;block_median_ratio_1.1957_gt_1.1000;persistent_block_median_ratio_recent_1.1317_gt_1.1000;persistent_p80_p20_recent_1.1793_gt_1.1500 |
| `xquicperf` | `connect` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0528_gt_0.0500;block_median_ratio_1.1539_gt_1.1000;persistent_block_median_ratio_recent_1.1539_gt_1.1000 |
| `xquicperf` | `download` | `iouring` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0461_gt_0.0300;block_median_ratio_1.1484_gt_1.1000;drift_0.0426_gt_0.0300;persistent_block_median_ratio_recent_1.1072_gt_1.1000;persistent_drift_0.0426_gt_0.0300 |
| `xquicperf` | `download` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0579_gt_0.0300;block_median_ratio_1.1198_gt_1.1000;drift_0.0876_gt_0.0300;severe_drift_0.0876_gt_0.0800 |
| `xquicperf` | `upload` | `iouring` | `loopback` |  | no_ready_rows;t1:block_median_ratio_1.1326_gt_1.1000;persistent_block_median_ratio_recent_1.1091_gt_1.1000 |
| `xquicperf` | `upload` | `syscall` | `loopback` |  | no_ready_rows;t1:p50_ci_width_0.0530_gt_0.0300;block_median_ratio_1.1642_gt_1.1000;drift_0.0639_gt_0.0300;persistent_drift_0.0639_gt_0.0300 |
