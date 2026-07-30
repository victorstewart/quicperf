# Stream churn

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `lsperf` | 51,151.7 operations/s | 2.387 [2.379, 2.394] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L14) |
| `picoperf` | 47,130.6 operations/s | 2.199 [2.189, 2.209] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L89) |
| `quicheperf` | 26,180.3 operations/s | 1.221 [1.217, 1.226] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L104) |
| `mvfstperf` | 23,442.3 operations/s | 1.094 [1.090, 1.097] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L29) |
| `ngtcp2perf` | 21,433.6 operations/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L59) |
| `tquicperf` | 20,841.5 operations/s | 0.972 [0.968, 0.977] | inconclusive | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L164) |
| `s2nperf` | 17,948.0 operations/s | 0.837 [0.828, 0.847] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L149) |
| `quinnperf` | 16,294.8 operations/s | 0.760 [0.752, 0.769] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L134) |
| `neqoperf` | 11,311.9 operations/s | 0.528 [0.525, 0.530] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L44) |
| `noqperf` | 10,002.1 operations/s | 0.467 [0.463, 0.470] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L74) |
| `xquicperf` | 3,384.6 operations/s | 0.158 [0.156, 0.160] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L179) |
| `quiczigperf` | 2,134.7 operations/s | 0.100 [0.099, 0.100] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L119) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
