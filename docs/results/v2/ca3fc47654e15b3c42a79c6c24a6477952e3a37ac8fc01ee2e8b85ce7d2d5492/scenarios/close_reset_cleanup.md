# Close/reset cleanup

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `lsperf` | 2,614.0 operations/s | 1.359 [1.354, 1.365] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L3) |
| `picoperf` | 1,938.3 operations/s | 1.008 [1.005, 1.011] | equivalent | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L78) |
| `ngtcp2perf` | 1,923.3 operations/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L48) |
| `quicheperf` | 1,693.7 operations/s | 0.881 [0.880, 0.882] | inferior | within planning envelope | invariance supported | invariance supported | [TSV](../row-results.tsv#L93) |
| `quiczigperf` | 1,329.0 operations/s | 0.691 [0.688, 0.694] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L108) |
| `tquicperf` | 1,266.1 operations/s | 0.658 [0.656, 0.661] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L153) |
| `s2nperf` | 1,212.2 operations/s | 0.630 [0.625, 0.635] | inferior | within planning envelope | invariance supported | sensitivity unresolved | [TSV](../row-results.tsv#L138) |
| `neqoperf` | 661.5 operations/s | 0.344 [0.343, 0.345] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L33) |
| `mvfstperf` | 224.8 operations/s | 0.117 [0.116, 0.118] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L18) |
| `quinnperf` | 215.9 operations/s | 0.112 [0.111, 0.113] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L123) |
| `xquicperf` | 176.1 operations/s | 0.092 [0.091, 0.092] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L168) |
| `noqperf` | 140.0 operations/s | 0.073 [0.072, 0.073] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L63) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
