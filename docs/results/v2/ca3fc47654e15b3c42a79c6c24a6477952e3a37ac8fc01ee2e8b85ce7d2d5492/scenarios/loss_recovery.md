# Loss recovery

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `picoperf` | 0.748 Gbit/s | 7.417 [6.981, 7.881] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L83) |
| `quicheperf` | 0.467 Gbit/s | 4.624 [4.326, 4.943] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L98) |
| `lsperf` | 0.173 Gbit/s | 1.717 [1.684, 1.750] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L8) |
| `quiczigperf` | 0.121 Gbit/s | 1.201 [1.192, 1.210] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L113) |
| `xquicperf` | 0.118 Gbit/s | 1.172 [1.160, 1.183] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L173) |
| `tquicperf` | 0.111 Gbit/s | 1.099 [1.087, 1.111] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L158) |
| `quinnperf` | 0.102 Gbit/s | 1.015 [1.004, 1.026] | equivalent | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L128) |
| `noqperf` | 0.101 Gbit/s | 1.001 [0.989, 1.013] | equivalent | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L68) |
| `ngtcp2perf` | 0.101 Gbit/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L53) |
| `s2nperf` | 0.090 Gbit/s | 0.893 [0.880, 0.906] | inferior | within planning envelope | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L143) |
| `mvfstperf` | 0.085 Gbit/s | 0.847 [0.837, 0.857] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L23) |
| `neqoperf` | 0.083 Gbit/s | 0.819 [0.812, 0.827] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L38) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
