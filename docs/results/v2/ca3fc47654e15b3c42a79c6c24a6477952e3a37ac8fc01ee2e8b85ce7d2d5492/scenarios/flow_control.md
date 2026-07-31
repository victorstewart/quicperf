# Flow control

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `picoperf` | 0.952 Gbit/s | 2.076 [2.030, 2.122] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L82) |
| `lsperf` | 0.914 Gbit/s | 1.993 [1.955, 2.033] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L7) |
| `quicheperf` | 0.606 Gbit/s | 1.321 [1.294, 1.348] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L97) |
| `s2nperf` | 0.574 Gbit/s | 1.252 [1.223, 1.282] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L142) |
| `mvfstperf` | 0.552 Gbit/s | 1.203 [1.173, 1.234] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L22) |
| `tquicperf` | 0.528 Gbit/s | 1.151 [1.130, 1.173] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L157) |
| `quiczigperf` | 0.519 Gbit/s | 1.132 [1.105, 1.160] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L112) |
| `ngtcp2perf` | 0.459 Gbit/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L52) |
| `quinnperf` | 0.425 Gbit/s | 0.928 [0.908, 0.947] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L127) |
| `neqoperf` | 0.379 Gbit/s | 0.826 [0.807, 0.845] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L37) |
| `noqperf` | 0.279 Gbit/s | 0.609 [0.594, 0.625] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L67) |
| `xquicperf` | 0.151 Gbit/s | 0.330 [0.323, 0.337] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L172) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
