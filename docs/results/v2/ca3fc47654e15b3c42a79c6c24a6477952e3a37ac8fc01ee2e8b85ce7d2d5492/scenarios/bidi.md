# Bidirectional transfer

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `lsperf` | 1.653 Gbit/s | 2.483 [2.399, 2.570] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L2) |
| `picoperf` | 1.148 Gbit/s | 1.724 [1.667, 1.783] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L77) |
| `s2nperf` | 1.125 Gbit/s | 1.691 [1.624, 1.760] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L137) |
| `quiczigperf` | 0.848 Gbit/s | 1.274 [1.230, 1.320] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L107) |
| `quicheperf` | 0.669 Gbit/s | 1.005 [0.953, 1.060] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L92) |
| `ngtcp2perf` | 0.666 Gbit/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L47) |
| `mvfstperf` | 0.644 Gbit/s | 0.967 [0.926, 1.010] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L17) |
| `neqoperf` | 0.537 Gbit/s | 0.806 [0.778, 0.836] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L32) |
| `quinnperf` | 0.524 Gbit/s | 0.787 [0.761, 0.815] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L122) |
| `tquicperf` | 0.508 Gbit/s | 0.763 [0.723, 0.806] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L152) |
| `xquicperf` | 0.345 Gbit/s | 0.519 [0.490, 0.550] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L167) |
| `noqperf` | 0.336 Gbit/s | 0.504 [0.490, 0.519] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L62) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
