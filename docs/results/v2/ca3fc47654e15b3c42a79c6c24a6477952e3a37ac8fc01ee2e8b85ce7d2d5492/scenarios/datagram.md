# QUIC DATAGRAM

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `picoperf` | 272,391.9 operations/s | 3.106 [3.049, 3.165] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L80) |
| `lsperf` | 239,387.8 operations/s | 2.730 [2.690, 2.771] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L5) |
| `quiczigperf` | 149,355.8 operations/s | 1.703 [1.681, 1.725] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L110) |
| `quicheperf` | 139,292.1 operations/s | 1.589 [1.560, 1.617] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L95) |
| `s2nperf` | 128,349.5 operations/s | 1.464 [1.431, 1.497] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L140) |
| `neqoperf` | 97,236.5 operations/s | 1.109 [1.091, 1.127] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L35) |
| `quinnperf` | 92,494.1 operations/s | 1.055 [1.038, 1.072] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L125) |
| `ngtcp2perf` | 87,686.7 operations/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L50) |
| `noqperf` | 54,026.8 operations/s | 0.616 [0.604, 0.629] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L65) |
| `mvfstperf` | 53,764.0 operations/s | 0.613 [0.603, 0.623] | inferior | within planning envelope | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L20) |
| `tquicperf` | 49,283.8 operations/s | 0.562 [0.538, 0.587] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L155) |
| `xquicperf` | 8,953.2 operations/s | 0.102 [0.100, 0.104] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L170) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
