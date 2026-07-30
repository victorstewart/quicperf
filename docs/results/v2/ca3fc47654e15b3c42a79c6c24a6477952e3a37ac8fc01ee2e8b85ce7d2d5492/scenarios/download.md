# Download

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `lsperf` | 1.645 Gbit/s | 2.067 [2.032, 2.102] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L6) |
| `s2nperf` | 1.184 Gbit/s | 1.488 [1.459, 1.518] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L141) |
| `picoperf` | 1.159 Gbit/s | 1.456 [1.430, 1.483] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L81) |
| `quiczigperf` | 1.043 Gbit/s | 1.311 [1.289, 1.333] | superior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L111) |
| `tquicperf` | 0.887 Gbit/s | 1.114 [1.094, 1.135] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L156) |
| `mvfstperf` | 0.852 Gbit/s | 1.070 [1.049, 1.092] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L21) |
| `quicheperf` | 0.831 Gbit/s | 1.044 [1.028, 1.061] | inconclusive | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L96) |
| `ngtcp2perf` | 0.796 Gbit/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L51) |
| `quinnperf` | 0.700 Gbit/s | 0.880 [0.864, 0.896] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L126) |
| `xquicperf` | 0.687 Gbit/s | 0.863 [0.852, 0.874] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L171) |
| `neqoperf` | 0.655 Gbit/s | 0.823 [0.809, 0.836] | inferior | within planning envelope | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L36) |
| `noqperf` | 0.522 Gbit/s | 0.657 [0.644, 0.669] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L66) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
