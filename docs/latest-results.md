# Latest Results

The adaptive publication runner samples each library/network/test row in randomized blocks until the row converges or reaches its bounded sample cap. Rows that remain noisy or nonstationary are retained with their measured distribution instead of being promoted as clean.

Client load is swept upward per row to find server saturation using as many client threads as needed within the configured limit. Tables are sorted by best bad-tail p99 first; for rate and throughput metrics that means the higher lower-tail value is better.

Current run status: `not_ready`. The run produced 4 clean publication rows and 74 rows that remain noisy, nonstationary, unsupported, or otherwise gated; the tables below use the best available measured distributions and the gate details remain the source of truth.

The TCP+TLS sidecar is excluded from these QUIC tables. Full raw data and gate details are committed under [`results/loopback-cubic-refresh-20260519`](results/loopback-cubic-refresh-20260519/).

## Results

### Download

Server-to-client bulk transfer; higher throughput is better.

| Library | Network | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | cubic | 1 | 30 | gigabits/second | 18.772 | 17.432 | 16.887 |
| ngtcp2 | io_uring | cubic | 1 | 20 | gigabits/second | 15.905 | 15.331 | 15.140 |
| LSQUIC | syscall | cubic | 1 | 110 | gigabits/second | 16.028 | 14.646 | 13.694 |
| XQUIC | syscall | cubic | 1 | 30 | gigabits/second | 11.748 | 10.835 | 10.653 |
| LSQUIC | io_uring | cubic | 1 | 30 | gigabits/second | 10.626 | 10.506 | 10.448 |
| quiche | syscall | cubic | 1 | 40 | gigabits/second | 10.879 | 10.465 | 10.318 |
| TQUIC | syscall | cubic | 1 | 30 | gigabits/second | 10.551 | 9.920 | 9.655 |
| quic-zig | syscall | cubic | 1 | 40 | gigabits/second | 10.582 | 10.221 | 9.432 |
| picoquic | io_uring | cubic | 1 | 25 | gigabits/second | 9.375 | 8.763 | 8.645 |
| XQUIC | io_uring | cubic | 1 | 50 | gigabits/second | 10.488 | 9.562 | 8.627 |
| TQUIC | io_uring | cubic | 3 | 30 | gigabits/second | 9.129 | 8.651 | 8.557 |
| quiche | io_uring | cubic | 1 | 40 | gigabits/second | 8.969 | 8.498 | 8.207 |
| quic-zig | io_uring | cubic | 1 | 20 | gigabits/second | 8.552 | 8.262 | 8.191 |
| picoquic | syscall | cubic | 1 | 50 | gigabits/second | 8.881 | 8.565 | 7.805 |
| Quinn | syscall | cubic | 2 | 30 | gigabits/second | 7.111 | 6.851 | 6.762 |
| Quinn | io_uring | cubic | 2 | 30 | gigabits/second | 6.776 | 6.666 | 6.616 |
| s2n-quic | io_uring | cubic | 4 | 20 | gigabits/second | 6.410 | 6.313 | 6.263 |
| noq | syscall | cubic | 2 | 30 | gigabits/second | 5.760 | 5.662 | 5.618 |
| noq | io_uring | cubic | 2 | 30 | gigabits/second | 5.583 | 5.510 | 5.464 |
| s2n-quic | syscall | cubic | 3 | 40 | gigabits/second | 6.429 | 6.257 | 5.354 |
| Neqo | syscall | cubic | 1 | 40 | gigabits/second | 4.547 | 4.412 | 4.325 |
| Neqo | io_uring | cubic | 1 | 40 | gigabits/second | 4.181 | 4.011 | 3.815 |
| mvfst | syscall | cubic | 1 | 40 | gigabits/second | 4.233 | 3.752 | 3.475 |
| mvfst | io_uring | cubic | 1 | 65 | gigabits/second | 3.613 | 3.344 | 3.179 |

### Upload

Client-to-server bulk transfer; higher throughput is better.

| Library | Network | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | cubic | 1 | 30 | gigabits/second | 18.034 | 16.757 | 16.337 |
| ngtcp2 | io_uring | cubic | 1 | 40 | gigabits/second | 16.113 | 15.615 | 15.262 |
| LSQUIC | syscall | cubic | 1 | 30 | gigabits/second | 14.691 | 13.259 | 12.913 |
| LSQUIC | io_uring | cubic | 2 | 20 | gigabits/second | 12.606 | 12.463 | 12.214 |
| TQUIC | syscall | cubic | 2 | 50 | gigabits/second | 12.863 | 12.290 | 12.035 |
| TQUIC | io_uring | cubic | 2 | 35 | gigabits/second | 11.654 | 11.243 | 11.104 |
| quiche | syscall | cubic | 1 | 45 | gigabits/second | 10.308 | 9.848 | 9.521 |
| XQUIC | syscall | cubic | 1 | 40 | gigabits/second | 11.301 | 10.309 | 9.433 |
| quic-zig | syscall | cubic | 1 | 120 | gigabits/second | 10.398 | 9.960 | 9.248 |
| picoquic | io_uring | cubic | 1 | 30 | gigabits/second | 9.034 | 8.505 | 8.197 |
| XQUIC | io_uring | cubic | 1 | 60 | gigabits/second | 10.332 | 9.527 | 8.193 |
| quic-zig | io_uring | cubic | 1 | 65 | gigabits/second | 8.249 | 7.903 | 7.628 |
| picoquic | syscall | cubic | 1 | 40 | gigabits/second | 8.595 | 8.142 | 7.554 |
| quiche | io_uring | cubic | 1 | 90 | gigabits/second | 8.492 | 7.829 | 7.193 |
| s2n-quic | syscall | cubic | 2 | 30 | gigabits/second | 7.329 | 7.120 | 6.938 |
| Neqo | syscall | cubic | 1 | 120 | gigabits/second | 4.698 | 4.553 | 4.429 |
| s2n-quic | io_uring | cubic | 1 | 30 | gigabits/second | 5.451 | 4.791 | 3.990 |
| Neqo | io_uring | cubic | 1 | 40 | gigabits/second | 4.652 | 4.010 | 3.914 |
| Quinn | io_uring | cubic | 1 | 40 | gigabits/second | 3.903 | 3.737 | 3.684 |
| Quinn | syscall | cubic | 1 | 45 | gigabits/second | 3.718 | 3.649 | 3.587 |
| noq | io_uring | cubic | 1 | 55 | gigabits/second | 3.456 | 3.344 | 3.251 |
| noq | syscall | cubic | 1 | 30 | gigabits/second | 3.275 | 3.192 | 3.148 |
| mvfst | syscall | cubic | 1 | 40 | gigabits/second | 2.918 | 2.827 | 2.763 |
| mvfst | io_uring | cubic | 1 | 45 | gigabits/second | 2.415 | 2.334 | 2.016 |

### Connect

Full connection establishment plus stream creation.

| Library | Network | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | io_uring | cubic | 1 | 20 | connections/second | 1,783 | 1,631 | 1,466 |
| Quinn | io_uring | cubic | 1 | 30 | connections/second | 1,660 | 1,398 | 1,372 |
| noq | io_uring | cubic | 1 | 40 | connections/second | 1,588 | 1,276 | 1,247 |
| XQUIC | io_uring | cubic | 1 | 40 | connections/second | 1,401 | 1,251 | 1,225 |
| quiche | io_uring | cubic | 1 | 40 | connections/second | 1,396 | 1,192 | 1,119 |
| s2n-quic | io_uring | cubic | 1 | 30 | connections/second | 1,278 | 1,088 | 1,065 |
| Quinn | syscall | cubic | 1 | 40 | connections/second | 1,415 | 1,178 | 1,011 |
| ngtcp2 | syscall | cubic | 1 | 25 | connections/second | 1,175 | 1,036 | 964 |
| noq | syscall | cubic | 1 | 30 | connections/second | 1,316 | 1,111 | 915 |
| LSQUIC | io_uring | cubic | 1 | 20 | connections/second | 1,135 | 974 | 881 |
| picoquic | io_uring | cubic | 1 | 30 | connections/second | 1,311 | 984 | 871 |
| LSQUIC | syscall | cubic | 1 | 25 | connections/second | 1,005 | 927 | 850 |
| quic-zig | io_uring | cubic | 1 | 30 | connections/second | 1,203 | 946 | 791 |
| quic-zig | syscall | cubic | 1 | 25 | connections/second | 1,075 | 893 | 790 |
| quiche | syscall | cubic | 1 | 30 | connections/second | 897 | 815 | 743 |
| TQUIC | syscall | cubic | 1 | 30 | connections/second | 1,019 | 830 | 707 |
| TQUIC | io_uring | cubic | 1 | 40 | connections/second | 1,472 | 1,223 | 670 |
| picoquic | syscall | cubic | 1 | 30 | connections/second | 855 | 701 | 648 |
| s2n-quic | syscall | cubic | 1 | 30 | connections/second | 1,045 | 839 | 623 |
| XQUIC | syscall | cubic | 1 | 40 | connections/second | 994 | 879 | 594 |
| Neqo | io_uring | cubic | 1 | 55 | connections/second | 436 | 380 | 322 |
| Neqo | syscall | cubic | 1 | 40 | connections/second | 402 | 336 | 305 |
| mvfst | io_uring | cubic | 1 | 40 | connections/second | 330 | 298 | 266 |
| mvfst | syscall | cubic | 1 | 30 | connections/second | 310 | 251 | 227 |

## Caveats

- `idle_footprint` is omitted from the current table because it was not part of this loopback refresh scenario set.
- `datagram` is omitted from the adaptive publication table; DATAGRAM support is covered by the high-value capability smoke and should remain separate until a fair adaptive DATAGRAM publication run is configured.
- Unsupported capability rows are explicit unsupported markers, not crashes.
- Row-level caveats and full gate reasons are in [`publication-results.tsv`](results/loopback-cubic-refresh-20260519/publication-results.tsv), [`row-stats.tsv`](results/loopback-cubic-refresh-20260519/row-stats.tsv), [`publication-row-audit.tsv`](results/loopback-cubic-refresh-20260519/publication-row-audit.tsv), and [`saturation-decisions.tsv`](results/loopback-cubic-refresh-20260519/saturation-decisions.tsv).
- Raw samples are in [`adaptive-samples.tsv`](results/loopback-cubic-refresh-20260519/adaptive-samples.tsv).
