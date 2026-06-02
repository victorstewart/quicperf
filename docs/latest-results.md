# Latest Results

The publication runner uses a predeclared plan: scout data selects client threads, then fixed randomized publication blocks collect the measured samples without adaptive extension.

Tables are sorted by p50, the publication statistic. p90 and p99 remain diagnostic tail-visibility columns unless a separate tail campaign has enough samples to claim them.

Current run status: `complete`. The run completed 384 of 384 selected rows: 302 publishable, 82 inconclusive/noisy, 0 failed, and 0 unsupported.

All completed selected rows are shown below. `inconclusive` means the row completed but tripped at least one audit gate; it is data with a visible caveat, not a failed or hidden row.

Raw QUIC data and gate details are committed under [`results/fixed-full-matrix-max16-20260601T175816Z`](results/fixed-full-matrix-max16-20260601T175816Z/).

## Results

### Download

Server-to-client bulk transfer; higher throughput is better.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| ngtcp2 | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 18.227 | 16.845 | 16.297 |
| ngtcp2 | io_uring | cubic | 4 | 20 | inconclusive | gigabits/second | 16.720 | 16.023 | 15.808 |
| LSQUIC | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 16.446 | 15.002 | 14.477 |
| LSQUIC | io_uring | cubic | 1 | 20 | inconclusive | gigabits/second | 15.026 | 13.597 | 13.303 |
| quiche | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 11.258 | 10.227 | 9.963 |
| quic-zig | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 10.463 | 10.237 | 10.018 |
| quic-zig | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 10.375 | 9.977 | 9.945 |
| quiche | io_uring | cubic | 1 | 20 | inconclusive | gigabits/second | 9.804 | 9.047 | 9.013 |
| picoquic | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 9.691 | 9.406 | 9.352 |
| picoquic | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 8.906 | 8.740 | 8.632 |
| TQUIC | io_uring | cubic | 1 | 20 | inconclusive | gigabits/second | 8.872 | 8.349 | 8.011 |
| TQUIC | syscall | cubic | 1 | 20 | publishable | gigabits/second | 8.600 | 8.422 | 8.379 |
| mvfst | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 7.586 | 6.849 | 6.735 |
| mvfst | syscall | cubic | 1 | 20 | publishable | gigabits/second | 7.483 | 6.853 | 6.796 |
| XQUIC | syscall | cubic | 16 | 20 | inconclusive | gigabits/second | 7.234 | 6.542 | 6.247 |
| Quinn | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 6.870 | 6.673 | 6.643 |
| Quinn | syscall | cubic | 2 | 20 | publishable | gigabits/second | 6.695 | 6.479 | 6.393 |
| s2n-quic | syscall | cubic | 2 | 20 | inconclusive | gigabits/second | 5.683 | 5.364 | 1.896 |
| s2n-quic | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 5.624 | 5.587 | 5.566 |
| noq | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 5.498 | 5.451 | 5.409 |
| noq | syscall | cubic | 2 | 20 | publishable | gigabits/second | 5.387 | 5.254 | 5.240 |
| Neqo | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 4.392 | 4.333 | 4.262 |
| Neqo | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 4.374 | 4.264 | 4.244 |
| XQUIC | io_uring | cubic | 2 | 20 | inconclusive | gigabits/second | 2.037 | 1.605 | 1.569 |

### Upload

Client-to-server bulk transfer; higher throughput is better.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| LSQUIC | syscall | cubic | 2 | 20 | inconclusive | gigabits/second | 33.495 | 29.499 | 28.286 |
| ngtcp2 | syscall | cubic | 2 | 20 | publishable | gigabits/second | 31.047 | 27.761 | 27.221 |
| LSQUIC | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 23.576 | 22.950 | 21.833 |
| ngtcp2 | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 22.270 | 20.210 | 19.955 |
| picoquic | syscall | cubic | 2 | 20 | publishable | gigabits/second | 15.823 | 15.480 | 15.344 |
| quiche | syscall | cubic | 4 | 20 | publishable | gigabits/second | 14.794 | 14.543 | 14.486 |
| picoquic | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 14.549 | 14.227 | 14.142 |
| TQUIC | syscall | cubic | 16 | 20 | publishable | gigabits/second | 14.251 | 14.027 | 13.872 |
| quiche | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 13.755 | 13.592 | 13.336 |
| TQUIC | io_uring | cubic | 4 | 20 | inconclusive | gigabits/second | 12.097 | 11.961 | 11.852 |
| quic-zig | syscall | cubic | 1 | 20 | publishable | gigabits/second | 10.642 | 10.289 | 10.111 |
| quic-zig | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 10.640 | 10.361 | 9.951 |
| mvfst | syscall | cubic | 8 | 20 | publishable | gigabits/second | 8.248 | 8.115 | 8.088 |
| mvfst | io_uring | cubic | 8 | 20 | inconclusive | gigabits/second | 7.771 | 6.832 | 6.327 |
| s2n-quic | syscall | cubic | 2 | 20 | publishable | gigabits/second | 6.798 | 6.495 | 6.475 |
| s2n-quic | io_uring | cubic | 2 | 20 | inconclusive | gigabits/second | 6.364 | 6.057 | 5.855 |
| Neqo | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 5.597 | 4.539 | 4.456 |
| Neqo | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 4.471 | 4.388 | 4.348 |
| Quinn | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 4.247 | 4.199 | 4.189 |
| XQUIC | syscall | cubic | 16 | 20 | publishable | gigabits/second | 3.953 | 3.901 | 3.848 |
| Quinn | syscall | cubic | 1 | 20 | publishable | gigabits/second | 3.450 | 3.420 | 3.390 |
| noq | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 3.424 | 3.390 | 3.339 |
| noq | syscall | cubic | 1 | 20 | publishable | gigabits/second | 2.862 | 2.828 | 2.793 |
| XQUIC | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 2.160 | 2.047 | 1.922 |

### Bidirectional

Simultaneous upload and download on one connection.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| ngtcp2 | syscall | cubic | 4 | 20 | publishable | gigabits/second | 20.503 | 19.430 | 18.394 |
| ngtcp2 | io_uring | cubic | 4 | 20 | publishable | gigabits/second | 18.634 | 17.932 | 17.769 |
| quiche | syscall | cubic | 4 | 20 | inconclusive | gigabits/second | 12.662 | 11.821 | 11.420 |
| quiche | io_uring | cubic | 4 | 20 | publishable | gigabits/second | 11.906 | 11.175 | 11.139 |
| TQUIC | syscall | cubic | 4 | 20 | publishable | gigabits/second | 11.223 | 10.870 | 10.477 |
| TQUIC | io_uring | cubic | 4 | 20 | publishable | gigabits/second | 10.281 | 9.834 | 9.823 |
| mvfst | syscall | cubic | 4 | 20 | publishable | gigabits/second | 7.406 | 7.293 | 7.250 |
| mvfst | io_uring | cubic | 4 | 20 | publishable | gigabits/second | 7.192 | 7.094 | 7.042 |
| Quinn | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 5.317 | 5.246 | 5.155 |
| quic-zig | syscall | cubic | 1 | 20 | publishable | gigabits/second | 5.286 | 5.201 | 5.151 |
| quic-zig | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 5.275 | 5.225 | 5.173 |
| Quinn | syscall | cubic | 1 | 20 | publishable | gigabits/second | 4.612 | 4.521 | 4.474 |
| noq | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 4.386 | 4.274 | 4.215 |
| XQUIC | syscall | cubic | 4 | 20 | publishable | gigabits/second | 4.299 | 4.205 | 4.148 |
| XQUIC | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 4.056 | 3.984 | 3.971 |
| noq | syscall | cubic | 1 | 20 | publishable | gigabits/second | 3.856 | 3.743 | 3.704 |
| Neqo | syscall | cubic | 1 | 20 | publishable | gigabits/second | 3.306 | 3.247 | 3.238 |
| Neqo | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 3.268 | 3.229 | 3.215 |
| s2n-quic | syscall | cubic | 16 | 20 | publishable | gigabits/second | 2.147 | 2.147 | 2.147 |
| s2n-quic | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 2.147 | 2.147 | 2.147 |
| LSQUIC | syscall | cubic | 16 | 20 | publishable | gigabits/second | 2.147 | 2.147 | 2.147 |
| LSQUIC | io_uring | cubic | 8 | 20 | publishable | gigabits/second | 1.074 | 1.074 | 1.074 |
| picoquic | io_uring | cubic | 16 | 20 | inconclusive | gigabits/second | 0.258 | 0.231 | 0.226 |
| picoquic | syscall | cubic | 16 | 20 | inconclusive | gigabits/second | 0.223 | 0.212 | 0.206 |

### Multistream Download

Server-to-client transfer split across concurrent streams.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| ngtcp2 | io_uring | cubic | 4 | 20 | publishable | gigabits/second | 16.582 | 15.734 | 15.310 |
| ngtcp2 | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 16.459 | 15.731 | 15.646 |
| quiche | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 11.156 | 10.453 | 10.198 |
| quiche | syscall | cubic | 1 | 20 | publishable | gigabits/second | 10.990 | 10.613 | 10.076 |
| TQUIC | syscall | cubic | 2 | 20 | inconclusive | gigabits/second | 10.049 | 9.381 | 8.771 |
| TQUIC | io_uring | cubic | 1 | 20 | inconclusive | gigabits/second | 8.555 | 8.202 | 8.180 |
| XQUIC | syscall | cubic | 16 | 20 | publishable | gigabits/second | 7.623 | 7.472 | 7.411 |
| Quinn | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 6.670 | 6.517 | 6.463 |
| Quinn | syscall | cubic | 2 | 20 | publishable | gigabits/second | 6.439 | 6.332 | 6.306 |
| mvfst | syscall | cubic | 4 | 20 | publishable | gigabits/second | 6.120 | 6.006 | 5.796 |
| mvfst | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 5.957 | 5.859 | 5.798 |
| noq | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 5.369 | 5.287 | 5.272 |
| noq | syscall | cubic | 2 | 20 | publishable | gigabits/second | 5.300 | 5.173 | 5.164 |
| XQUIC | io_uring | cubic | 8 | 20 | inconclusive | gigabits/second | 3.860 | 3.780 | 3.586 |
| quic-zig | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 3.167 | 3.125 | 3.119 |
| quic-zig | syscall | cubic | 1 | 20 | publishable | gigabits/second | 3.166 | 3.117 | 3.085 |
| Neqo | syscall | cubic | 1 | 20 | publishable | gigabits/second | 2.777 | 2.705 | 2.680 |
| Neqo | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 2.508 | 2.479 | 2.469 |
| LSQUIC | syscall | cubic | 16 | 20 | publishable | gigabits/second | 1.544 | 1.544 | 1.544 |
| s2n-quic | syscall | cubic | 16 | 20 | publishable | gigabits/second | 1.074 | 1.074 | 1.074 |
| s2n-quic | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 1.074 | 1.074 | 1.074 |
| picoquic | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 0.673 | 0.668 | 0.661 |
| picoquic | syscall | cubic | 16 | 20 | publishable | gigabits/second | 0.546 | 0.542 | 0.540 |
| LSQUIC | io_uring | cubic | 16 | 20 | inconclusive | gigabits/second | 0.434 | 0.272 | 0.258 |

### Multistream Upload

Client-to-server transfer split across concurrent streams.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| ngtcp2 | syscall | cubic | 4 | 20 | publishable | gigabits/second | 24.816 | 23.326 | 23.126 |
| ngtcp2 | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 18.761 | 18.369 | 18.226 |
| quiche | syscall | cubic | 2 | 20 | publishable | gigabits/second | 15.291 | 14.628 | 14.329 |
| TQUIC | syscall | cubic | 2 | 20 | publishable | gigabits/second | 14.158 | 13.241 | 13.234 |
| quiche | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 13.933 | 12.873 | 12.715 |
| TQUIC | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 12.770 | 12.471 | 12.060 |
| quic-zig | syscall | cubic | 4 | 20 | publishable | gigabits/second | 9.392 | 9.329 | 9.298 |
| quic-zig | io_uring | cubic | 4 | 20 | publishable | gigabits/second | 8.976 | 8.874 | 8.830 |
| mvfst | syscall | cubic | 16 | 20 | publishable | gigabits/second | 7.879 | 7.770 | 7.513 |
| mvfst | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 6.927 | 6.844 | 6.823 |
| XQUIC | syscall | cubic | 16 | 20 | publishable | gigabits/second | 3.477 | 3.425 | 3.402 |
| Neqo | syscall | cubic | 2 | 20 | publishable | gigabits/second | 3.336 | 3.186 | 3.151 |
| Neqo | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 3.193 | 3.019 | 3.005 |
| XQUIC | io_uring | cubic | 16 | 20 | inconclusive | gigabits/second | 1.659 | 1.622 | 1.607 |
| LSQUIC | syscall | cubic | 16 | 20 | publishable | gigabits/second | 1.544 | 1.544 | 1.544 |
| LSQUIC | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 1.544 | 1.544 | 1.544 |
| Quinn | syscall | cubic | 16 | 20 | publishable | gigabits/second | 1.534 | 1.525 | 1.524 |
| Quinn | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 1.533 | 1.527 | 1.526 |
| s2n-quic | syscall | cubic | 16 | 20 | inconclusive | gigabits/second | 1.380 | 1.283 | 1.217 |
| s2n-quic | io_uring | cubic | 16 | 20 | inconclusive | gigabits/second | 1.331 | 1.275 | 1.255 |
| noq | syscall | cubic | 8 | 20 | publishable | gigabits/second | 0.768 | 0.759 | 0.753 |
| noq | io_uring | cubic | 8 | 20 | publishable | gigabits/second | 0.768 | 0.758 | 0.749 |
| picoquic | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 0.593 | 0.586 | 0.584 |
| picoquic | syscall | cubic | 16 | 20 | publishable | gigabits/second | 0.591 | 0.580 | 0.580 |

### Request/Response

Small request/response exchanges on fresh bidirectional streams.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| TQUIC | syscall | cubic | 16 | 20 | publishable | requests/second | 155,043 | 152,707 | 152,640 |
| TQUIC | io_uring | cubic | 16 | 20 | publishable | requests/second | 153,124 | 151,606 | 149,234 |
| LSQUIC | syscall | cubic | 16 | 20 | publishable | requests/second | 119,404 | 116,795 | 114,151 |
| LSQUIC | io_uring | cubic | 16 | 20 | publishable | requests/second | 69,023 | 67,477 | 67,093 |
| quiche | syscall | cubic | 16 | 20 | publishable | requests/second | 64,574 | 62,480 | 62,081 |
| picoquic | syscall | cubic | 16 | 20 | publishable | requests/second | 59,098 | 57,358 | 57,183 |
| ngtcp2 | syscall | cubic | 16 | 20 | publishable | requests/second | 51,386 | 50,135 | 49,229 |
| Quinn | syscall | cubic | 2 | 20 | publishable | requests/second | 51,031 | 49,882 | 49,712 |
| quiche | io_uring | cubic | 16 | 20 | publishable | requests/second | 50,634 | 47,603 | 46,701 |
| ngtcp2 | io_uring | cubic | 16 | 20 | publishable | requests/second | 44,244 | 43,103 | 42,546 |
| s2n-quic | io_uring | cubic | 4 | 20 | publishable | requests/second | 40,974 | 40,225 | 39,912 |
| s2n-quic | syscall | cubic | 4 | 20 | publishable | requests/second | 39,098 | 38,666 | 38,424 |
| noq | io_uring | cubic | 1 | 20 | publishable | requests/second | 32,765 | 32,764 | 32,764 |
| Quinn | io_uring | cubic | 1 | 20 | publishable | requests/second | 32,765 | 32,764 | 32,764 |
| noq | syscall | cubic | 1 | 20 | publishable | requests/second | 32,764 | 32,764 | 32,764 |
| picoquic | io_uring | cubic | 8 | 20 | publishable | requests/second | 30,699 | 29,894 | 29,141 |
| XQUIC | syscall | cubic | 16 | 20 | publishable | requests/second | 20,578 | 20,088 | 19,928 |
| XQUIC | io_uring | cubic | 2 | 20 | publishable | requests/second | 18,209 | 17,889 | 17,742 |
| Neqo | io_uring | cubic | 4 | 20 | publishable | requests/second | 12,230 | 12,094 | 12,029 |
| Neqo | syscall | cubic | 4 | 20 | publishable | requests/second | 12,154 | 12,017 | 11,920 |
| mvfst | syscall | cubic | 16 | 20 | publishable | requests/second | 11,070 | 10,944 | 10,840 |
| mvfst | io_uring | cubic | 16 | 20 | publishable | requests/second | 10,709 | 9,856 | 9,851 |
| quic-zig | io_uring | cubic | 4 | 20 | publishable | requests/second | 3,716 | 3,698 | 3,696 |
| quic-zig | syscall | cubic | 4 | 20 | publishable | requests/second | 3,704 | 3,663 | 3,649 |

### Stream Churn

Repeated stream open, send, receive, and finish lifecycle.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| TQUIC | syscall | cubic | 16 | 20 | publishable | streams/second | 178,272 | 175,498 | 174,451 |
| TQUIC | io_uring | cubic | 16 | 20 | publishable | streams/second | 176,678 | 173,001 | 172,607 |
| LSQUIC | syscall | cubic | 16 | 20 | publishable | streams/second | 115,554 | 109,616 | 108,647 |
| quiche | syscall | cubic | 16 | 20 | publishable | streams/second | 74,756 | 71,260 | 69,965 |
| LSQUIC | io_uring | cubic | 16 | 20 | publishable | streams/second | 69,856 | 69,436 | 69,403 |
| quiche | io_uring | cubic | 16 | 20 | publishable | streams/second | 53,924 | 50,014 | 49,181 |
| ngtcp2 | syscall | cubic | 16 | 20 | publishable | streams/second | 52,478 | 50,793 | 50,259 |
| Quinn | syscall | cubic | 2 | 20 | publishable | streams/second | 52,026 | 50,413 | 49,685 |
| picoquic | syscall | cubic | 16 | 20 | inconclusive | streams/second | 48,480 | 43,890 | 41,331 |
| picoquic | io_uring | cubic | 16 | 20 | publishable | streams/second | 45,686 | 44,724 | 44,606 |
| noq | syscall | cubic | 2 | 20 | publishable | streams/second | 44,056 | 42,808 | 42,738 |
| ngtcp2 | io_uring | cubic | 16 | 20 | publishable | streams/second | 42,407 | 41,823 | 41,008 |
| s2n-quic | io_uring | cubic | 4 | 20 | publishable | streams/second | 41,534 | 40,538 | 40,308 |
| s2n-quic | syscall | cubic | 4 | 20 | publishable | streams/second | 38,984 | 38,611 | 38,245 |
| noq | io_uring | cubic | 1 | 20 | publishable | streams/second | 32,765 | 32,764 | 32,764 |
| Quinn | io_uring | cubic | 1 | 20 | publishable | streams/second | 32,765 | 32,764 | 32,764 |
| XQUIC | syscall | cubic | 16 | 20 | publishable | streams/second | 20,325 | 19,840 | 19,787 |
| XQUIC | io_uring | cubic | 2 | 20 | publishable | streams/second | 18,125 | 17,845 | 17,799 |
| Neqo | io_uring | cubic | 4 | 20 | publishable | streams/second | 12,286 | 12,177 | 12,079 |
| Neqo | syscall | cubic | 4 | 20 | publishable | streams/second | 12,174 | 12,100 | 12,081 |
| mvfst | syscall | cubic | 16 | 20 | publishable | streams/second | 11,067 | 10,895 | 10,768 |
| mvfst | io_uring | cubic | 16 | 20 | inconclusive | streams/second | 10,825 | 9,920 | 9,816 |
| quic-zig | io_uring | cubic | 4 | 20 | publishable | streams/second | 3,894 | 3,849 | 3,828 |
| quic-zig | syscall | cubic | 4 | 20 | publishable | streams/second | 3,869 | 3,820 | 3,783 |

### Small Payload Messages

Tiny-message packet and API overhead.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| TQUIC | syscall | cubic | 16 | 20 | publishable | messages/second | 176,604 | 172,126 | 171,083 |
| TQUIC | io_uring | cubic | 16 | 20 | publishable | messages/second | 174,458 | 169,261 | 168,849 |
| LSQUIC | syscall | cubic | 16 | 20 | publishable | messages/second | 121,891 | 119,452 | 118,643 |
| quiche | syscall | cubic | 16 | 20 | publishable | messages/second | 73,852 | 70,781 | 69,397 |
| LSQUIC | io_uring | cubic | 16 | 20 | publishable | messages/second | 71,088 | 70,754 | 70,108 |
| quiche | io_uring | cubic | 16 | 20 | publishable | messages/second | 53,078 | 49,565 | 47,663 |
| ngtcp2 | syscall | cubic | 16 | 20 | publishable | messages/second | 52,724 | 51,916 | 50,391 |
| Quinn | syscall | cubic | 2 | 20 | publishable | messages/second | 52,511 | 51,624 | 50,965 |
| picoquic | syscall | cubic | 16 | 20 | publishable | messages/second | 49,594 | 47,894 | 46,923 |
| picoquic | io_uring | cubic | 16 | 20 | publishable | messages/second | 45,910 | 44,848 | 44,232 |
| noq | syscall | cubic | 2 | 20 | publishable | messages/second | 44,583 | 43,484 | 43,250 |
| ngtcp2 | io_uring | cubic | 16 | 20 | publishable | messages/second | 42,998 | 41,953 | 41,632 |
| s2n-quic | io_uring | cubic | 4 | 20 | publishable | messages/second | 41,380 | 40,016 | 39,766 |
| s2n-quic | syscall | cubic | 4 | 20 | publishable | messages/second | 39,527 | 38,878 | 38,414 |
| noq | io_uring | cubic | 1 | 20 | publishable | messages/second | 32,765 | 32,764 | 32,764 |
| Quinn | io_uring | cubic | 1 | 20 | publishable | messages/second | 32,765 | 32,764 | 32,764 |
| XQUIC | syscall | cubic | 16 | 20 | publishable | messages/second | 20,354 | 19,831 | 19,712 |
| XQUIC | io_uring | cubic | 4 | 20 | publishable | messages/second | 18,941 | 18,214 | 18,082 |
| Neqo | io_uring | cubic | 4 | 20 | publishable | messages/second | 12,237 | 12,115 | 12,016 |
| Neqo | syscall | cubic | 4 | 20 | publishable | messages/second | 12,212 | 12,089 | 12,051 |
| mvfst | syscall | cubic | 16 | 20 | publishable | messages/second | 11,136 | 10,879 | 10,836 |
| mvfst | io_uring | cubic | 16 | 20 | publishable | messages/second | 10,656 | 9,975 | 9,759 |
| quic-zig | io_uring | cubic | 8 | 20 | publishable | messages/second | 3,938 | 3,931 | 3,907 |
| quic-zig | syscall | cubic | 8 | 20 | publishable | messages/second | 3,936 | 3,904 | 3,881 |

### Loss Recovery

Deterministic impairment path covering loss recovery behavior.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| LSQUIC | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 18.342 | 17.080 | 16.577 |
| ngtcp2 | syscall | cubic | 2 | 20 | publishable | gigabits/second | 17.379 | 16.687 | 16.448 |
| LSQUIC | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 17.354 | 16.715 | 16.414 |
| ngtcp2 | io_uring | cubic | 8 | 20 | publishable | gigabits/second | 16.691 | 16.208 | 15.881 |
| quiche | syscall | cubic | 1 | 20 | publishable | gigabits/second | 11.689 | 11.264 | 11.098 |
| quiche | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 10.877 | 10.430 | 10.316 |
| quic-zig | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 9.629 | 9.434 | 9.155 |
| quic-zig | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 9.394 | 8.368 | 8.263 |
| TQUIC | syscall | cubic | 2 | 20 | publishable | gigabits/second | 8.980 | 8.857 | 8.799 |
| TQUIC | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 8.792 | 8.627 | 8.527 |
| picoquic | syscall | cubic | 1 | 20 | publishable | gigabits/second | 7.590 | 6.990 | 6.896 |
| mvfst | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 7.503 | 7.274 | 7.065 |
| mvfst | syscall | cubic | 16 | 20 | publishable | gigabits/second | 7.426 | 7.191 | 7.077 |
| picoquic | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 7.175 | 6.783 | 6.626 |
| Quinn | io_uring | cubic | 4 | 20 | publishable | gigabits/second | 6.544 | 6.461 | 6.442 |
| Quinn | syscall | cubic | 2 | 20 | publishable | gigabits/second | 6.526 | 6.367 | 6.279 |
| s2n-quic | io_uring | cubic | 2 | 20 | inconclusive | gigabits/second | 6.033 | 5.596 | 3.066 |
| Neqo | syscall | cubic | 2 | 20 | publishable | gigabits/second | 5.860 | 5.742 | 5.708 |
| Neqo | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 5.715 | 5.614 | 5.481 |
| s2n-quic | syscall | cubic | 2 | 20 | inconclusive | gigabits/second | 5.574 | 5.281 | 3.166 |
| noq | syscall | cubic | 2 | 20 | publishable | gigabits/second | 5.102 | 5.031 | 5.021 |
| noq | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 4.967 | 4.940 | 4.897 |
| XQUIC | syscall | cubic | 16 | 20 | publishable | gigabits/second | 2.834 | 2.694 | 2.653 |
| XQUIC | io_uring | cubic | 2 | 20 | inconclusive | gigabits/second | 2.467 | 2.375 | 2.275 |

### Flow Control

Small-window transfer pressure and flow-control update behavior.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| ngtcp2 | syscall | cubic | 4 | 20 | publishable | gigabits/second | 15.600 | 14.319 | 13.984 |
| ngtcp2 | io_uring | cubic | 8 | 20 | publishable | gigabits/second | 14.795 | 14.109 | 13.663 |
| LSQUIC | syscall | cubic | 1 | 20 | inconclusive | gigabits/second | 13.941 | 12.713 | 12.600 |
| LSQUIC | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 11.732 | 11.386 | 11.212 |
| quiche | syscall | cubic | 8 | 20 | publishable | gigabits/second | 10.309 | 9.689 | 9.188 |
| quiche | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 9.964 | 9.648 | 9.297 |
| picoquic | syscall | cubic | 1 | 20 | publishable | gigabits/second | 9.686 | 9.321 | 9.206 |
| picoquic | io_uring | cubic | 1 | 20 | publishable | gigabits/second | 9.580 | 9.377 | 9.283 |
| quic-zig | syscall | cubic | 2 | 20 | publishable | gigabits/second | 8.470 | 8.156 | 8.101 |
| quic-zig | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 8.434 | 8.237 | 8.175 |
| TQUIC | io_uring | cubic | 16 | 20 | publishable | gigabits/second | 8.102 | 7.699 | 7.620 |
| TQUIC | syscall | cubic | 16 | 20 | publishable | gigabits/second | 7.943 | 7.647 | 7.402 |
| mvfst | syscall | cubic | 2 | 20 | publishable | gigabits/second | 6.659 | 6.015 | 5.875 |
| mvfst | io_uring | cubic | 4 | 20 | publishable | gigabits/second | 6.653 | 6.023 | 5.971 |
| Neqo | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 5.563 | 5.428 | 5.151 |
| Quinn | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 5.327 | 5.271 | 5.263 |
| Quinn | syscall | cubic | 2 | 20 | publishable | gigabits/second | 5.213 | 5.116 | 5.030 |
| XQUIC | syscall | cubic | 8 | 20 | publishable | gigabits/second | 5.116 | 4.896 | 4.721 |
| s2n-quic | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 4.950 | 4.857 | 4.778 |
| s2n-quic | syscall | cubic | 2 | 20 | publishable | gigabits/second | 4.887 | 4.705 | 4.648 |
| Neqo | syscall | cubic | 1 | 20 | publishable | gigabits/second | 4.795 | 4.714 | 4.646 |
| noq | io_uring | cubic | 2 | 20 | publishable | gigabits/second | 4.320 | 4.271 | 4.221 |
| noq | syscall | cubic | 2 | 20 | publishable | gigabits/second | 4.225 | 4.157 | 4.124 |
| XQUIC | io_uring | cubic | 8 | 20 | publishable | gigabits/second | 2.359 | 2.226 | 2.077 |

### Connect

Full connection establishment plus stream creation.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| noq | syscall | cubic | 8 | 20 | inconclusive | connections/second | 306 | 284 | 262 |
| Quinn | syscall | cubic | 8 | 20 | inconclusive | connections/second | 302 | 277 | 274 |
| TQUIC | syscall | cubic | 16 | 20 | publishable | connections/second | 300 | 282 | 281 |
| picoquic | syscall | cubic | 16 | 20 | publishable | connections/second | 297 | 281 | 271 |
| s2n-quic | syscall | cubic | 16 | 20 | publishable | connections/second | 295 | 276 | 269 |
| LSQUIC | syscall | cubic | 16 | 20 | inconclusive | connections/second | 292 | 274 | 266 |
| XQUIC | io_uring | cubic | 16 | 20 | publishable | connections/second | 287 | 276 | 270 |
| quic-zig | syscall | cubic | 8 | 20 | publishable | connections/second | 286 | 265 | 249 |
| quiche | syscall | cubic | 16 | 20 | publishable | connections/second | 277 | 265 | 255 |
| noq | io_uring | cubic | 16 | 20 | inconclusive | connections/second | 277 | 261 | 256 |
| TQUIC | io_uring | cubic | 16 | 20 | publishable | connections/second | 275 | 270 | 262 |
| Quinn | io_uring | cubic | 16 | 20 | publishable | connections/second | 275 | 269 | 254 |
| s2n-quic | io_uring | cubic | 16 | 20 | publishable | connections/second | 271 | 260 | 249 |
| picoquic | io_uring | cubic | 16 | 20 | inconclusive | connections/second | 270 | 262 | 255 |
| XQUIC | syscall | cubic | 16 | 20 | inconclusive | connections/second | 269 | 263 | 260 |
| quic-zig | io_uring | cubic | 16 | 20 | publishable | connections/second | 267 | 255 | 249 |
| LSQUIC | io_uring | cubic | 16 | 20 | publishable | connections/second | 263 | 249 | 241 |
| mvfst | syscall | cubic | 16 | 20 | publishable | connections/second | 261 | 243 | 241 |
| quiche | io_uring | cubic | 16 | 20 | publishable | connections/second | 258 | 248 | 246 |
| mvfst | io_uring | cubic | 16 | 20 | inconclusive | connections/second | 254 | 242 | 239 |
| Neqo | syscall | cubic | 16 | 20 | inconclusive | connections/second | 247 | 235 | 228 |
| Neqo | io_uring | cubic | 16 | 20 | publishable | connections/second | 234 | 224 | 215 |
| ngtcp2 | io_uring | cubic | 16 | 20 | inconclusive | connections/second | 116 | 110 | 106 |
| ngtcp2 | syscall | cubic | 16 | 20 | publishable | connections/second | 113 | 112 | 109 |

### Resumed Connect

Session-ticket resumption proof for connection establishment.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| XQUIC | syscall | cubic | 2 | 20 | inconclusive | connections/second | 444 | 423 | 422 |
| XQUIC | io_uring | cubic | 2 | 20 | inconclusive | connections/second | 442 | 406 | 396 |
| picoquic | io_uring | cubic | 4 | 20 | inconclusive | connections/second | 402 | 330 | 326 |
| picoquic | syscall | cubic | 2 | 20 | inconclusive | connections/second | 388 | 375 | 363 |
| quiche | io_uring | cubic | 2 | 20 | publishable | connections/second | 306 | 296 | 284 |
| quiche | syscall | cubic | 2 | 20 | inconclusive | connections/second | 301 | 292 | 288 |
| mvfst | syscall | cubic | 4 | 20 | inconclusive | connections/second | 289 | 259 | 248 |
| mvfst | io_uring | cubic | 2 | 20 | publishable | connections/second | 264 | 255 | 254 |
| TQUIC | syscall | cubic | 16 | 20 | publishable | connections/second | 216 | 210 | 208 |
| TQUIC | io_uring | cubic | 8 | 20 | inconclusive | connections/second | 182 | 173 | 169 |
| LSQUIC | io_uring | cubic | 2 | 20 | inconclusive | connections/second | 128 | 119 | 119 |
| ngtcp2 | io_uring | cubic | 16 | 20 | publishable | connections/second | 114 | 109 | 108 |
| ngtcp2 | syscall | cubic | 16 | 20 | publishable | connections/second | 112 | 109 | 108 |
| LSQUIC | syscall | cubic | 1 | 20 | inconclusive | connections/second | 80 | 72 | 69 |
| noq | io_uring | cubic | 16 | 20 | publishable | connections/second | 15 | 15 | 15 |
| Quinn | io_uring | cubic | 16 | 20 | publishable | connections/second | 15 | 15 | 15 |
| s2n-quic | io_uring | cubic | 16 | 20 | publishable | connections/second | 15 | 15 | 15 |
| Neqo | io_uring | cubic | 16 | 20 | publishable | connections/second | 15 | 15 | 15 |
| quic-zig | io_uring | cubic | 16 | 20 | publishable | connections/second | 15 | 14 | 14 |
| s2n-quic | syscall | cubic | 16 | 20 | publishable | connections/second | 14 | 14 | 14 |
| noq | syscall | cubic | 16 | 20 | publishable | connections/second | 14 | 14 | 14 |
| Quinn | syscall | cubic | 16 | 20 | publishable | connections/second | 14 | 14 | 14 |
| Neqo | syscall | cubic | 16 | 20 | publishable | connections/second | 14 | 14 | 14 |
| quic-zig | syscall | cubic | 16 | 20 | publishable | connections/second | 14 | 14 | 14 |

### 0-RTT request/response

Session resumption with early request/response data.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| TQUIC | syscall | cubic | 16 | 20 | publishable | requests/second | 154,448 | 151,728 | 150,310 |
| TQUIC | io_uring | cubic | 16 | 20 | publishable | requests/second | 152,698 | 150,104 | 149,197 |
| LSQUIC | syscall | cubic | 16 | 20 | publishable | requests/second | 114,950 | 113,158 | 111,788 |
| quiche | syscall | cubic | 16 | 20 | publishable | requests/second | 65,327 | 62,600 | 61,437 |
| picoquic | syscall | cubic | 16 | 20 | publishable | requests/second | 56,003 | 53,626 | 53,171 |
| LSQUIC | io_uring | cubic | 8 | 20 | publishable | requests/second | 51,964 | 51,448 | 51,385 |
| quiche | io_uring | cubic | 8 | 20 | publishable | requests/second | 46,529 | 45,708 | 44,774 |
| ngtcp2 | syscall | cubic | 16 | 20 | publishable | requests/second | 45,569 | 44,301 | 43,771 |
| s2n-quic | io_uring | cubic | 4 | 20 | publishable | requests/second | 43,378 | 42,178 | 41,905 |
| ngtcp2 | io_uring | cubic | 16 | 20 | publishable | requests/second | 41,831 | 40,053 | 39,996 |
| s2n-quic | syscall | cubic | 4 | 20 | publishable | requests/second | 41,652 | 41,335 | 41,136 |
| Quinn | syscall | cubic | 1 | 20 | publishable | requests/second | 32,765 | 32,764 | 32,764 |
| noq | syscall | cubic | 1 | 20 | publishable | requests/second | 32,765 | 32,764 | 32,764 |
| Quinn | io_uring | cubic | 1 | 20 | publishable | requests/second | 32,765 | 32,764 | 32,764 |
| noq | io_uring | cubic | 1 | 20 | publishable | requests/second | 32,764 | 32,764 | 32,764 |
| picoquic | io_uring | cubic | 8 | 20 | publishable | requests/second | 30,602 | 29,702 | 29,510 |
| XQUIC | syscall | cubic | 16 | 20 | publishable | requests/second | 20,544 | 20,272 | 20,046 |
| XQUIC | io_uring | cubic | 2 | 20 | publishable | requests/second | 18,139 | 17,835 | 17,747 |
| mvfst | syscall | cubic | 16 | 20 | publishable | requests/second | 10,880 | 10,695 | 10,586 |
| Neqo | io_uring | cubic | 4 | 20 | publishable | requests/second | 10,783 | 10,626 | 10,515 |
| Neqo | syscall | cubic | 4 | 20 | publishable | requests/second | 10,569 | 10,402 | 10,335 |
| mvfst | io_uring | cubic | 16 | 20 | publishable | requests/second | 10,527 | 10,130 | 9,627 |
| quic-zig | io_uring | cubic | 4 | 20 | publishable | requests/second | 3,666 | 3,648 | 3,644 |
| quic-zig | syscall | cubic | 4 | 20 | publishable | requests/second | 3,664 | 3,636 | 3,619 |

### Datagram

Unreliable application DATAGRAM echo capability.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| quiche | io_uring | cubic | 2 | 20 | inconclusive | DATAGRAMs/second | 5,206,512 | 4,134,915 | 3,981,228 |
| quiche | syscall | cubic | 2 | 20 | inconclusive | DATAGRAMs/second | 5,141,278 | 4,154,823 | 3,737,509 |
| quic-zig | syscall | cubic | 2 | 20 | publishable | DATAGRAMs/second | 3,553,603 | 3,418,734 | 3,403,750 |
| Quinn | syscall | cubic | 4 | 20 | publishable | DATAGRAMs/second | 3,504,773 | 3,476,106 | 3,468,650 |
| quic-zig | io_uring | cubic | 2 | 20 | publishable | DATAGRAMs/second | 3,459,620 | 3,367,573 | 3,339,851 |
| Quinn | io_uring | cubic | 4 | 20 | publishable | DATAGRAMs/second | 3,296,997 | 3,207,451 | 3,054,185 |
| noq | syscall | cubic | 4 | 20 | publishable | DATAGRAMs/second | 2,772,331 | 2,734,676 | 2,720,516 |
| s2n-quic | io_uring | cubic | 8 | 20 | inconclusive | DATAGRAMs/second | 2,654,584 | 2,294,118 | 2,209,037 |
| noq | io_uring | cubic | 4 | 20 | publishable | DATAGRAMs/second | 2,642,926 | 2,563,678 | 2,523,966 |
| s2n-quic | syscall | cubic | 4 | 20 | inconclusive | DATAGRAMs/second | 2,381,133 | 2,249,304 | 2,099,796 |
| LSQUIC | syscall | cubic | 2 | 20 | inconclusive | DATAGRAMs/second | 2,233,385 | 2,138,614 | 2,119,075 |
| Neqo | syscall | cubic | 2 | 20 | publishable | DATAGRAMs/second | 1,996,135 | 1,911,508 | 1,895,730 |
| Neqo | io_uring | cubic | 2 | 20 | publishable | DATAGRAMs/second | 1,860,976 | 1,810,892 | 1,745,771 |
| ngtcp2 | syscall | cubic | 4 | 20 | publishable | DATAGRAMs/second | 1,498,893 | 1,345,202 | 1,316,809 |
| ngtcp2 | io_uring | cubic | 1 | 20 | inconclusive | DATAGRAMs/second | 1,369,468 | 1,315,466 | 1,288,234 |
| LSQUIC | io_uring | cubic | 16 | 20 | publishable | DATAGRAMs/second | 928,370 | 920,789 | 911,843 |
| TQUIC | syscall | cubic | 2 | 20 | publishable | DATAGRAMs/second | 887,032 | 833,950 | 812,362 |
| TQUIC | io_uring | cubic | 2 | 20 | publishable | DATAGRAMs/second | 839,446 | 811,719 | 774,656 |
| mvfst | io_uring | cubic | 1 | 20 | inconclusive | DATAGRAMs/second | 379,326 | 328,096 | 18,505 |
| picoquic | io_uring | cubic | 1 | 20 | inconclusive | DATAGRAMs/second | 91,122 | 83,557 | 80,253 |
| mvfst | syscall | cubic | 16 | 20 | inconclusive | DATAGRAMs/second | 74,796 | 61,151 | 51,605 |
| picoquic | syscall | cubic | 1 | 20 | inconclusive | DATAGRAMs/second | 71,990 | 68,153 | 65,498 |
| XQUIC | syscall | cubic | 8 | 20 | publishable | DATAGRAMs/second | 9,984 | 9,529 | 9,383 |
| XQUIC | io_uring | cubic | 8 | 20 | inconclusive | DATAGRAMs/second | 3,452 | 2,089 | 1,755 |

### Idle Footprint

Server RSS delta per held idle connection; lower is better.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| ngtcp2 | io_uring | cubic | 16 | 20 | publishable | bytes/connection | 76,544 | 86,093 | 88,028 |
| LSQUIC | syscall | cubic | 8 | 20 | inconclusive | bytes/connection | 79,872 | 114,176 | 125,373 |
| Quinn | syscall | cubic | 16 | 20 | inconclusive | bytes/connection | 80,896 | 86,528 | 90,468 |
| quiche | io_uring | cubic | 16 | 20 | inconclusive | bytes/connection | 84,864 | 93,286 | 96,927 |
| LSQUIC | io_uring | cubic | 16 | 20 | inconclusive | bytes/connection | 87,808 | 94,618 | 96,000 |
| Quinn | io_uring | cubic | 16 | 20 | inconclusive | bytes/connection | 90,496 | 100,378 | 101,437 |
| picoquic | io_uring | cubic | 16 | 20 | publishable | bytes/connection | 93,056 | 105,754 | 107,021 |
| ngtcp2 | syscall | cubic | 16 | 20 | inconclusive | bytes/connection | 110,336 | 120,883 | 121,966 |
| noq | syscall | cubic | 16 | 20 | inconclusive | bytes/connection | 113,920 | 130,918 | 132,877 |
| TQUIC | io_uring | cubic | 16 | 20 | inconclusive | bytes/connection | 115,072 | 120,755 | 125,686 |
| quiche | syscall | cubic | 16 | 20 | publishable | bytes/connection | 125,440 | 135,194 | 135,839 |
| XQUIC | io_uring | cubic | 16 | 20 | inconclusive | bytes/connection | 135,168 | 141,594 | 142,239 |
| picoquic | syscall | cubic | 16 | 20 | publishable | bytes/connection | 135,424 | 140,800 | 144,348 |
| noq | io_uring | cubic | 16 | 20 | inconclusive | bytes/connection | 141,696 | 152,166 | 154,125 |
| TQUIC | syscall | cubic | 16 | 20 | inconclusive | bytes/connection | 146,560 | 161,203 | 164,475 |
| XQUIC | syscall | cubic | 16 | 20 | inconclusive | bytes/connection | 164,352 | 174,054 | 176,335 |
| mvfst | io_uring | cubic | 16 | 20 | publishable | bytes/connection | 235,520 | 245,862 | 248,028 |
| s2n-quic | syscall | cubic | 16 | 20 | inconclusive | bytes/connection | 255,360 | 277,606 | 283,551 |
| s2n-quic | io_uring | cubic | 16 | 20 | inconclusive | bytes/connection | 267,008 | 295,987 | 313,889 |
| mvfst | syscall | cubic | 16 | 20 | publishable | bytes/connection | 278,528 | 288,051 | 289,134 |
| Neqo | syscall | cubic | 16 | 20 | publishable | bytes/connection | 347,264 | 357,197 | 360,607 |
| Neqo | io_uring | cubic | 16 | 20 | publishable | bytes/connection | 372,480 | 383,027 | 384,732 |
| quic-zig | syscall | cubic | 16 | 20 | inconclusive | bytes/connection | 464,384 | 464,666 | 464,896 |
| quic-zig | io_uring | cubic | 16 | 20 | inconclusive | bytes/connection | 470,144 | 472,064 | 472,064 |

### Close/Reset Cleanup

Graceful fresh-stream close and cleanup throughput.

| Library | Network | CC | Client threads | Samples | Status | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---|---:|---:|---:|
| TQUIC | syscall | cubic | 16 | 20 | publishable | streams/second | 178,364 | 176,090 | 175,037 |
| TQUIC | io_uring | cubic | 16 | 20 | publishable | streams/second | 177,026 | 173,336 | 172,230 |
| LSQUIC | syscall | cubic | 16 | 20 | publishable | streams/second | 115,444 | 112,335 | 110,762 |
| quiche | syscall | cubic | 16 | 20 | publishable | streams/second | 75,080 | 72,457 | 71,959 |
| LSQUIC | io_uring | cubic | 16 | 20 | publishable | streams/second | 69,916 | 69,156 | 68,714 |
| Quinn | io_uring | cubic | 2 | 20 | publishable | streams/second | 54,645 | 52,578 | 52,232 |
| ngtcp2 | syscall | cubic | 16 | 20 | publishable | streams/second | 52,912 | 50,078 | 49,896 |
| quiche | io_uring | cubic | 16 | 20 | publishable | streams/second | 52,788 | 48,907 | 47,512 |
| Quinn | syscall | cubic | 2 | 20 | publishable | streams/second | 51,519 | 50,233 | 49,929 |
| picoquic | syscall | cubic | 16 | 20 | publishable | streams/second | 49,276 | 47,001 | 42,528 |
| picoquic | io_uring | cubic | 16 | 20 | publishable | streams/second | 45,716 | 44,744 | 44,056 |
| noq | syscall | cubic | 2 | 20 | publishable | streams/second | 43,988 | 43,370 | 42,951 |
| ngtcp2 | io_uring | cubic | 16 | 20 | publishable | streams/second | 42,285 | 41,116 | 40,862 |
| s2n-quic | io_uring | cubic | 4 | 20 | publishable | streams/second | 41,612 | 40,456 | 39,449 |
| s2n-quic | syscall | cubic | 4 | 20 | publishable | streams/second | 39,452 | 38,781 | 38,065 |
| noq | io_uring | cubic | 1 | 20 | publishable | streams/second | 32,764 | 32,764 | 32,764 |
| XQUIC | syscall | cubic | 16 | 20 | publishable | streams/second | 20,354 | 20,141 | 19,818 |
| XQUIC | io_uring | cubic | 2 | 20 | publishable | streams/second | 18,196 | 17,757 | 17,564 |
| Neqo | io_uring | cubic | 4 | 20 | publishable | streams/second | 12,304 | 12,170 | 12,145 |
| Neqo | syscall | cubic | 4 | 20 | publishable | streams/second | 12,234 | 12,082 | 12,040 |
| mvfst | syscall | cubic | 16 | 20 | publishable | streams/second | 11,022 | 10,944 | 10,840 |
| mvfst | io_uring | cubic | 16 | 20 | publishable | streams/second | 10,798 | 10,099 | 9,880 |
| quic-zig | io_uring | cubic | 8 | 20 | publishable | streams/second | 3,936 | 3,928 | 3,925 |
| quic-zig | syscall | cubic | 4 | 20 | publishable | streams/second | 3,835 | 3,794 | 3,786 |

## Caveats

- Scout samples choose workload shape and client threads; they are excluded from publication statistics.
- A completed row with CI, spread, or drift problems is inconclusive/noisy, not extended in the same run.
- DATAGRAM rows report delivered unique echo rate; delivery/loss counters are in the raw sample TSV.
- `idle_footprint` reports server RSS delta per connection, where lower is better.
- Row-level caveats and full gate reasons are in [`publication-results.tsv`](results/fixed-full-matrix-max16-20260601T175816Z/publication-results.tsv), [`row-stats.tsv`](results/fixed-full-matrix-max16-20260601T175816Z/row-stats.tsv), [`publication-row-audit.tsv`](results/fixed-full-matrix-max16-20260601T175816Z/publication-row-audit.tsv), and [`benchmark-plan.tsv`](results/fixed-full-matrix-max16-20260601T175816Z/benchmark-plan.tsv).
- Raw samples are in [`adaptive-samples.tsv`](results/fixed-full-matrix-max16-20260601T175816Z/adaptive-samples.tsv).
