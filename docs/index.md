# quicperf

Publication-grade QUIC server benchmarking across 12 implementations using a
shared C++ I/O path, a fixed treatment, and paired simultaneous inference.

## Latest qualified campaign

[ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/README.md) contains 4,320/4,320 valid
V2.3 samples. Open the [interactive results explorer](explorer/), read the
[result summary](latest-results.md), browse
[scenario-specific tables](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/README.md), review the
[methodology](methodology.md), or follow the [operator guide](harness-v2.md).

There is no global leaderboard. Full raw evidence is distributed as release
assets; Git contains the compact qualified bundle only.

## Scenarios

- [Download](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/download.md)
- [Upload](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/upload.md)
- [Multi-stream download](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/multistream_download.md)
- [Multi-stream upload](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/multistream_upload.md)
- [Bidirectional transfer](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/bidi.md)
- [Small-payload packet rate](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/small_payload_pps.md)
- [QUIC DATAGRAM](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/datagram.md)
- [Request/response](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/reqresp.md)
- [Stream churn](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/stream_churn.md)
- [Connection setup](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/connect.md)
- [Resumed connection setup](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/resumed_connect.md)
- [0-RTT request/response](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/zero_rtt_reqresp.md)
- [Loss recovery](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/loss_recovery.md)
- [Flow control](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/flow_control.md)
- [Close/reset cleanup](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/scenarios/close_reset_cleanup.md)

## Reproducibility and downloads

- [Compact bundle manifest](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/public-bundle-manifest.json)
- [Prepared full-evidence asset inventory](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/release-assets.json)
- [V2.3 methodology](methodology.md)
- [Operator guide](harness-v2.md)
- [Migration guide](migration-v2.3.md)
