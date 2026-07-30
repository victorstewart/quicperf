# Latest qualified results

Campaign [`ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492`](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/README.md) is
`publication_qualified`.

- Executed: 2026-07-29–30 (America/New_York)
- Source: `44250d751e650f11f620733aa6e5d0498f947d12`; exact Git tree `a72228525e2f09fabd0b01cee4888e201a376ef4`
- Host: AMD Ryzen 7 8845HS w/ Radeon 780M Graphics; turbo disabled;
  3.8 GHz
  `performance`/`performance` policy
- Treatment: one `iouring` server core, four client cores, exactly 16 active
  connections, 50/50 `ngtcp2perf`/`picoperf` reference-client mixture
- Matrix: 12 server implementations × 15 scenarios × 24 rows = 4,320/4,320
  valid samples
- Session walls: 8819.694s and
  8793.689s (10,800s ceiling each)
- Maximum Tctl: 57.875°C and
  56.875°C (80°C ceiling)
- Localized preallocated retries: 1 in session 1 and
  1 in session 2
- Deterministic render: 39.322s (60s ceiling)
- Simultaneous classifications: 459 superior,
  374 inferior, 15
  equivalent, 307 inconclusive
- Admission: 180/180 native interoperability, host stability qualified, and
  four-client-core headroom qualified

## Read the results

Use the [campaign page](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/README.md) for
scenario-specific tables. There is deliberately no global leaderboard:
throughput and operation rates have different meanings across scenarios, and
reference-client or session sensitivity constrains some comparisons.

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

Compact machine-readable files are committed with the campaign page. Complete
raw evidence is prepared as release assets described in
[`release-assets.json`](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/release-assets.json).

## Limitations

These results describe this host and exact fixed treatment. They do not estimate
capacity, memory scaling, long-tail latency, a syscall backend, or same-stack
client/server performance. GitHub Actions validates publication artifacts but
does not reproduce physical qualification.
