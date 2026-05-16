# DATAGRAM Addendum

Collected on 2026-05-16.

This addendum replaces the retracted full31 DATAGRAM rows. The earlier rows used
different DATAGRAM pressure between native quiche and packet-engine adapters,
which made the quiche row incomparable.

Harness fixes applied before this addendum:

- packet-engine adapters no longer flush or poll once per app DATAGRAM
- all supported adapters use the same queue, flush, drain, echo cycle
- DATAGRAM rows record sent, received, unreturned, delivery ratio, UDP packets,
  send submit/syscall batches, receive polls, and DATAGRAMs per UDP packet
- DATAGRAM rows are gated on delivery ratio
- the default DATAGRAM operation count was raised so the fastest row is not a
  sub-second timing artifact

The visible table in `docs/latest-results.md` is the approved full-duration
DATAGRAM-only smoke. It uses:

- 8,388,608 delivered DATAGRAM echo operations per sample
- a shared 1,024-message outstanding DATAGRAM cap
- one client thread and one server thread per row
- no interleaving with the full benchmark matrix

The smoke completed all supported rows without benchmark failures. Unsupported
adapters return the explicit `requires_quic_datagram_adapter_api` marker.

The DATAGRAM adaptive inspection is included for auditability. It collected 417
measured samples with zero benchmark failures, but only 1 of 12 result rows
passed the strict convergence gates in the bounded inspection run. Treat the
visible table as a DATAGRAM addendum, not a clean adaptive leaderboard.

Smoke artifacts:

- `datagram-smoke-raw-samples.tsv`
- `datagram-smoke-summary.tsv`

Adaptive inspection artifacts:

- `publication-results.tsv`
- `row-stats.tsv`
- `publication-row-audit.tsv`
- `saturation-decisions.tsv`
- `adaptive-samples.tsv`
