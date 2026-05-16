# DATAGRAM Addendum

Collected on 2026-05-16.

This addendum replaces the retracted full31 DATAGRAM rows. The earlier rows used
different DATAGRAM pressure between native quiche and packet-engine adapters,
which made the quiche row incomparable.

The addendum run uses:

- 65,536 DATAGRAM echo operations per sample
- a shared 1,024-message outstanding DATAGRAM cap
- client-reported sent, received, lost, and delivery-ratio counters
- the same adaptive discovery, saturation, and confirmatory holdout runner used
  by the main results

The run completed without benchmark failures. Unsupported adapters returned the
explicit `requires_quic_datagram_adapter_api` marker.

All measured DATAGRAM rows are still marked `not_ready` by the strict
publication gates because the rows remained noisy or nonstationary. The table in
`docs/latest-results.md` is therefore an inspectable measured distribution, not
a clean DATAGRAM leaderboard. Full gate reasons are in:

- `publication-results.tsv`
- `row-stats.tsv`
- `publication-row-audit.tsv`
- `saturation-decisions.tsv`

