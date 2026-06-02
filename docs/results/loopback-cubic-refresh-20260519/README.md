# Archived Loopback CUBIC Refresh 2026-05-19

Archived adaptive loopback run from
`adaptive-loopback-cubic-refresh-20260519T024014Z-2661494`. Current results are
published from the fixed-design full matrix in `docs/latest-results.md`.

- Status: `not_ready`
- Congestion controller: CUBIC for QUIC adapters.
- Scenarios: `download`, `upload`, `connect`
- Socket backends: `syscall`, `iouring`
- Discovery samples: 4,310
- Confirm samples: 370
- Clean publication rows: 4
- Gated/not-ready rows: 74

The data was complete for the configured run, but the strict publication gate
rejected most rows for loopback noise, nonstationarity, or unsupported
capability cases. Treat `publication-results.tsv`, `row-stats.tsv`, and
`adaptive-run-summary.md` as the source of truth for this archived run's row
status.
