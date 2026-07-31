# Changelog

## V2.3 — review candidate

- Replaced the former public benchmark workflow with the exact-identity,
  crash-resumable V2.3 coordinator.
- Standardized publication on the common C++ io_uring backend, one server core,
  four client cores, 16 connections, two balanced reference clients, 12
  servers, 15 scenarios, and 4,320 primary trials.
- Added paired-session exact-sign inference, physical qualification, strict
  workload/timing/thermal/throttle policy, hardened ARM recovery, immutable
  journaling, deterministic analysis, and checksum-bound export.
- Published the first qualified V2.3 campaign as compact CC BY 4.0 data with
  complete raw evidence staged separately.
- Removed scout/adaptive and obsolete V2/V2.1/V2.2 publication compatibility,
  legacy wrappers, diagnostic fallback, and out-of-scope campaign surfaces.

This is a hard cutover. Historical samples are not migrated or relabeled.
