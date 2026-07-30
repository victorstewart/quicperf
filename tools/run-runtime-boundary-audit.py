#!/usr/bin/env python3
"""Externally audit every exact v2 endpoint on both common C++ backends."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from quicperf_harness.canonical import canonical_bytes
from quicperf_harness.planner import CANONICAL_SERVERS, SERVER_BACKENDS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    bin_dir = arguments.bin_dir.resolve(strict=True)
    monitor = bin_dir / "quicperf-runtime-monitor"
    fixture = bin_dir / "runtime_boundary_violation_fixture"
    missing = [
        name
        for name in (*CANONICAL_SERVERS, monitor.name, fixture.name)
        if not (bin_dir / name).is_file()
    ]
    if missing:
        raise SystemExit(f"runtime boundary audit missing binaries: {','.join(missing)}")
    arguments.out.mkdir(parents=True, exist_ok=False)
    reports = arguments.out / "reports"
    reports.mkdir()

    os.environ["QUICPERF_BIN_DIR"] = str(bin_dir)
    os.environ["QUICPERF_RUNTIME_MONITOR_BIN"] = str(monitor)
    os.environ["QUICPERF_RUNTIME_MONITOR_REPORT_DIR"] = str(reports)
    from tests.test_v2_native_endpoint import NativeEndpointContractTests

    workload: dict[str, int | str] = {
        "active_streams_per_connection": 1,
        "bulk_chunk_bytes": 0,
        "connection_count": 16,
        "datagram_body_bytes": 0,
        "datagram_max_unreturned_per_connection": 0,
        "global_operation_slots": 0,
        "measurement_duration_ns": 100_000_000,
        "operation_body_bytes": 64,
        "progress_interval_ns": 10_000_000,
        "request_body_bytes": 0,
        "response_body_bytes": 0,
        "scenario": "small_payload_pps",
        "ticket_slots": 0,
        "warmup_duration_ns": 50_000_000,
    }
    cells: list[dict[str, object]] = []
    case = NativeEndpointContractTests(methodName="test_every_named_endpoint_describes_itself")
    for binary in CANONICAL_SERVERS:
        for backend in SERVER_BACKENDS:
            server, client = case._run_ngtcp2_workload(
                {**workload, "backend": backend}, binary=binary, exercise=True
            )
            if min(
                int(server["live_connections"]),
                int(client["live_connections"]),
                int(server["work_inventory"]),
                int(client["work_inventory"]),
            ) <= 0:
                raise RuntimeError(
                    f"runtime boundary exercise failed semantically: {binary}/{backend}"
                )
            cells.append(
                {
                    "binary": binary,
                    "backend": backend,
                    "scenario": "untimed_exercise_reset",
                    "status": "passed",
                }
            )

    documents = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(reports.glob("*.json"))
    ]
    expected_hashes = {
        str((bin_dir / binary).resolve()): hashlib.sha256(
            (bin_dir / binary).read_bytes()
        ).hexdigest()
        for binary in CANONICAL_SERVERS
    }
    if len(documents) != len(CANONICAL_SERVERS) * len(SERVER_BACKENDS) * 2:
        raise RuntimeError(
            f"runtime monitor report cardinality mismatch: {len(documents)}"
        )
    counts = {binary: 0 for binary in CANONICAL_SERVERS}
    for document in documents:
        executable = str(document.get("executable", ""))
        expected_hash = expected_hashes.get(executable)
        if expected_hash is None:
            raise RuntimeError(f"runtime monitor observed an unexpected executable: {executable}")
        binary = Path(executable).name
        counts[binary] += 1
        if document.get("status") != "passed" or document.get("violation"):
            raise RuntimeError(f"runtime monitor rejected {binary}: {document}")
        if document.get("executable_sha256") != expected_hash:
            raise RuntimeError(f"runtime monitor executable hash mismatch: {binary}")
        if int(document.get("scope_entries", 0)) <= 0:
            raise RuntimeError(f"runtime monitor observed no adapter scopes: {binary}")
        if document.get("scope_entries") != document.get("scope_exits"):
            raise RuntimeError(f"runtime monitor observed unbalanced adapter scopes: {binary}")
        if int(document.get("ownership_attestations", 0)) <= 0:
            raise RuntimeError(f"runtime monitor observed no ownership attestation: {binary}")
        if int(document.get("vdso_breakpoint_symbols", 0)) < 3:
            raise RuntimeError(f"runtime monitor could not arm vDSO coverage: {binary}")
    expected_per_binary = len(SERVER_BACKENDS) * 2
    if any(count != expected_per_binary for count in counts.values()):
        raise RuntimeError(f"runtime monitor binary coverage mismatch: {counts}")

    summary = {
        "schema_version": "quicperf.runtime-boundary-audit.v1",
        "status": "passed",
        "privilege_required": False,
        "cell_count": len(cells),
        "process_count": len(documents),
        "cells": cells,
        "executable_sha256": {
            Path(path).name: digest for path, digest in sorted(expected_hashes.items())
        },
        "reports": documents,
    }
    (arguments.out / "summary.json").write_bytes(canonical_bytes(summary))
    print(
        "runtime_boundary_audit status=passed "
        f"cells={len(cells)} processes={len(documents)} out={arguments.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
