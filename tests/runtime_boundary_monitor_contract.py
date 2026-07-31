#!/usr/bin/env python3
"""Development negative controls for the unprivileged runtime-boundary monitor."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


EXPECTED = {
    "direct-clock-syscall": "direct_clock_syscall",
    "hidden-fd": "adapter_fd_create",
    "hidden-socket": "adapter_fd_create",
    "hidden-poller": "adapter_fd_create",
    "static-liburing": "adapter_fd_create",
    "hidden-thread": "adapter_thread_create",
    "poller-wait": "adapter_poller_wait",
    "vdso-private-clock": "vdso_private_clock",
}


def run(monitor: Path, fixture: Path, output: Path, mode: str) -> dict[str, object]:
    report = output / f"{mode}.json"
    completed = subprocess.run(
        [str(monitor), "--report", str(report), "--", str(fixture), mode],
        check=False,
    )
    value = json.loads(report.read_text(encoding="utf-8"))
    expected_status = 0 if mode == "positive" else 3
    if completed.returncode != expected_status:
        raise RuntimeError(
            f"{mode}: monitor exit {completed.returncode}, expected {expected_status}"
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="quicperf-runtime-monitor-contract-") as root:
        output = Path(root)
        positive = run(arguments.monitor, arguments.fixture, output, "positive")
        if (
            positive.get("status") != "passed"
            or positive.get("violation")
            or int(positive.get("scope_entries", 0)) <= 0
            or positive.get("scope_entries") != positive.get("scope_exits")
            or int(positive.get("ownership_attestations", 0)) <= 0
            or int(positive.get("vdso_breakpoint_symbols", 0)) < 3
        ):
            raise RuntimeError(f"positive runtime-monitor control failed: {positive}")
        for mode, expected in EXPECTED.items():
            value = run(arguments.monitor, arguments.fixture, output, mode)
            if value.get("status") != "violation_detected" or value.get("violation") != expected:
                raise RuntimeError(f"{mode}: unexpected monitor evidence: {value}")
    print(
        "runtime_boundary_monitor_contract status=ok "
        f"positive=1 negative_controls={len(EXPECTED)} privilege_required=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
