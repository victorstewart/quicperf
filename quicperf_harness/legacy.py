"""Explicit, non-executing translation of the supported legacy environment surface."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Mapping

from .canonical import canonical_bytes, load_strict
from .errors import InvalidConfigurationError
from .spec import validate_experiment_spec


_KNOWN = {
    "QUICPERF_BINARIES",
    "QUICPERF_REFERENCE_CLIENTS",
    "QUICPERF_SCENARIOS",
    "QUICPERF_NETWORKS",
}


def _words(value: str, name: str) -> list[str]:
    result = value.split()
    if not result or any(not item for item in result):
        raise InvalidConfigurationError(f"{name} must contain a nonempty whitespace-separated list")
    return result


def translate_legacy(
    base_profile: Path,
    assignments: Mapping[str, str],
) -> bytes:
    unknown = sorted(set(assignments) - _KNOWN)
    if unknown:
        raise InvalidConfigurationError(
            "unsupported legacy variables: " + ", ".join(unknown)
        )
    data = copy.deepcopy(load_strict(base_profile))
    data["name"] = "legacy-diagnostic"
    data["campaign_kind"] = "diagnostic"
    data["estimand"] = "symmetric_stack_pair"
    data["manifest_policy"]["clean_tree_required"] = False
    data["manifest_policy"]["allow_diagnostic_dirty"] = True
    data["schedule"]["worker_process_policy"] = "fresh_process"
    data["qualification"] = {
        "worker_reuse_required": False,
        "lane_interference_required": False,
        "client_headroom_required": False,
        "window_equivalence_required": False,
        "host_stability_required": False,
        "tail_window_required": False,
    }
    if "QUICPERF_BINARIES" in assignments:
        data["roles"]["servers"] = _words(assignments["QUICPERF_BINARIES"], "QUICPERF_BINARIES")
    if "QUICPERF_REFERENCE_CLIENTS" in assignments:
        data["roles"]["reference_clients"] = _words(
            assignments["QUICPERF_REFERENCE_CLIENTS"], "QUICPERF_REFERENCE_CLIENTS"
        )
    elif "QUICPERF_BINARIES" in assignments:
        data["roles"]["reference_clients"] = list(data["roles"]["servers"])
    if "QUICPERF_SCENARIOS" in assignments:
        selected = set(_words(assignments["QUICPERF_SCENARIOS"], "QUICPERF_SCENARIOS"))
        data["workloads"] = [item for item in data["workloads"] if item["scenario"] in selected]
        if {item["scenario"] for item in data["workloads"]} != selected:
            raise InvalidConfigurationError("legacy scenario list includes an unknown scenario")
    if "QUICPERF_NETWORKS" in assignments:
        data["backends"]["server"] = _words(assignments["QUICPERF_NETWORKS"], "QUICPERF_NETWORKS")
    servers = len(data["roles"]["servers"])
    scenarios = len(data["workloads"])
    backends = len(data["backends"]["server"])
    rows = servers if servers > 1 and servers % 2 == 0 else 1
    primary = rows * scenarios * servers * backends
    retry = int(data["schedule"]["dormant_retry_per_microblock"])
    data["schedule"]["sessions"] = 2 if rows > 1 else 1
    data["schedule"]["williams_rows"] = rows
    data["expected_cardinality"] = {
        "planned_trials": primary,
        "maximum_trial_ids": primary * (1 + retry),
        "committed_samples": primary,
        "sessions": data["schedule"]["sessions"],
        "williams_rows": rows,
    }
    validate_experiment_spec(data)
    return canonical_bytes(data)
