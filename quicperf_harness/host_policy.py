from __future__ import annotations

import argparse
import hashlib
import os
import re
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .canonical import canonical_bytes, loads_strict
from .lanes import (
    CGROUP_ROOT_ENV,
    LaneError,
    activate_delegated_controllers,
    delegated_cgroup_root,
)
from .topology import TopologyError, allocate_lanes, discover_physical_cores


class HostPolicyError(RuntimeError):
    pass


STATE_SCHEMA = "quicperf.host-policy-state.v8"
PLAN_SCHEMA = "quicperf.host-policy-plan.v2"
OBSERVATION_SCHEMA = "quicperf.host-policy-observation.v6"
_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
_POLICY_PATTERN = re.compile(r"policy[0-9]+")
PUBLICATION_FREQUENCY_KHZ = "3800000"
_SWAP_UNIT_PATTERN = re.compile(r"[A-Za-z0-9:_.\\x-]+\.swap")


@dataclass(frozen=True)
class HostPaths:
    cpu_sysfs: Path = Path("/sys/devices/system/cpu")
    proc_swaps: Path = Path("/proc/swaps")
    boot_id: Path = Path("/proc/sys/kernel/random/boot_id")
    cgroup_mount: Path = Path("/sys/fs/cgroup")
    proc_self_cgroup: Path = Path("/proc/self/cgroup")
    proc_irq: Path = Path("/proc/irq")
    proc_cmdline: Path = Path("/proc/cmdline")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise HostPolicyError(f"cannot read {path}: {exc}") from exc


def _write_verified(path: Path, value: str) -> None:
    try:
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise HostPolicyError(f"cannot write {value!r} to {path}: {exc}") from exc
    deadline = time.monotonic() + 1.0
    while (observed := _read(path)) != value and time.monotonic() < deadline:
        time.sleep(0.01)
    if observed != value:
        raise HostPolicyError(
            f"host policy write did not stick at {path}: expected={value} observed={observed}"
        )


def _swap_entries(proc_swaps: Path) -> list[dict[str, Any]]:
    try:
        lines = proc_swaps.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise HostPolicyError(f"cannot read {proc_swaps}: {exc}") from exc
    if not lines or lines[0].split() != ["Filename", "Type", "Size", "Used", "Priority"]:
        raise HostPolicyError("/proc/swaps has an unexpected header")
    entries: list[dict[str, Any]] = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != 5:
            raise HostPolicyError(f"malformed /proc/swaps row: {line!r}")
        name, kind, size, used, priority = fields
        try:
            numeric = (int(size), int(used), int(priority))
        except ValueError as exc:
            raise HostPolicyError(f"non-numeric /proc/swaps row: {line!r}") from exc
        if numeric[0] < 0 or numeric[1] < 0 or numeric[1] > numeric[0]:
            raise HostPolicyError(f"invalid /proc/swaps sizes: {line!r}")
        entries.append(
            {
                "path": name,
                "type": kind,
                "size_kib": numeric[0],
                "used_kib": numeric[1],
                "priority": numeric[2],
            }
        )
    return entries


def _systemd_swap_unit(path: str) -> str | None:
    try:
        escaped = subprocess.run(
            ["/usr/bin/systemd-escape", "--path", "--suffix=swap", path],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        load_state = subprocess.run(
            ["/usr/bin/systemctl", "show", escaped, "--property=LoadState", "--value"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise HostPolicyError(f"cannot resolve systemd ownership for swap {path}: {exc}") from exc
    return escaped if load_state == "loaded" else None


def _cpu_policy_snapshot(cpu_sysfs: Path) -> list[dict[str, str]]:
    policies = sorted((cpu_sysfs / "cpufreq").glob("policy[0-9]*"))
    if not policies:
        raise HostPolicyError("no CPU frequency policies are exposed")
    result: list[dict[str, str]] = []
    for policy in policies:
        governor = policy / "scaling_governor"
        epp = policy / "energy_performance_preference"
        minimum = policy / "scaling_min_freq"
        maximum = policy / "scaling_max_freq"
        if not all(path.is_file() for path in (governor, epp, minimum, maximum)):
            raise HostPolicyError(
                f"CPU policy lacks governor, EPP, or frequency control: {policy}"
            )
        available_governors = _read(policy / "scaling_available_governors").split()
        available_epps = _read(policy / "energy_performance_available_preferences").split()
        if "performance" not in available_governors or "performance" not in available_epps:
            raise HostPolicyError(f"CPU policy cannot express publication settings: {policy}")
        result.append(
            {
                "path": str(policy.resolve()),
                "governor": _read(governor),
                "epp": _read(epp),
                "scaling_min_khz": _read(minimum),
                "scaling_max_khz": _read(maximum),
            }
        )
    return result


def _turbo_control_snapshot(cpu_sysfs: Path) -> list[dict[str, str]]:
    controls: list[dict[str, str]] = []
    for path, disabled_value in (
        (cpu_sysfs / "cpufreq/boost", "0"),
        (cpu_sysfs / "intel_pstate/no_turbo", "1"),
    ):
        if not path.is_file():
            continue
        value = _read(path)
        if value not in {"0", "1"}:
            raise HostPolicyError(f"invalid CPU turbo control value at {path}: {value!r}")
        controls.append(
            {
                "path": str(path.resolve()),
                "value": value,
                "disabled_value": disabled_value,
            }
        )
    if not controls:
        raise HostPolicyError("no supported CPU turbo/boost control is exposed")
    return controls


def _parse_cpu_list(value: str, label: str, *, allow_empty: bool = False) -> set[int]:
    value = value.strip()
    if value in {"", "(null)"}:
        if allow_empty:
            return set()
        raise HostPolicyError(f"{label} CPU list is empty")
    cpus: set[int] = set()
    for item in value.split(","):
        if re.fullmatch(r"[0-9]+", item):
            begin = end = int(item)
        elif re.fullmatch(r"[0-9]+-[0-9]+", item):
            begin, end = (int(part) for part in item.split("-", 1))
            if end < begin:
                raise HostPolicyError(f"{label} CPU range is reversed: {item}")
        else:
            raise HostPolicyError(f"{label} CPU list is malformed: {value!r}")
        cpus.update(range(begin, end + 1))
    return cpus


def _format_cpu_list(cpus: set[int]) -> str:
    if not cpus:
        raise HostPolicyError("cannot format an empty CPU list")
    ranges: list[str] = []
    ordered = sorted(cpus)
    begin = previous = ordered[0]
    for cpu in ordered[1:]:
        if cpu == previous + 1:
            previous = cpu
            continue
        ranges.append(str(begin) if begin == previous else f"{begin}-{previous}")
        begin = previous = cpu
    ranges.append(str(begin) if begin == previous else f"{begin}-{previous}")
    return ",".join(ranges)


def _format_cpu_mask(cpus: set[int]) -> str:
    if not cpus:
        raise HostPolicyError("cannot format an empty CPU mask")
    mask = sum(1 << cpu for cpu in cpus)
    groups: list[str] = []
    while mask:
        groups.append(f"{mask & 0xffffffff:08x}")
        mask >>= 32
    groups[-1] = groups[-1].lstrip("0") or "0"
    return ",".join(reversed(groups))


def _parse_cpu_mask(value: str, label: str) -> int:
    compact = value.strip().replace(",", "")
    if not compact or re.fullmatch(r"[0-9a-fA-F]+", compact) is None:
        raise HostPolicyError(f"{label} CPU mask is malformed: {value!r}")
    return int(compact, 16)


def _control_writable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise HostPolicyError(f"cannot inspect permissions for {path}: {exc}") from exc
    return bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _publication_cpu_sets(
    cpu_sysfs: Path,
) -> tuple[set[int], int, set[int], set[int], set[int], set[int]]:
    try:
        # Boot isolation intentionally removes publication CPUs from ordinary
        # processes' inherited affinity. Host policy still has to validate the
        # complete online topology before its transient service is launched.
        cores = discover_physical_cores(cpu_sysfs, respect_process_affinity=False)
        lanes = allocate_lanes(cores, 1, client_cores_per_lane=4)
    except (OSError, ValueError, TopologyError) as exc:
        raise HostPolicyError(f"cannot resolve publication CPU topology: {exc}") from exc
    measured_primaries = {
        cpu
        for lane in lanes
        for cpu in (lane.server_cpu, *lane.client_cpus)
    }
    measured = {
        cpu
        for core in cores
        if core.primary_cpu in measured_primaries
        for cpu in core.cpus
    }
    all_cpus = {cpu for core in cores for cpu in core.cpus}
    available_housekeeping = all_cpus - measured
    if (
        not measured
        or not available_housekeeping
        or measured & available_housekeeping
    ):
        raise HostPolicyError("publication measured and housekeeping CPUs are invalid")
    housekeeping_primaries = {
        cpu for lane in lanes for cpu in lane.housekeeping_cpus
    }
    owned_primaries = measured_primaries | housekeeping_primaries
    monitor_cores = [
        core for core in cores if core.primary_cpu not in owned_primaries
    ]
    if not monitor_cores:
        raise HostPolicyError(
            "publication requires a dedicated physical core for the monitor"
        )
    monitor_core = monitor_cores[0]
    if len(monitor_core.cpus) != 2:
        raise HostPolicyError(
            "publication monitor requires one dedicated two-thread SMT core"
        )
    monitor_cpu = monitor_core.primary_cpu
    required_isolated = measured | set(monitor_core.cpus)
    required_housekeeping = housekeeping_primaries
    return (
        measured,
        monitor_cpu,
        required_isolated,
        required_housekeeping,
        all_cpus,
        set(monitor_core.cpus),
    )


def _cmdline_options(proc_cmdline: Path) -> dict[str, str]:
    options: dict[str, str] = {}
    unique = {"isolcpus", "nohz_full", "rcu_nocbs", "irqaffinity"}
    for token in _read(proc_cmdline).split():
        name, separator, value = token.partition("=")
        if not separator:
            continue
        if name in options and name in unique:
            raise HostPolicyError(f"kernel command line repeats {name}")
        options[name] = value
    return options


def _isolcpus_value(value: str) -> tuple[set[str], set[int]]:
    pieces = value.split(",")
    flags: set[str] = set()
    while pieces and pieces[0] in {"domain", "managed_irq", "nohz"}:
        flags.add(pieces.pop(0))
    return flags, _parse_cpu_list(",".join(pieces), "isolcpus")


def _boot_irq_policy(paths: HostPaths) -> dict[str, Any]:
    (
        measured,
        monitor_cpu,
        required_isolated,
        required_housekeeping,
        all_cpus,
        monitor_core,
    ) = _publication_cpu_sets(paths.cpu_sysfs)
    required = (
        "isolcpus/nohz_full/rcu_nocbs containing "
        f"{_format_cpu_list(required_isolated)}, with IRQ affinity on their "
        "online complement"
    )
    options = _cmdline_options(paths.proc_cmdline)
    missing = [
        name
        for name in ("isolcpus", "nohz_full", "rcu_nocbs", "irqaffinity")
        if name not in options
    ]
    if missing:
        raise HostPolicyError(
            "publication IRQ isolation requires a reboot with kernel arguments "
            f"{required}; missing={missing}"
        )
    flags, isolated_cmdline = _isolcpus_value(options["isolcpus"])
    nohz_cmdline = _parse_cpu_list(options["nohz_full"], "nohz_full")
    rcu_cmdline = _parse_cpu_list(options["rcu_nocbs"], "rcu_nocbs")
    irqaffinity_cmdline = _parse_cpu_list(options["irqaffinity"], "irqaffinity")
    isolated_sysfs = _parse_cpu_list(
        _read(paths.cpu_sysfs / "isolated"), "sysfs isolated", allow_empty=True
    )
    nohz_sysfs = _parse_cpu_list(
        _read(paths.cpu_sysfs / "nohz_full"), "sysfs nohz_full", allow_empty=True
    )
    isolated = isolated_cmdline
    housekeeping = all_cpus - isolated
    irq_targets = housekeeping - monitor_core
    mismatches: list[str] = []
    if not {"domain", "managed_irq"}.issubset(flags):
        mismatches.append(f"isolcpus_flags={sorted(flags)}")
    if not required_isolated <= isolated:
        mismatches.append(
            "isolcpus_missing="
            + _format_cpu_list(required_isolated - isolated)
        )
    if not required_housekeeping <= housekeeping:
        mismatches.append(
            "housekeeping_missing="
            + _format_cpu_list(required_housekeeping - housekeeping)
        )
    if monitor_core & housekeeping:
        mismatches.append(
            "monitor_core_not_fully_isolated="
            + _format_cpu_list(monitor_core & housekeeping)
        )
    if not irq_targets:
        mismatches.append("runtime_irq_cpus=empty")
    for name, observed, expected in (
        ("isolcpus", isolated_cmdline, isolated),
        ("nohz_full", nohz_cmdline, isolated),
        ("rcu_nocbs", rcu_cmdline, isolated),
        ("irqaffinity", irqaffinity_cmdline, housekeeping),
        ("sysfs_isolated", isolated_sysfs, isolated),
        ("sysfs_nohz_full", nohz_sysfs, isolated),
    ):
        if observed != expected:
            mismatches.append(
                f"{name}={_format_cpu_list(observed) if observed else 'empty'}"
            )
    if mismatches:
        raise HostPolicyError(
            "publication IRQ isolation is not effective; reboot with kernel arguments "
            f"{required}; observed={mismatches}"
        )
    return {
        "measured_cpus": sorted(measured),
        "monitor_cpu": monitor_cpu,
        "isolated_cpus": sorted(isolated),
        "housekeeping_cpus": sorted(housekeeping),
        "runtime_irq_cpus": sorted(irq_targets),
        "isolcpus_flags": sorted(flags),
        "isolcpus_cpus": sorted(isolated_cmdline),
        "nohz_full_cpus": sorted(nohz_cmdline),
        "rcu_nocbs_cpus": sorted(rcu_cmdline),
        "irqaffinity_cpus": sorted(irqaffinity_cmdline),
        "sysfs_isolated_cpus": sorted(isolated_sysfs),
        "sysfs_nohz_full_cpus": sorted(nohz_sysfs),
    }


def _irq_policy_snapshot(paths: HostPaths) -> dict[str, Any]:
    boot = _boot_irq_policy(paths)
    measured = set(boot["measured_cpus"])
    housekeeping = set(boot["housekeeping_cpus"])
    irq_targets = set(boot["runtime_irq_cpus"])
    default_path = paths.proc_irq / "default_smp_affinity"
    default_value = _read(default_path)
    _parse_cpu_mask(default_value, "default IRQ affinity")
    target_list = _format_cpu_list(irq_targets)
    target_mask = _format_cpu_mask(irq_targets)
    irqs: list[dict[str, Any]] = []
    unsafe_read_only: list[int] = []
    try:
        irq_directories = sorted(
            (path for path in paths.proc_irq.iterdir() if path.name.isdecimal()),
            key=lambda path: int(path.name),
        )
    except OSError as exc:
        raise HostPolicyError(f"cannot enumerate {paths.proc_irq}: {exc}") from exc
    for irq_dir in irq_directories:
        affinity_path = irq_dir / "smp_affinity_list"
        effective_path = irq_dir / "effective_affinity_list"
        if not affinity_path.is_file() or not effective_path.is_file():
            raise HostPolicyError(f"IRQ {irq_dir.name} lacks affinity controls")
        affinity = _read(affinity_path)
        effective = _read(effective_path)
        affinity_cpus = _parse_cpu_list(affinity, f"IRQ {irq_dir.name} affinity")
        effective_cpus = _parse_cpu_list(
            effective, f"IRQ {irq_dir.name} effective affinity", allow_empty=True
        )
        writable = _control_writable(affinity_path)
        irq = int(irq_dir.name)
        if (
            not writable
            and effective_cpus & measured
            and not (affinity_cpus <= measured and effective_cpus <= affinity_cpus)
        ):
            unsafe_read_only.append(irq)
        irqs.append(
            {
                "irq": irq,
                "path": str(affinity_path.resolve()),
                "affinity": affinity,
                "effective_affinity": effective,
                "writable": writable,
                "target": target_list,
            }
        )
    if not irqs:
        raise HostPolicyError("no IRQ affinity controls are exposed")
    if unsafe_read_only:
        raise HostPolicyError(
            "read-only IRQs have unsafe mixed measured/housekeeping affinity: "
            f"{unsafe_read_only}"
        )
    return {
        "boot": boot,
        "default_affinity": {
            "path": str(default_path.resolve()),
            "value": default_value,
            "target": target_mask,
        },
        "irqs": irqs,
    }


def irq_policy_identity(paths: HostPaths = HostPaths()) -> dict[str, Any]:
    """Return the stable boot and configured IRQ policy bound into run identity."""

    policy = _irq_policy_snapshot(paths)
    return {
        "boot": policy["boot"],
        "default_affinity": policy["default_affinity"],
        "irqs": [
            {
                key: value
                for key, value in entry.items()
                if key != "effective_affinity"
            }
            for entry in policy["irqs"]
        ],
    }


def snapshot(paths: HostPaths = HostPaths()) -> dict[str, Any]:
    swaps = _swap_entries(paths.proc_swaps)
    for entry in swaps:
        entry["systemd_unit"] = _systemd_swap_unit(str(entry["path"]))
    return {
        "schema_version": STATE_SCHEMA,
        "boot_id": _read(paths.boot_id),
        "swaps": swaps,
        "cpu_policies": _cpu_policy_snapshot(paths.cpu_sysfs),
        "turbo_controls": _turbo_control_snapshot(paths.cpu_sysfs),
        "irq_policy": _irq_policy_snapshot(paths),
    }


def _validate_state_shape(state: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "boot_id",
        "swaps",
        "cpu_policies",
        "turbo_controls",
        "irq_policy",
    }
    if set(state) != required or state.get("schema_version") != STATE_SCHEMA:
        raise HostPolicyError("host policy state schema is invalid")
    if not isinstance(state["boot_id"], str) or not state["boot_id"]:
        raise HostPolicyError("host policy boot ID is invalid")
    if (
        not isinstance(state["swaps"], list)
        or not isinstance(state["cpu_policies"], list)
        or not isinstance(state["turbo_controls"], list)
    ):
        raise HostPolicyError("host policy state collections are invalid")
    if not state["cpu_policies"] or not state["turbo_controls"]:
        raise HostPolicyError("host policy state lacks CPU controls")
    for entry in state["swaps"]:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "type",
            "size_kib",
            "used_kib",
            "priority",
            "systemd_unit",
        }:
            raise HostPolicyError("saved swap entry is malformed")
        if not isinstance(entry["path"], str) or not entry["path"]:
            raise HostPolicyError("saved swap path is malformed")
        if not isinstance(entry["type"], str) or not entry["type"]:
            raise HostPolicyError("saved swap type is malformed")
        if any(
            type(entry[key]) is not int
            for key in ("size_kib", "used_kib", "priority")
        ):
            raise HostPolicyError("saved swap numeric field is malformed")
        if (
            entry["size_kib"] < 0
            or entry["used_kib"] < 0
            or entry["used_kib"] > entry["size_kib"]
        ):
            raise HostPolicyError("saved swap sizes are invalid")
        unit = entry["systemd_unit"]
        if unit is not None and (
            not isinstance(unit, str) or _SWAP_UNIT_PATTERN.fullmatch(unit) is None
        ):
            raise HostPolicyError("saved swap unit is malformed")
    if len({entry["path"] for entry in state["swaps"]}) != len(state["swaps"]):
        raise HostPolicyError("saved swap paths are not unique")
    for entry in state["cpu_policies"]:
        if not isinstance(entry, dict) or set(entry) != {
            "path", "governor", "epp", "scaling_min_khz", "scaling_max_khz"
        }:
            raise HostPolicyError("saved CPU policy entry is malformed")
        if any(not isinstance(entry[key], str) or not entry[key] for key in entry):
            raise HostPolicyError("saved CPU policy field is malformed")
        try:
            minimum = int(entry["scaling_min_khz"])
            maximum = int(entry["scaling_max_khz"])
        except ValueError as exc:
            raise HostPolicyError("saved CPU frequency is malformed") from exc
        if minimum <= 0 or maximum < minimum:
            raise HostPolicyError("saved CPU frequency bounds are invalid")
    if len({entry["path"] for entry in state["cpu_policies"]}) != len(
        state["cpu_policies"]
    ):
        raise HostPolicyError("saved CPU policy paths are not unique")
    for entry in state["turbo_controls"]:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "value",
            "disabled_value",
        }:
            raise HostPolicyError("saved turbo control entry is malformed")
        if not isinstance(entry["path"], str) or not entry["path"]:
            raise HostPolicyError("saved turbo control path is malformed")
        if entry["value"] not in {"0", "1"} or entry["disabled_value"] not in {
            "0",
            "1",
        }:
            raise HostPolicyError("saved turbo control value is malformed")
    if len({entry["path"] for entry in state["turbo_controls"]}) != len(
        state["turbo_controls"]
    ):
        raise HostPolicyError("saved turbo control paths are not unique")
    irq_policy = state["irq_policy"]
    if not isinstance(irq_policy, dict) or set(irq_policy) != {
        "boot",
        "default_affinity",
        "irqs",
    }:
        raise HostPolicyError("saved IRQ policy is malformed")
    boot = irq_policy["boot"]
    boot_fields = {
        "measured_cpus",
        "monitor_cpu",
        "isolated_cpus",
        "housekeeping_cpus",
        "runtime_irq_cpus",
        "isolcpus_flags",
        "isolcpus_cpus",
        "nohz_full_cpus",
        "rcu_nocbs_cpus",
        "irqaffinity_cpus",
        "sysfs_isolated_cpus",
        "sysfs_nohz_full_cpus",
    }
    if not isinstance(boot, dict) or set(boot) != boot_fields:
        raise HostPolicyError("saved IRQ boot policy is malformed")
    measured = boot["measured_cpus"]
    housekeeping = boot["housekeeping_cpus"]
    irq_targets = boot["runtime_irq_cpus"]
    for field in boot_fields - {"isolcpus_flags", "monitor_cpu"}:
        values = boot[field]
        if (
            not isinstance(values, list)
            or any(type(cpu) is not int or cpu < 0 for cpu in values)
            or values != sorted(set(values))
        ):
            raise HostPolicyError(f"saved IRQ boot field is malformed: {field}")
    if type(boot["monitor_cpu"]) is not int or boot["monitor_cpu"] < 0:
        raise HostPolicyError("saved IRQ monitor CPU is malformed")
    if (
        not isinstance(boot["isolcpus_flags"], list)
        or any(not isinstance(flag, str) or not flag for flag in boot["isolcpus_flags"])
        or boot["isolcpus_flags"] != sorted(set(boot["isolcpus_flags"]))
        or not {"domain", "managed_irq"}.issubset(boot["isolcpus_flags"])
    ):
        raise HostPolicyError("saved isolcpus flags are malformed")
    isolated = boot["isolated_cpus"]
    monitor_cpu = boot["monitor_cpu"]
    if (
        not measured
        or monitor_cpu in measured
        or not (set(measured) | {monitor_cpu}) <= set(isolated)
        or not housekeeping
        or not irq_targets
        or set(isolated) & set(housekeeping)
        or set(measured) & set(housekeeping)
        or not set(irq_targets) <= set(housekeeping)
    ):
        raise HostPolicyError("saved measured/housekeeping CPU sets are invalid")
    for field in (
        "isolcpus_cpus",
        "nohz_full_cpus",
        "rcu_nocbs_cpus",
        "sysfs_isolated_cpus",
        "sysfs_nohz_full_cpus",
    ):
        if boot[field] != isolated:
            raise HostPolicyError(f"saved IRQ boot field differs from isolated CPUs: {field}")
    if boot["irqaffinity_cpus"] != housekeeping:
        raise HostPolicyError("saved irqaffinity differs from housekeeping CPUs")
    default = irq_policy["default_affinity"]
    if not isinstance(default, dict) or set(default) != {"path", "value", "target"}:
        raise HostPolicyError("saved default IRQ affinity is malformed")
    if any(not isinstance(default[field], str) or not default[field] for field in default):
        raise HostPolicyError("saved default IRQ affinity field is malformed")
    _parse_cpu_mask(default["value"], "saved default IRQ affinity")
    if _parse_cpu_mask(default["target"], "saved target IRQ affinity") != sum(
        1 << cpu for cpu in irq_targets
    ):
        raise HostPolicyError("saved default IRQ target is malformed")
    if not isinstance(irq_policy["irqs"], list) or not irq_policy["irqs"]:
        raise HostPolicyError("saved IRQ entries are malformed")
    for entry in irq_policy["irqs"]:
        if not isinstance(entry, dict) or set(entry) != {
            "irq",
            "path",
            "affinity",
            "effective_affinity",
            "writable",
            "target",
        }:
            raise HostPolicyError("saved IRQ entry is malformed")
        if type(entry["irq"]) is not int or entry["irq"] < 0:
            raise HostPolicyError("saved IRQ number is malformed")
        if not isinstance(entry["path"], str) or not entry["path"]:
            raise HostPolicyError("saved IRQ path is malformed")
        if type(entry["writable"]) is not bool:
            raise HostPolicyError("saved IRQ writability is malformed")
        if (
            not isinstance(entry["affinity"], str)
            or not entry["affinity"]
            or not isinstance(entry["effective_affinity"], str)
            or not isinstance(entry["target"], str)
            or not entry["target"]
        ):
            raise HostPolicyError("saved IRQ affinity field is malformed")
        affinity = _parse_cpu_list(entry["affinity"], "saved IRQ affinity")
        effective = _parse_cpu_list(
            entry["effective_affinity"],
            "saved IRQ effective affinity",
            allow_empty=True,
        )
        if entry["target"] != _format_cpu_list(set(irq_targets)):
            raise HostPolicyError("saved IRQ target is malformed")
        if (
            not entry["writable"]
            and effective & set(measured)
            and not (affinity <= set(measured) and effective <= affinity)
        ):
            raise HostPolicyError("saved read-only IRQ affinity is unsafe")
        if not affinity:
            raise HostPolicyError("saved IRQ affinity is empty")
    if len({entry["irq"] for entry in irq_policy["irqs"]}) != len(
        irq_policy["irqs"]
    ):
        raise HostPolicyError("saved IRQ numbers are not unique")
    if len({entry["path"] for entry in irq_policy["irqs"]}) != len(
        irq_policy["irqs"]
    ):
        raise HostPolicyError("saved IRQ paths are not unique")


def publication_policy_plan(state: dict[str, Any]) -> dict[str, Any]:
    _validate_state_shape(state)
    changes: list[dict[str, Any]] = []
    for entry in state["swaps"]:
        changes.append(
            {
                "kind": "swap",
                "path": entry["path"],
                "from": {
                    key: entry[key]
                    for key in (
                        "type",
                        "size_kib",
                        "used_kib",
                        "priority",
                        "systemd_unit",
                    )
                },
                "to": "inactive",
            }
        )
    for entry in state["cpu_policies"]:
        if entry["governor"] != "performance":
            changes.append(
                {
                    "kind": "governor",
                    "path": f"{entry['path']}/scaling_governor",
                    "from": entry["governor"],
                    "to": "performance",
                }
            )
        if entry["epp"] != "performance":
            changes.append(
                {
                    "kind": "epp",
                    "path": f"{entry['path']}/energy_performance_preference",
                    "from": entry["epp"],
                    "to": "performance",
                }
            )
        if (
            entry["scaling_min_khz"] != PUBLICATION_FREQUENCY_KHZ
            or entry["scaling_max_khz"] != PUBLICATION_FREQUENCY_KHZ
        ):
            changes.append(
                {
                    "kind": "frequency",
                    "path": entry["path"],
                    "from": {
                        "scaling_min_khz": entry["scaling_min_khz"],
                        "scaling_max_khz": entry["scaling_max_khz"],
                    },
                    "to": {
                        "scaling_min_khz": PUBLICATION_FREQUENCY_KHZ,
                        "scaling_max_khz": PUBLICATION_FREQUENCY_KHZ,
                    },
                }
            )
    for entry in state["turbo_controls"]:
        if entry["value"] != entry["disabled_value"]:
            changes.append(
                {
                    "kind": "turbo",
                    "path": entry["path"],
                    "from": entry["value"],
                    "to": entry["disabled_value"],
                }
            )
    irq_policy = state["irq_policy"]
    default = irq_policy["default_affinity"]
    if _parse_cpu_mask(default["value"], "default IRQ affinity") != _parse_cpu_mask(
        default["target"], "target default IRQ affinity"
    ):
        changes.append(
            {
                "kind": "irq-default",
                "path": default["path"],
                "from": default["value"],
                "to": default["target"],
            }
        )
    for entry in irq_policy["irqs"]:
        if entry["writable"] and _parse_cpu_list(
            entry["affinity"], f"IRQ {entry['irq']} affinity"
        ) != _parse_cpu_list(entry["target"], f"IRQ {entry['irq']} target"):
            changes.append(
                {
                    "kind": "irq",
                    "path": entry["path"],
                    "from": entry["affinity"],
                    "to": entry["target"],
                }
            )
    changes.sort(key=lambda entry: (str(entry["kind"]), str(entry["path"])))
    return {
        "schema_version": PLAN_SCHEMA,
        "boot_id": state["boot_id"],
        "changes": changes,
    }


def publication_policy_plan_sha256(state: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(publication_policy_plan(state))).hexdigest()


def publication_policy_change_lines(state: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for change in publication_policy_plan(state)["changes"]:
        if change["kind"] == "swap":
            source = change["from"]
            lines.append(
                f"disable swap {change['path']} "
                f"(used={source['used_kib']} KiB, priority={source['priority']})"
            )
        elif change["kind"] == "frequency":
            lines.append(
                f"pin frequency {change['path']} from "
                f"min={change['from']['scaling_min_khz']} "
                f"max={change['from']['scaling_max_khz']} to "
                f"min=max={PUBLICATION_FREQUENCY_KHZ} kHz"
            )
        elif change["kind"] in {"irq", "irq-default"}:
            lines.append(
                f"route {change['kind']} {change['path']} from "
                f"{change['from']} to housekeeping CPUs {change['to']}"
            )
        else:
            lines.append(
                f"set {change['kind']} {change['path']} from "
                f"{change['from']} to {change['to']}"
            )
    return lines


def _atomic_store(path: Path, state: dict[str, Any]) -> None:
    payload = canonical_bytes(state)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _load_state(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
        state = loads_strict(payload)
    except (OSError, ValueError) as exc:
        raise HostPolicyError(f"cannot load host policy state {path}: {exc}") from exc
    if canonical_bytes(state) != payload or not isinstance(state, dict):
        raise HostPolicyError("host policy state is not canonical JSON")
    _validate_state_shape(state)
    return state


def _run(command: Sequence[str]) -> None:
    try:
        subprocess.run(list(command), check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise HostPolicyError(f"host command failed: {' '.join(command)}: {exc}") from exc


def _validate_policy_path(path: str, cpu_sysfs: Path) -> Path:
    try:
        resolved_cpu = cpu_sysfs.resolve(strict=True)
        resolved = Path(path).resolve(strict=True)
    except OSError as exc:
        raise HostPolicyError(f"cannot resolve saved CPU policy path {path}: {exc}") from exc
    if (
        resolved.parent != resolved_cpu / "cpufreq"
        or _POLICY_PATTERN.fullmatch(resolved.name) is None
    ):
        raise HostPolicyError(f"saved CPU policy path is outside cpufreq: {resolved}")
    return resolved


def _validate_turbo_path(path: str, disabled_value: str, cpu_sysfs: Path) -> Path:
    try:
        resolved_cpu = cpu_sysfs.resolve(strict=True)
        resolved = Path(path).resolve(strict=True)
    except OSError as exc:
        raise HostPolicyError(f"cannot resolve saved turbo control path {path}: {exc}") from exc
    expected = {
        (resolved_cpu / "cpufreq/boost").resolve(): "0",
        (resolved_cpu / "intel_pstate/no_turbo").resolve(): "1",
    }
    if resolved not in expected or expected[resolved] != disabled_value:
        raise HostPolicyError(f"saved turbo control path is invalid: {resolved}")
    return resolved


def _validate_irq_path(path: str, irq: int, proc_irq: Path) -> Path:
    try:
        resolved_root = proc_irq.resolve(strict=True)
        resolved = Path(path).resolve(strict=True)
    except OSError as exc:
        raise HostPolicyError(f"cannot resolve saved IRQ path {path}: {exc}") from exc
    expected = resolved_root / str(irq) / "smp_affinity_list"
    if resolved != expected:
        raise HostPolicyError(f"saved IRQ path is outside /proc/irq: {resolved}")
    return resolved


def _validate_default_irq_path(path: str, proc_irq: Path) -> Path:
    try:
        resolved_root = proc_irq.resolve(strict=True)
        resolved = Path(path).resolve(strict=True)
    except OSError as exc:
        raise HostPolicyError(
            f"cannot resolve saved default IRQ affinity path {path}: {exc}"
        ) from exc
    if resolved != resolved_root / "default_smp_affinity":
        raise HostPolicyError(
            f"saved default IRQ affinity path is outside /proc/irq: {resolved}"
        )
    return resolved


def _write_mask_verified(path: Path, value: str) -> None:
    target = _parse_cpu_mask(value, f"target mask {path}")
    try:
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise HostPolicyError(f"cannot write {value!r} to {path}: {exc}") from exc
    deadline = time.monotonic() + 1.0
    while (
        observed := _parse_cpu_mask(_read(path), f"observed mask {path}")
    ) != target and time.monotonic() < deadline:
        time.sleep(0.01)
    if observed != target:
        raise HostPolicyError(
            f"host IRQ mask write did not stick at {path}: "
            f"expected={value} observed={_read(path)}"
        )


def _changed_irq_entries(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        entry
        for entry in state["irq_policy"]["irqs"]
        if entry["writable"]
        and _parse_cpu_list(
            entry["affinity"], f"IRQ {entry['irq']} affinity"
        )
        != _parse_cpu_list(entry["target"], f"IRQ {entry['irq']} target")
    ]


def _apply_irq_policy(state: dict[str, Any], paths: HostPaths) -> None:
    policy = state["irq_policy"]
    default = policy["default_affinity"]
    default_path = _validate_default_irq_path(default["path"], paths.proc_irq)
    if _parse_cpu_mask(
        _read(default_path), "current default IRQ affinity"
    ) != _parse_cpu_mask(default["target"], "target default IRQ affinity"):
        _write_mask_verified(default_path, default["target"])
    for entry in _changed_irq_entries(state):
        path = _validate_irq_path(entry["path"], entry["irq"], paths.proc_irq)
        if _read(path) != entry["target"]:
            _write_verified(path, entry["target"])


def _converge_turbo_controls(
    controls: list[tuple[dict[str, str], Path]],
    target_key: str,
    operation: str,
) -> None:
    for _attempt in range(2 * len(controls) + 1):
        pending = [
            (entry, path)
            for entry, path in controls
            if _read(path) != entry[target_key]
        ]
        if not pending:
            return
        for entry, path in pending:
            _write_verified(path, str(entry[target_key]))
    observed = {str(path): _read(path) for _entry, path in controls}
    raise HostPolicyError(f"turbo control {operation} did not converge: {observed}")


def _set_frequency_pair(policy: Path, minimum: str, maximum: str) -> None:
    try:
        minimum_value = int(minimum)
        maximum_value = int(maximum)
        current_minimum = int(_read(policy / "scaling_min_freq"))
    except ValueError as exc:
        raise HostPolicyError(f"CPU frequency control is malformed: {policy}") from exc
    if minimum_value <= 0 or maximum_value < minimum_value:
        raise HostPolicyError(f"CPU frequency target is invalid: {policy}")
    order = (
        (("scaling_min_freq", minimum), ("scaling_max_freq", maximum))
        if maximum_value < current_minimum
        else (("scaling_max_freq", maximum), ("scaling_min_freq", minimum))
    )
    for name, value in order:
        if _read(policy / name) != value:
            _write_verified(policy / name, value)
    if (
        _read(policy / "scaling_min_freq") != minimum
        or _read(policy / "scaling_max_freq") != maximum
    ):
        raise HostPolicyError(f"CPU frequency pair did not converge: {policy}")


def _verify_prepared(paths: HostPaths) -> dict[str, Any]:
    state = snapshot(paths)
    governors = sorted({entry["governor"] for entry in state["cpu_policies"]})
    epps = sorted({entry["epp"] for entry in state["cpu_policies"]})
    turbo = [
        entry
        for entry in state["turbo_controls"]
        if entry["value"] != entry["disabled_value"]
    ]
    frequencies = sorted(
        {
            (entry["scaling_min_khz"], entry["scaling_max_khz"])
            for entry in state["cpu_policies"]
        }
    )
    irq_policy = state["irq_policy"]
    measured = set(irq_policy["boot"]["measured_cpus"])
    default = irq_policy["default_affinity"]
    irq_violations = [
        entry["irq"]
        for entry in irq_policy["irqs"]
        if entry["writable"]
        and _parse_cpu_list(
            entry["effective_affinity"],
            f"IRQ {entry['irq']} effective affinity",
            allow_empty=True,
        )
        & measured
    ]
    writable_policy_violations = [
        entry["irq"]
        for entry in irq_policy["irqs"]
        if entry["writable"]
        and _parse_cpu_list(
            entry["affinity"], f"IRQ {entry['irq']} affinity"
        )
        != _parse_cpu_list(entry["target"], f"IRQ {entry['irq']} target")
    ]
    if (
        state["swaps"]
        or governors != ["performance"]
        or epps != ["performance"]
        or frequencies != [(PUBLICATION_FREQUENCY_KHZ, PUBLICATION_FREQUENCY_KHZ)]
        or turbo
        or _parse_cpu_mask(default["value"], "default IRQ affinity")
        != _parse_cpu_mask(default["target"], "target default IRQ affinity")
        or irq_violations
        or writable_policy_violations
    ):
        raise HostPolicyError(
            "prepared host policy verification failed: "
            f"swaps={state['swaps']} governors={governors} epps={epps} "
            f"frequencies={frequencies} turbo={turbo} "
            f"irq_effective={irq_violations} irq_allowed={writable_policy_violations}"
        )
    try:
        cgroup_root = delegated_cgroup_root(
            cgroup_mount=paths.cgroup_mount,
            proc_self_cgroup=paths.proc_self_cgroup,
        )
    except LaneError as exc:
        raise HostPolicyError(f"delegated cgroup verification failed: {exc}") from exc
    return {
        "schema_version": OBSERVATION_SCHEMA,
        "status": "prepared",
        "swap_count": 0,
        "governors": governors,
        "epps": epps,
        "frequencies_khz": frequencies,
        "turbo": "disabled",
        "irq_policy_sha256": hashlib.sha256(
            canonical_bytes(irq_policy)
        ).hexdigest(),
        "measured_cpus": irq_policy["boot"]["measured_cpus"],
        "monitor_cpu": irq_policy["boot"]["monitor_cpu"],
        "isolated_cpus": irq_policy["boot"]["isolated_cpus"],
        "housekeeping_cpus": irq_policy["boot"]["housekeeping_cpus"],
        "runtime_irq_cpus": irq_policy["boot"]["runtime_irq_cpus"],
        "cgroup_root": str(cgroup_root),
    }


def prepare(
    state_path: Path,
    authorized_plan_sha256: str,
    paths: HostPaths = HostPaths(),
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise HostPolicyError("publication host preparation requires root")
    if state_path.exists():
        raise HostPolicyError("host policy state already exists; recover it before preparation")
    if _DIGEST_PATTERN.fullmatch(authorized_plan_sha256) is None:
        raise HostPolicyError("authorized host policy plan digest is invalid")
    state = snapshot(paths)
    observed_plan_sha256 = publication_policy_plan_sha256(state)
    if observed_plan_sha256 != authorized_plan_sha256:
        raise HostPolicyError(
            "host policy changed after operator authorization: "
            f"authorized={authorized_plan_sha256} observed={observed_plan_sha256}"
        )
    used_swaps = [entry["path"] for entry in state["swaps"] if entry["used_kib"]]
    if used_swaps:
        raise HostPolicyError(f"refusing to disable swaps with live pages: {used_swaps}")
    cgroup_text = os.environ.get(CGROUP_ROOT_ENV)
    if not cgroup_text:
        raise HostPolicyError(f"{CGROUP_ROOT_ENV} is required")
    try:
        activate_delegated_controllers(
            Path(cgroup_text),
            cgroup_mount=paths.cgroup_mount,
            proc_self_cgroup=paths.proc_self_cgroup,
        )
    except LaneError as exc:
        raise HostPolicyError(f"cannot activate delegated controllers: {exc}") from exc
    _atomic_store(state_path, state)
    try:
        _apply_irq_policy(state, paths)
        for entry in state["swaps"]:
            if entry["systemd_unit"] is not None:
                _run(["/usr/bin/systemctl", "stop", str(entry["systemd_unit"])])
            else:
                _run(["/usr/bin/swapoff", "--", str(entry["path"])])
        for entry in state["cpu_policies"]:
            policy = _validate_policy_path(str(entry["path"]), paths.cpu_sysfs)
            if entry["governor"] != "performance":
                _write_verified(policy / "scaling_governor", "performance")
            if entry["epp"] != "performance":
                _write_verified(policy / "energy_performance_preference", "performance")
            if (
                entry["scaling_min_khz"] != PUBLICATION_FREQUENCY_KHZ
                or entry["scaling_max_khz"] != PUBLICATION_FREQUENCY_KHZ
            ):
                _set_frequency_pair(
                    policy,
                    PUBLICATION_FREQUENCY_KHZ,
                    PUBLICATION_FREQUENCY_KHZ,
                )
        if any(
            entry["value"] != entry["disabled_value"]
            for entry in state["turbo_controls"]
        ):
            turbo_controls = [
                (
                    entry,
                    _validate_turbo_path(
                        str(entry["path"]),
                        str(entry["disabled_value"]),
                        paths.cpu_sysfs,
                    ),
                )
                for entry in state["turbo_controls"]
            ]
            _converge_turbo_controls(
                turbo_controls, "disabled_value", "preparation"
            )
        return _verify_prepared(paths)
    except BaseException:
        restore(state_path, paths)
        raise


def restore(state_path: Path, paths: HostPaths = HostPaths()) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise HostPolicyError("publication host restoration requires root")
    state = _load_state(state_path)
    if state["boot_id"] != _read(paths.boot_id):
        raise HostPolicyError("host policy state belongs to a different boot")
    observed_boot = _boot_irq_policy(paths)
    if observed_boot != state["irq_policy"]["boot"]:
        raise HostPolicyError("IRQ boot policy changed during the publication run")
    saved_default = state["irq_policy"]["default_affinity"]
    resolved_default_irq = _validate_default_irq_path(
        saved_default["path"], paths.proc_irq
    )
    current_default_mask = _parse_cpu_mask(
        _read(resolved_default_irq), "current default IRQ affinity"
    )
    allowed_default_masks = {
        _parse_cpu_mask(saved_default["value"], "saved default IRQ affinity"),
        _parse_cpu_mask(saved_default["target"], "target default IRQ affinity"),
    }
    if current_default_mask not in allowed_default_masks:
        raise HostPolicyError("default IRQ affinity changed externally during the run")
    changed_irq_numbers = {entry["irq"] for entry in _changed_irq_entries(state)}
    resolved_irqs: list[tuple[dict[str, Any], Path]] = []
    for entry in state["irq_policy"]["irqs"]:
        path = _validate_irq_path(entry["path"], entry["irq"], paths.proc_irq)
        writable = _control_writable(path)
        if writable != entry["writable"]:
            raise HostPolicyError(
                f"IRQ writability changed during the run: {entry['irq']}"
            )
        allowed = {entry["affinity"]}
        if entry["irq"] in changed_irq_numbers:
            allowed.add(entry["target"])
        if _read(path) not in allowed:
            raise HostPolicyError(
                f"IRQ affinity changed externally during the run: {entry['irq']}"
            )
        resolved_irqs.append((entry, path))

    resolved_policies: list[tuple[dict[str, str], Path]] = []
    for entry in state["cpu_policies"]:
        policy = _validate_policy_path(str(entry["path"]), paths.cpu_sysfs)
        if entry["governor"] not in _read(
            policy / "scaling_available_governors"
        ).split():
            raise HostPolicyError(f"saved governor is no longer available for {policy}")
        if entry["epp"] not in _read(
            policy / "energy_performance_available_preferences"
        ).split():
            raise HostPolicyError(f"saved EPP is no longer available for {policy}")
        policy_changed = (
            entry["governor"] != "performance" or entry["epp"] != "performance"
        )
        if policy_changed:
            if _read(policy / "scaling_governor") not in {
                entry["governor"],
                "performance",
            }:
                raise HostPolicyError(
                    f"governor changed externally during the run: {policy}"
                )
            if _read(policy / "energy_performance_preference") not in {
                entry["epp"],
                "performance",
            }:
                raise HostPolicyError(f"EPP changed externally during the run: {policy}")
        frequency_changed = (
            entry["scaling_min_khz"] != PUBLICATION_FREQUENCY_KHZ
            or entry["scaling_max_khz"] != PUBLICATION_FREQUENCY_KHZ
        )
        if frequency_changed:
            for name, saved in (
                ("scaling_min_freq", entry["scaling_min_khz"]),
                ("scaling_max_freq", entry["scaling_max_khz"]),
            ):
                if _read(policy / name) not in {saved, PUBLICATION_FREQUENCY_KHZ}:
                    raise HostPolicyError(
                        f"CPU frequency changed externally during the run: {policy}"
                    )
        resolved_policies.append((entry, policy))

    resolved_turbo: list[tuple[dict[str, str], Path]] = []
    turbo_changed = any(
        entry["value"] != entry["disabled_value"]
        for entry in state["turbo_controls"]
    )
    for entry in state["turbo_controls"]:
        control = _validate_turbo_path(
            str(entry["path"]), str(entry["disabled_value"]), paths.cpu_sysfs
        )
        if turbo_changed and _read(control) not in {"0", "1"}:
            raise HostPolicyError(
                f"turbo control changed externally during the run: {control}"
            )
        resolved_turbo.append((entry, control))

    current = {str(entry["path"]): entry for entry in _swap_entries(paths.proc_swaps)}
    expected = {str(entry["path"]): entry for entry in state["swaps"]}
    unexpected = sorted(set(current) - set(expected))
    if unexpected:
        raise HostPolicyError(f"refusing to remove swaps activated externally: {unexpected}")
    for name in sorted(set(current) & set(expected)):
        if any(
            current[name][key] != expected[name][key]
            for key in ("type", "size_kib", "priority")
        ):
            raise HostPolicyError(f"swap changed externally during the run: {name}")

    for entry, policy in resolved_policies:
        policy_changed = (
            entry["governor"] != "performance" or entry["epp"] != "performance"
        )
        if policy_changed:
            if _read(policy / "scaling_governor") != entry["governor"]:
                _write_verified(
                    policy / "scaling_governor", str(entry["governor"])
                )
            if _read(policy / "energy_performance_preference") != entry["epp"]:
                _write_verified(
                    policy / "energy_performance_preference", str(entry["epp"])
                )
        if (
            _read(policy / "scaling_min_freq") != entry["scaling_min_khz"]
            or _read(policy / "scaling_max_freq") != entry["scaling_max_khz"]
        ):
            _set_frequency_pair(
                policy,
                str(entry["scaling_min_khz"]),
                str(entry["scaling_max_khz"]),
            )
    if turbo_changed:
        _converge_turbo_controls(resolved_turbo, "value", "restoration")

    for name, entry in expected.items():
        if name not in current:
            if entry["systemd_unit"] is not None:
                _run(["/usr/bin/systemctl", "start", str(entry["systemd_unit"])])
            else:
                _run(
                    [
                        "/usr/bin/swapon",
                        "--priority",
                        str(entry["priority"]),
                        "--",
                        name,
                    ]
                )
    restored_swaps = {
        str(entry["path"]): entry for entry in _swap_entries(paths.proc_swaps)
    }
    if set(restored_swaps) != set(expected) or any(
        any(
            restored_swaps[name][key] != expected[name][key]
            for key in ("type", "size_kib", "priority")
        )
        for name in expected
    ):
        raise HostPolicyError("swap restoration did not reproduce the saved devices/priorities")
    for entry, policy in resolved_policies:
        policy_changed = (
            entry["governor"] != "performance" or entry["epp"] != "performance"
        )
        if policy_changed:
            if _read(policy / "scaling_governor") != entry["governor"]:
                raise HostPolicyError(f"governor restoration failed for {policy}")
            if _read(policy / "energy_performance_preference") != entry["epp"]:
                raise HostPolicyError(f"EPP restoration failed for {policy}")
        if (
            _read(policy / "scaling_min_freq") != entry["scaling_min_khz"]
            or _read(policy / "scaling_max_freq") != entry["scaling_max_khz"]
        ):
            raise HostPolicyError(f"CPU frequency restoration failed for {policy}")
    if turbo_changed:
        for entry, control in resolved_turbo:
            if _read(control) != entry["value"]:
                raise HostPolicyError(f"turbo restoration failed for {control}")
    for entry, path in resolved_irqs:
        if entry["irq"] in changed_irq_numbers and _read(path) != entry["affinity"]:
            _write_verified(path, entry["affinity"])
    if current_default_mask != _parse_cpu_mask(
        saved_default["value"], "saved default IRQ affinity"
    ):
        _write_mask_verified(resolved_default_irq, saved_default["value"])
    for entry, path in resolved_irqs:
        if _read(path) != entry["affinity"]:
            raise HostPolicyError(f"IRQ affinity restoration failed for {entry['irq']}")
    if _parse_cpu_mask(
        _read(resolved_default_irq), "restored default IRQ affinity"
    ) != _parse_cpu_mask(saved_default["value"], "saved default IRQ affinity"):
        raise HostPolicyError("default IRQ affinity restoration failed")
    state_path.unlink()
    return {
        "schema_version": OBSERVATION_SCHEMA,
        "status": "restored",
        "swap_count": len(expected),
        "governors": sorted({entry["governor"] for entry in state["cpu_policies"]}),
        "epps": sorted({entry["epp"] for entry in state["cpu_policies"]}),
        "frequencies_khz": sorted(
            {
                (entry["scaling_min_khz"], entry["scaling_max_khz"])
                for entry in state["cpu_policies"]
            }
        ),
        "turbo_controls": [
            {"path": entry["path"], "value": entry["value"]}
            for entry in state["turbo_controls"]
        ],
        "irq_policy": "restored",
        "measured_cpus": state["irq_policy"]["boot"]["measured_cpus"],
        "monitor_cpu": state["irq_policy"]["boot"]["monitor_cpu"],
        "isolated_cpus": state["irq_policy"]["boot"]["isolated_cpus"],
        "housekeeping_cpus": state["irq_policy"]["boot"]["housekeeping_cpus"],
    }


def run_quicperf(
    state_path: Path,
    authorized_plan_sha256: str,
    arguments: Sequence[str],
) -> int:
    command = list(arguments)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise HostPolicyError("run-quicperf requires quicperfctl arguments")

    def interrupt(_signal: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    previous = {
        number: signal.signal(number, interrupt)
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    }
    status = 5
    prepared_successfully = False
    try:
        prepared = prepare(state_path, authorized_plan_sha256)
        prepared_successfully = True
        print(canonical_bytes(prepared).decode("utf-8"), flush=True)
        from .cli import main as quicperf_main

        status = quicperf_main(command)
    finally:
        for number in previous:
            signal.signal(number, signal.SIG_IGN)
        try:
            if prepared_successfully or state_path.exists():
                restored = restore(state_path)
                print(canonical_bytes(restored).decode("utf-8"), flush=True)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
    return status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Apply or restore quicperf host policy")
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_command = subparsers.add_parser("prepare")
    prepare_command.add_argument("--state", required=True, type=Path)
    prepare_command.add_argument("--plan-sha256", required=True)
    restore_command = subparsers.add_parser("restore")
    restore_command.add_argument("--state", required=True, type=Path)
    run = subparsers.add_parser("run-quicperf")
    run.add_argument("--state", required=True, type=Path)
    run.add_argument("--plan-sha256", required=True)
    run.add_argument("arguments", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "run-quicperf":
            return run_quicperf(
                arguments.state,
                arguments.plan_sha256,
                arguments.arguments,
            )
        result = (
            prepare(arguments.state, arguments.plan_sha256)
            if arguments.command == "prepare"
            else restore(arguments.state)
        )
    except HostPolicyError as exc:
        print(f"quicperf_host_policy status=failed reason={exc}", flush=True)
        return 4
    print(canonical_bytes(result).decode("utf-8"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
