"""Live AMD delivered-performance provider policy and host primitives."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import ctypes
import hashlib
import heapq
import math
import multiprocessing
from multiprocessing.managers import BaseManager
import os
from pathlib import Path
import select
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Mapping, Sequence

from .canonical import canonical_bytes, load_strict, loads_strict
from .health import (
    AMD_PERF_COUNTER_SOURCE,
    AmdCounterSample,
    AmdPerfCounterReader,
    AmdTemperatureSample,
    HealthError,
)


PROVIDER_VERSION = "amd_delivered_performance_v1"
PROBE_START_LEAD_NS = 250_000_000
CONTINUOUS_MONITOR_SWITCH_INTERVAL_SECONDS = 0.0001
CONTINUOUS_MONITOR_SCHED_FIFO_PRIORITY = 51
CONTINUOUS_MONITOR_BOUNDARY_POLICY_GUARD_NS = 50_000_000
CONTINUOUS_MONITOR_BOUNDARY_SPIN_LEAD_NS = 10_000_000
TEMPERATURE_WATCHDOG_MESSAGE = struct.Struct("=cqqqi")
TEMPERATURE_WATCHDOG_COUNTER_MESSAGE = struct.Struct("=cqqqqi")
TEMPERATURE_WATCHDOG_STARTED = b"S"
TEMPERATURE_WATCHDOG_SAMPLE = b"T"
TEMPERATURE_WATCHDOG_COUNTER_SAMPLE = b"C"
TEMPERATURE_WATCHDOG_STOPPED = b"X"
TEMPERATURE_WATCHDOG_STOP = b"Q"
TEMPERATURE_WATCHDOG_ERROR = b"E"
DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "profiles/v2/host-stability/amd-delivered-performance-v1.json"
)


class AmdMonitorTransientError(HealthError):
    """Treatment-independent AMD monitor scheduling failure."""


class AmdBoundaryMonitorTransientError(AmdMonitorTransientError):
    """A boundary-sampling transient with continuous health evidence intact."""


def _continuous_monitor_wait_ns(
    now_ns: int, due_ns: int, next_boundary_ns: int | None
) -> int:
    wait_ns = max(0, due_ns - now_ns)
    if next_boundary_ns is not None and due_ns == next_boundary_ns:
        wait_ns = max(0, wait_ns - CONTINUOUS_MONITOR_BOUNDARY_SPIN_LEAD_NS)
    return wait_ns


def _continuous_monitor_due_ns(
    now_ns: int,
    next_temperature_ns: int,
    next_policy_ns: int,
    next_boundary_ns: int | None,
) -> int:
    regular_due = min(next_temperature_ns, next_policy_ns)
    if next_boundary_ns is None:
        return regular_due
    spin_start = next_boundary_ns - CONTINUOUS_MONITOR_BOUNDARY_SPIN_LEAD_NS
    counter_guard_start = (
        next_boundary_ns - CONTINUOUS_MONITOR_BOUNDARY_POLICY_GUARD_NS
    )
    if now_ns >= spin_start:
        return next_boundary_ns
    if now_ns >= counter_guard_start:
        return min(next_temperature_ns, spin_start)
    return min(regular_due, counter_guard_start)


def _continuous_monitor_periodic_allowed(
    now_ns: int,
    next_boundary_ns: int | None,
    guard_ns: int,
) -> bool:
    return (
        next_boundary_ns is None
        or now_ns < next_boundary_ns - guard_ns
        or now_ns >= next_boundary_ns
    )


def _continuous_temperature_reasons(
    samples: Sequence["AmdMonitorTemperatureSample"],
    *,
    start_raw_ns: int,
    end_raw_ns: int,
    policy: "AmdProviderPolicy",
) -> tuple[str, ...]:
    if not samples:
        return ("tctl_sample_missing",)
    ordered = tuple(sorted(samples, key=lambda sample: sample.raw_ns))
    reasons = []
    if (
        ordered[0].raw_ns - start_raw_ns > policy.temperature_gap_max_ns
        or end_raw_ns - ordered[-1].raw_ns > policy.temperature_gap_max_ns
        or any(
            current.raw_ns <= previous.raw_ns
            or current.raw_ns - previous.raw_ns > policy.temperature_gap_max_ns
            for previous, current in zip(ordered, ordered[1:])
        )
    ):
        reasons.append("tctl_monitor_dropout")
    if any(
        sample.tctl_millicelsius >= policy.measurement_ceiling_millicelsius
        for sample in ordered
    ):
        reasons.append("tctl_thermal_headroom_breach")
    return tuple(reasons)


@dataclass(frozen=True)
class AmdCpuAllowlistEntry:
    cpuinfo_model_name: str
    product_name: str
    base_frequency_khz: int
    tjmax_millicelsius: int
    official_source_url: str
    official_source_retrieved_utc_date: str
    official_source_sha256: str


@dataclass(frozen=True)
class AmdProviderPolicy:
    entry: AmdCpuAllowlistEntry
    required_cpu_flags: tuple[str, ...]
    positive_frequency_khz: int
    negative_control_frequency_khz: int
    counter_period_ns: int
    counter_interval_min_ns: int
    counter_interval_max_ns: int
    temperature_period_ns: int
    temperature_gap_max_ns: int
    boundary_timestamp_semantics: str
    interval_duration_error_max_fraction: Decimal
    phase_offset_max_ns: int
    cooling_ceiling_millicelsius: int
    cooling_consecutive_ns: int
    cooling_timeout_ns: int
    measurement_ceiling_millicelsius: int
    tjmax_headroom_millicelsius: int
    active_fraction: Decimal
    cumulative_ratio_minimum: Decimal
    active_window_ratio_minimum: Decimal
    loop_cumulative_minimum: Decimal
    loop_bucket_minimum: Decimal
    calibration_probe_seconds: int
    reference_start_second: int
    reference_end_second: int
    qualification_start_second: int
    calibration_active_windows_minimum: int
    session_probe_seconds: int
    session_active_windows_minimum: int
    negative_control_deadline_ns: int
    negative_control_consecutive_windows: int


@dataclass(frozen=True)
class AmdTemperatureSource:
    input_path: Path
    tjmax_millicelsius: int
    tjmax_source: str


@dataclass(frozen=True)
class AmdPolicyReadback:
    policy_path: Path
    affected_cpus: tuple[int, ...]
    scaling_min_khz: int
    scaling_max_khz: int
    governor: str
    epp: str
    boost: bool


@dataclass(frozen=True)
class AmdMonitorCounterSample:
    raw_ns: int
    aperf: int
    mperf: int
    monitor_cpu: int


@dataclass(frozen=True)
class AmdMonitorTemperatureSample:
    raw_ns: int
    tctl_millicelsius: int
    monitor_cpu: int


@dataclass(frozen=True)
class AmdProbeEvidence:
    start_raw_ns: int
    end_raw_ns: int
    monitor_cpu: int
    counter_samples: Mapping[int, tuple[AmdMonitorCounterSample, ...]]
    temperature_samples: tuple[AmdMonitorTemperatureSample, ...]
    loop_buckets: Mapping[int, tuple[int, ...]]
    helper_sha256: str


@dataclass(frozen=True)
class AmdReference:
    ratio: Mapping[int, float]
    loop_iterations: Mapping[int, float]


@dataclass(frozen=True)
class AmdCounterWindow:
    cpu: int
    raw_ns: int
    delta_ns: int
    aperf_delta: int
    mperf_delta: int
    ratio: float
    active: bool
    valid: bool
    reason: str


@dataclass(frozen=True)
class AmdProbeEvaluation:
    passed: bool
    reasons: tuple[str, ...]
    active_windows: Mapping[int, int]
    cumulative_fraction_of_reference: Mapping[int, float]
    minimum_window_fraction_of_reference: Mapping[int, float]
    loop_cumulative_fraction_of_reference: Mapping[int, float]
    minimum_loop_bucket_fraction_of_reference: Mapping[int, float]
    maximum_tctl_millicelsius: int


@dataclass(frozen=True)
class AmdBoundarySnapshot:
    token: str
    target_raw_ns: int
    observed_raw_ns: int
    monitor_cpu: int
    counters: Mapping[int, tuple[int, int]]
    tctl_millicelsius: int
    cgroup_throttling: Mapping[str, tuple[int, int]]


@dataclass(frozen=True)
class AmdMicroblockEvaluation:
    passed: bool
    reasons: tuple[str, ...]
    active_cpus: tuple[int, ...]
    fraction_of_reference: Mapping[int, float]
    start_lateness_ns: int
    end_lateness_ns: int
    target_interval_ns: int
    observed_interval_ns: int
    interval_duration_error_ns: int


def _object(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise HealthError(f"{label} fields differ from the frozen AMD policy")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise HealthError(f"{label} must be a positive integer")
    return value


def _decimal(value: Any, label: str) -> Decimal:
    if not isinstance(value, str):
        raise HealthError(f"{label} must be a decimal string")
    try:
        result = Decimal(value)
    except Exception as exc:
        raise HealthError(f"{label} is not a decimal") from exc
    if not result.is_finite() or result <= 0 or result > 1:
        raise HealthError(f"{label} must be in (0, 1]")
    return result


def load_amd_provider_policy(
    *,
    cpu_model: str,
    path: Path = DEFAULT_POLICY_PATH,
) -> AmdProviderPolicy:
    try:
        root = load_strict(path)
    except Exception as exc:
        raise HealthError(f"cannot load AMD provider policy {path}: {exc}") from exc
    root = _object(
        root,
        {"schema_version", "provider", "allowlist", "required_cpu_flags",
         "policy", "sampling", "thermal", "performance"},
        "AMD provider policy",
    )
    if root["schema_version"] != "quicperf.amd-delivered-performance-policy.v1":
        raise HealthError("AMD provider policy schema is invalid")
    if root["provider"] != PROVIDER_VERSION:
        raise HealthError("AMD provider name is invalid")
    entries = root["allowlist"]
    if not isinstance(entries, list) or not entries:
        raise HealthError("AMD provider allowlist must be nonempty")
    matches = []
    for index, raw in enumerate(entries):
        item = _object(
            raw,
            {"cpuinfo_model_name", "product_name", "base_frequency_khz",
             "tjmax_millicelsius", "official_source"},
            f"AMD allowlist entry {index}",
        )
        source = _object(
            item["official_source"],
            {"url", "retrieved_utc_date", "captured_content_sha256"},
            f"AMD allowlist entry {index} source",
        )
        digest = source["captured_content_sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise HealthError("AMD official-source digest is invalid")
        entry = AmdCpuAllowlistEntry(
            cpuinfo_model_name=str(item["cpuinfo_model_name"]),
            product_name=str(item["product_name"]),
            base_frequency_khz=_positive_integer(
                item["base_frequency_khz"], "AMD base frequency"
            ),
            tjmax_millicelsius=_positive_integer(
                item["tjmax_millicelsius"], "AMD Tjmax"
            ),
            official_source_url=str(source["url"]),
            official_source_retrieved_utc_date=str(source["retrieved_utc_date"]),
            official_source_sha256=digest,
        )
        if entry.cpuinfo_model_name == cpu_model:
            matches.append(entry)
    if len(matches) != 1:
        raise HealthError(
            f"{PROVIDER_VERSION} does not allowlist exact CPU model {cpu_model!r}"
        )
    entry = matches[0]
    flags = root["required_cpu_flags"]
    if (
        not isinstance(flags, list)
        or len(flags) != len(set(flags))
        or any(not isinstance(flag, str) or not flag for flag in flags)
    ):
        raise HealthError("AMD required CPU flags are invalid")
    policy = _object(
        root["policy"],
        {"boost", "governor", "epp", "positive_frequency_khz",
         "negative_control_frequency_khz"},
        "AMD CPU policy",
    )
    if policy["boost"] is not False or policy["governor"] != "performance" or policy["epp"] != "performance":
        raise HealthError("AMD CPU policy must freeze boost off and performance governor/EPP")
    sampling = _object(
        root["sampling"],
        {"counter_period_ns", "counter_interval_min_ns", "counter_interval_max_ns",
         "temperature_period_ns", "temperature_gap_max_ns"},
        "AMD sampling policy",
    )
    thermal = _object(
        root["thermal"],
        {"cooling_ceiling_millicelsius", "cooling_consecutive_ns",
         "cooling_timeout_ns", "measurement_ceiling_millicelsius",
         "tjmax_headroom_millicelsius"},
        "AMD thermal policy",
    )
    performance = _object(
        root["performance"],
        {"active_fraction", "cumulative_ratio_minimum",
         "active_window_ratio_minimum", "loop_cumulative_minimum",
         "loop_bucket_minimum", "calibration_probe_seconds",
         "reference_start_second", "reference_end_second",
         "qualification_start_second", "calibration_active_windows_minimum",
         "session_probe_seconds", "session_active_windows_minimum",
         "negative_control_deadline_ns", "negative_control_consecutive_windows"},
        "AMD performance policy",
    )
    result = AmdProviderPolicy(
        entry=entry,
        required_cpu_flags=tuple(flags),
        positive_frequency_khz=_positive_integer(
            policy["positive_frequency_khz"], "AMD positive frequency"
        ),
        negative_control_frequency_khz=_positive_integer(
            policy["negative_control_frequency_khz"], "AMD negative frequency"
        ),
        counter_period_ns=_positive_integer(sampling["counter_period_ns"], "counter period"),
        counter_interval_min_ns=_positive_integer(sampling["counter_interval_min_ns"], "counter minimum interval"),
        counter_interval_max_ns=_positive_integer(sampling["counter_interval_max_ns"], "counter maximum interval"),
        temperature_period_ns=_positive_integer(sampling["temperature_period_ns"], "temperature period"),
        temperature_gap_max_ns=_positive_integer(sampling["temperature_gap_max_ns"], "temperature maximum gap"),
        boundary_timestamp_semantics="target_lateness",
        interval_duration_error_max_fraction=Decimal("0"),
        phase_offset_max_ns=1_000_000,
        cooling_ceiling_millicelsius=_positive_integer(thermal["cooling_ceiling_millicelsius"], "cooling ceiling"),
        cooling_consecutive_ns=_positive_integer(thermal["cooling_consecutive_ns"], "cooling interval"),
        cooling_timeout_ns=_positive_integer(thermal["cooling_timeout_ns"], "cooling timeout"),
        measurement_ceiling_millicelsius=_positive_integer(thermal["measurement_ceiling_millicelsius"], "measurement ceiling"),
        tjmax_headroom_millicelsius=_positive_integer(thermal["tjmax_headroom_millicelsius"], "Tjmax headroom"),
        active_fraction=_decimal(performance["active_fraction"], "active fraction"),
        cumulative_ratio_minimum=_decimal(performance["cumulative_ratio_minimum"], "cumulative ratio"),
        active_window_ratio_minimum=_decimal(performance["active_window_ratio_minimum"], "window ratio"),
        loop_cumulative_minimum=_decimal(performance["loop_cumulative_minimum"], "loop cumulative ratio"),
        loop_bucket_minimum=_decimal(performance["loop_bucket_minimum"], "loop bucket ratio"),
        calibration_probe_seconds=_positive_integer(performance["calibration_probe_seconds"], "calibration duration"),
        reference_start_second=_positive_integer(performance["reference_start_second"], "reference start"),
        reference_end_second=_positive_integer(performance["reference_end_second"], "reference end"),
        qualification_start_second=_positive_integer(performance["qualification_start_second"], "qualification start"),
        calibration_active_windows_minimum=_positive_integer(performance["calibration_active_windows_minimum"], "calibration active-window minimum"),
        session_probe_seconds=_positive_integer(performance["session_probe_seconds"], "session probe duration"),
        session_active_windows_minimum=_positive_integer(performance["session_active_windows_minimum"], "session active-window minimum"),
        negative_control_deadline_ns=_positive_integer(performance["negative_control_deadline_ns"], "negative-control deadline"),
        negative_control_consecutive_windows=_positive_integer(performance["negative_control_consecutive_windows"], "negative-control window count"),
    )
    if result.positive_frequency_khz != entry.base_frequency_khz:
        raise HealthError("AMD positive frequency differs from the official base frequency")
    if result.negative_control_frequency_khz * 10 != entry.base_frequency_khz * 9:
        raise HealthError("AMD negative control must be exactly 90% of base frequency")
    if (
        result.required_cpu_flags != ("constant_tsc", "nonstop_tsc", "aperfmperf")
        or result.counter_period_ns != 100_000_000
        or result.counter_interval_min_ns != 50_000_000
        or result.counter_interval_max_ns != 200_000_000
        or result.temperature_period_ns != 20_000_000
        or result.temperature_gap_max_ns != 50_000_000
        or result.cooling_ceiling_millicelsius != 60_000
        or result.cooling_consecutive_ns != 30_000_000_000
        or result.cooling_timeout_ns != 1_200_000_000_000
        or result.active_fraction != Decimal("0.05")
        or result.cumulative_ratio_minimum != Decimal("0.995")
        or result.active_window_ratio_minimum != Decimal("0.98")
        or result.loop_cumulative_minimum != Decimal("0.99")
        or result.loop_bucket_minimum != Decimal("0.98")
        or result.calibration_probe_seconds != 120
        or result.reference_start_second != 10
        or result.reference_end_second != 30
        or result.qualification_start_second != 30
        or result.calibration_active_windows_minimum != 850
        or result.session_probe_seconds != 60
        or result.session_active_windows_minimum != 550
        or result.negative_control_deadline_ns != 2_000_000_000
        or result.negative_control_consecutive_windows != 3
    ):
        raise HealthError("AMD provider thresholds differ from the frozen v1 contract")
    if min(
        result.measurement_ceiling_millicelsius,
        entry.tjmax_millicelsius - result.tjmax_headroom_millicelsius,
    ) != 80_000:
        raise HealthError("AMD Tctl ceiling must freeze to exactly 80C")
    if not (
        result.counter_interval_min_ns <= result.counter_period_ns <= result.counter_interval_max_ns
        and result.temperature_period_ns <= result.temperature_gap_max_ns
        and result.reference_start_second < result.reference_end_second
        == result.qualification_start_second < result.calibration_probe_seconds
    ):
        raise HealthError("AMD provider timing policy is internally inconsistent")
    return result


def read_cpu_model_and_flags(
    proc_cpuinfo: Path = Path("/proc/cpuinfo"),
) -> tuple[str, frozenset[str]]:
    try:
        records = [
            block for block in proc_cpuinfo.read_text(encoding="ascii").split("\n\n")
            if block.strip()
        ]
    except OSError as exc:
        raise HealthError(f"cannot read CPU identity from {proc_cpuinfo}: {exc}") from exc
    identities: list[tuple[str, frozenset[str]]] = []
    for block in records:
        fields = {}
        for line in block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
        if "processor" not in fields:
            continue
        model = fields.get("model name", "")
        flags = frozenset(fields.get("flags", "").split())
        if not model or not flags:
            raise HealthError("CPU identity record lacks model name or flags")
        identities.append((model, flags))
    if not identities or len(set(identities)) != 1:
        raise HealthError("all online CPU records must expose one exact model and flag set")
    return identities[0]


def resolve_temperature_source(
    policy: AmdProviderPolicy,
    hwmon_root: Path = Path("/sys/class/hwmon"),
) -> AmdTemperatureSource:
    matches: list[tuple[Path, Path | None]] = []
    for device in sorted(hwmon_root.glob("hwmon*")):
        try:
            if (device / "name").read_text(encoding="ascii").strip() != "k10temp":
                continue
        except OSError:
            continue
        for label in sorted(device.glob("temp*_label")):
            try:
                if label.read_text(encoding="ascii").strip() != "Tctl":
                    continue
            except OSError:
                continue
            prefix = label.name.removesuffix("_label")
            input_path = device / f"{prefix}_input"
            critical_path = device / f"{prefix}_crit"
            if input_path.is_file():
                matches.append((input_path.resolve(), critical_path.resolve() if critical_path.is_file() else None))
    if len(matches) != 1:
        raise HealthError("AMD provider requires exactly one readable k10temp Tctl input")
    input_path, critical_path = matches[0]
    if critical_path is None:
        return AmdTemperatureSource(
            input_path, policy.entry.tjmax_millicelsius, "exact_cpu_allowlist"
        )
    try:
        sysfs_tjmax = int(critical_path.read_text(encoding="ascii").strip())
    except (OSError, ValueError) as exc:
        raise HealthError(f"cannot read k10temp Tctl critical temperature: {exc}") from exc
    if sysfs_tjmax != policy.entry.tjmax_millicelsius:
        raise HealthError("k10temp critical temperature differs from the exact AMD allowlist")
    return AmdTemperatureSource(input_path, sysfs_tjmax, "k10temp_temp_crit")


def _read_text(path: Path) -> str:
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise HealthError(f"cannot read AMD policy control {path}: {exc}") from exc
    if not value:
        raise HealthError(f"AMD policy control is empty: {path}")
    return value


def _read_khz(path: Path) -> int:
    try:
        value = int(_read_text(path))
    except ValueError as exc:
        raise HealthError(f"AMD frequency control is not an integer: {path}") from exc
    if value <= 0:
        raise HealthError(f"AMD frequency control is not positive: {path}")
    return value


def read_policy_readbacks(
    cpus: Sequence[int],
    cpu_sysfs: Path = Path("/sys/devices/system/cpu"),
) -> tuple[AmdPolicyReadback, ...]:
    requested = set(cpus)
    if not requested or len(requested) != len(tuple(cpus)) or any(cpu < 0 for cpu in requested):
        raise HealthError("AMD policy readback requires distinct nonnegative CPUs")
    readbacks = []
    covered: set[int] = set()
    for policy_path in sorted((cpu_sysfs / "cpufreq").glob("policy[0-9]*")):
        try:
            affected = tuple(sorted(int(cpu) for cpu in _read_text(policy_path / "affected_cpus").split()))
        except ValueError as exc:
            raise HealthError(f"invalid affected CPU list for {policy_path}") from exc
        selected = requested.intersection(affected)
        if not selected:
            continue
        if covered.intersection(selected):
            raise HealthError("a measured CPU appears in multiple cpufreq policies")
        covered.update(selected)
        boost_path = policy_path / "boost"
        if not boost_path.is_file():
            boost_path = cpu_sysfs / "cpufreq/boost"
        boost_text = _read_text(boost_path)
        if boost_text not in {"0", "1"}:
            raise HealthError(f"invalid AMD boost control at {boost_path}")
        readbacks.append(
            AmdPolicyReadback(
                policy_path=policy_path.resolve(),
                affected_cpus=affected,
                scaling_min_khz=_read_khz(policy_path / "scaling_min_freq"),
                scaling_max_khz=_read_khz(policy_path / "scaling_max_freq"),
                governor=_read_text(policy_path / "scaling_governor"),
                epp=_read_text(policy_path / "energy_performance_preference"),
                boost=boost_text == "1",
            )
        )
    if covered != requested:
        raise HealthError(f"AMD cpufreq policies do not cover measured CPUs: {sorted(requested - covered)}")
    return tuple(readbacks)


def resolve_smt_control_cpus(
    cpus: Sequence[int],
    cpu_sysfs: Path = Path("/sys/devices/system/cpu"),
) -> tuple[int, ...]:
    """Expand one measured CPU per core to every sibling policy on those cores."""

    measured = tuple(cpus)
    if (
        not measured
        or len(set(measured)) != len(measured)
        or any(type(cpu) is not int or cpu < 0 for cpu in measured)
    ):
        raise HealthError("AMD SMT policy expansion requires distinct nonnegative CPUs")
    controlled: set[int] = set()
    for cpu in measured:
        path = cpu_sysfs / f"cpu{cpu}/topology/thread_siblings_list"
        siblings: set[int] = set()
        for piece in _read_text(path).split(","):
            bounds = piece.split("-")
            try:
                if len(bounds) == 1:
                    first = last = int(bounds[0])
                elif len(bounds) == 2:
                    first, last = map(int, bounds)
                else:
                    raise ValueError
            except ValueError as exc:
                raise HealthError(f"invalid AMD SMT sibling list at {path}") from exc
            if first < 0 or last < first:
                raise HealthError(f"invalid AMD SMT sibling range at {path}")
            siblings.update(range(first, last + 1))
        if cpu not in siblings or not siblings:
            raise HealthError(f"AMD SMT sibling list omits CPU {cpu}")
        overlap = controlled.intersection(siblings)
        if overlap:
            raise HealthError(
                "AMD measurement CPUs share a physical core: "
                f"CPU {cpu}, siblings {sorted(overlap)}"
            )
        controlled.update(siblings)
    return tuple(sorted(controlled))


def verify_policy_readbacks(
    readbacks: Sequence[AmdPolicyReadback],
    *,
    expected_frequency_khz: int,
) -> None:
    if not readbacks:
        raise HealthError("AMD policy readback set is empty")
    for readback in readbacks:
        if readback.boost:
            raise HealthError(f"AMD boost is enabled for {readback.policy_path}")
        if readback.governor != "performance" or readback.epp != "performance":
            raise HealthError(f"AMD governor/EPP drifted for {readback.policy_path}")
        if (
            readback.scaling_min_khz != expected_frequency_khz
            or readback.scaling_max_khz != expected_frequency_khz
        ):
            raise HealthError(
                f"AMD frequency readback differs for {readback.policy_path}: "
                f"expected={expected_frequency_khz} "
                f"min={readback.scaling_min_khz} max={readback.scaling_max_khz}"
            )


def verify_cpu_prerequisites(
    policy: AmdProviderPolicy,
    *,
    proc_cpuinfo: Path = Path("/proc/cpuinfo"),
) -> frozenset[str]:
    model, flags = read_cpu_model_and_flags(proc_cpuinfo)
    if model != policy.entry.cpuinfo_model_name:
        raise HealthError("live CPU model differs from the loaded AMD allowlist entry")
    missing = set(policy.required_cpu_flags) - flags
    if missing:
        raise HealthError(f"AMD provider CPU flags are missing: {sorted(missing)}")
    return flags


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise HealthError(f"cannot hash AMD probe helper {path}: {exc}") from exc
    return digest.hexdigest()


def _current_cpu() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    value = libc.sched_getcpu()
    if value < 0:
        error = ctypes.get_errno()
        raise HealthError(f"sched_getcpu failed: [{error}] {os.strerror(error)}")
    return int(value)


def _read_temperature(path: Path) -> int:
    try:
        value = int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError) as exc:
        raise HealthError(f"cannot read AMD Tctl from {path}: {exc}") from exc
    if value <= 0:
        raise HealthError("AMD Tctl must be positive")
    return value


def _pread_text(fd: int, path: Path) -> str:
    try:
        value = os.pread(fd, 4096, 0).decode("ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise HealthError(f"cannot read AMD sysfs control {path}: {exc}") from exc
    if not value:
        raise HealthError(f"AMD sysfs control is empty: {path}")
    return value


class _AmdPersistentPolicyReader:
    """Read the frozen cpufreq controls without repeated sysfs traversal."""

    def __init__(
        self,
        readbacks: Sequence[AmdPolicyReadback],
        cpu_sysfs: Path = Path("/sys/devices/system/cpu"),
    ) -> None:
        self._entries: list[
            tuple[AmdPolicyReadback, tuple[tuple[Path, int], ...]]
        ] = []
        try:
            for readback in readbacks:
                boost_path = readback.policy_path / "boost"
                if not boost_path.is_file():
                    boost_path = cpu_sysfs / "cpufreq/boost"
                paths = (
                    readback.policy_path / "scaling_min_freq",
                    readback.policy_path / "scaling_max_freq",
                    readback.policy_path / "scaling_governor",
                    readback.policy_path / "energy_performance_preference",
                    boost_path,
                )
                descriptors = []
                try:
                    for path in paths:
                        descriptors.append(
                            (path, os.open(path, os.O_RDONLY | os.O_CLOEXEC))
                        )
                except BaseException:
                    for _path, fd in descriptors:
                        os.close(fd)
                    raise
                self._entries.append((readback, tuple(descriptors)))
        except BaseException:
            self.close()
            raise

    def read(self) -> tuple[AmdPolicyReadback, ...]:
        result = []
        for template, descriptors in self._entries:
            values = tuple(_pread_text(fd, path) for path, fd in descriptors)
            try:
                minimum = int(values[0])
                maximum = int(values[1])
            except ValueError as exc:
                raise HealthError(
                    f"invalid AMD frequency control at {template.policy_path}"
                ) from exc
            if minimum <= 0 or maximum <= 0 or values[4] not in {"0", "1"}:
                raise HealthError(
                    f"invalid AMD policy readback at {template.policy_path}"
                )
            result.append(
                AmdPolicyReadback(
                    policy_path=template.policy_path,
                    affected_cpus=template.affected_cpus,
                    scaling_min_khz=minimum,
                    scaling_max_khz=maximum,
                    governor=values[2],
                    epp=values[3],
                    boost=values[4] == "1",
                )
            )
        return tuple(result)

    def close(self) -> None:
        entries, self._entries = self._entries, []
        for _template, descriptors in entries:
            for _path, fd in descriptors:
                os.close(fd)


def _read_cgroup_throttling(path: Path) -> tuple[int, int]:
    try:
        rows = [line.split() for line in (path / "cpu.stat").read_text(
            encoding="ascii"
        ).splitlines()]
        if any(len(row) != 2 for row in rows):
            raise ValueError("malformed cpu.stat row")
        values = {row[0]: int(row[1]) for row in rows}
    except (OSError, ValueError) as exc:
        raise HealthError(f"cannot read AMD boundary cgroup telemetry from {path}: {exc}") from exc
    if len(values) != len(rows) or not {"nr_throttled", "throttled_usec"}.issubset(values):
        raise HealthError(f"AMD boundary cpu.stat is malformed at {path}")
    result = (values["nr_throttled"], values["throttled_usec"])
    if any(value < 0 for value in result):
        raise HealthError(f"AMD boundary cgroup counters are negative at {path}")
    return result


def collect_amd_probe(
    *,
    cpus: Sequence[int],
    housekeeping_cpu: int,
    duration_seconds: int,
    helper: Path,
    policy: AmdProviderPolicy,
    temperature_source: AmdTemperatureSource,
    start_lead_ns: int = PROBE_START_LEAD_NS,
) -> AmdProbeEvidence:
    """Run the pinned native loop and retain every raw provider observation."""

    measured = tuple(cpus)
    if (
        not measured
        or len(set(measured)) != len(measured)
        or housekeeping_cpu in measured
        or duration_seconds <= 0
        or duration_seconds > 120
        or start_lead_ns < 100_000_000
    ):
        raise HealthError("AMD probe CPU or timing arguments are invalid")
    helper = helper.resolve(strict=True)
    if not os.access(helper, os.X_OK):
        raise HealthError(f"AMD probe helper is not executable: {helper}")
    helper_sha256 = _sha256_file(helper)
    start_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) + start_lead_ns
    processes = [
        subprocess.Popen(
            [
                str(helper),
                "--cpu", str(cpu),
                "--start-raw-ns", str(start_raw_ns),
                "--duration-seconds", str(duration_seconds),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for cpu in measured
    ]
    previous_affinity = os.sched_getaffinity(0)
    counters: dict[int, list[AmdMonitorCounterSample]] = {cpu: [] for cpu in measured}
    temperatures: list[AmdMonitorTemperatureSample] = []
    counter_reader: AmdPerfCounterReader | None = None
    try:
        os.sched_setaffinity(0, {housekeeping_cpu})
        if os.sched_getaffinity(0) != {housekeeping_cpu}:
            raise HealthError("AMD monitor did not retain exact housekeeping affinity")
        counter_reader = AmdPerfCounterReader(measured)
        while True:
            now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            if now >= start_raw_ns:
                break
            time.sleep(min((start_raw_ns - now) / 1_000_000_000, 0.005))

        def temperature_sample(raw_ns: int) -> None:
            monitor_cpu = _current_cpu()
            temperatures.append(
                AmdMonitorTemperatureSample(
                    raw_ns, _read_temperature(temperature_source.input_path), monitor_cpu
                )
            )

        def counter_sample(raw_ns: int) -> None:
            monitor_cpu = _current_cpu()
            if counter_reader is None:
                raise HealthError("AMD perf counter reader is unavailable")
            for cpu, (aperf, mperf) in counter_reader.read().items():
                counters[cpu].append(
                    AmdMonitorCounterSample(raw_ns, aperf, mperf, monitor_cpu)
                )

        sample_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        temperature_sample(sample_raw_ns)
        counter_sample(sample_raw_ns)
        next_temperature = start_raw_ns + policy.temperature_period_ns
        next_counter = start_raw_ns + policy.counter_period_ns
        end_target = start_raw_ns + duration_seconds * 1_000_000_000
        while next_temperature <= end_target:
            while True:
                now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                if now >= next_temperature:
                    break
                time.sleep(min((next_temperature - now) / 1_000_000_000, 0.002))
            raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            temperature_sample(raw_ns)
            if raw_ns >= next_counter:
                counter_sample(raw_ns)
                while next_counter <= raw_ns:
                    next_counter += policy.counter_period_ns
            next_temperature += policy.temperature_period_ns
        end_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    except BaseException:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        raise
    finally:
        if counter_reader is not None:
            counter_reader.close()
        os.sched_setaffinity(0, previous_affinity)

    loop_buckets: dict[int, tuple[int, ...]] = {}
    for expected_cpu, process in zip(measured, processes, strict=True):
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=2)
            raise HealthError(f"AMD probe helper on CPU {expected_cpu} did not stop") from exc
        if process.returncode != 0:
            detail = stderr.decode("utf-8", "replace").strip()
            raise HealthError(
                f"AMD probe helper on CPU {expected_cpu} failed with "
                f"exit {process.returncode}: {detail}"
            )
        try:
            document = loads_strict(stdout)
        except Exception as exc:
            raise HealthError(f"AMD probe helper on CPU {expected_cpu} emitted invalid JSON") from exc
        if canonical_bytes(document) + b"\n" != stdout:
            raise HealthError("AMD probe helper output is not canonical JSON")
        if (
            not isinstance(document, Mapping)
            or set(document) != {
                "actual_end_raw_ns", "actual_start_raw_ns", "buckets", "cpu",
                "final_state", "schema_version", "start_raw_ns"
            }
            or document["schema_version"] != "quicperf.amd-stability-probe.v1"
            or document["cpu"] != expected_cpu
            or document["start_raw_ns"] != start_raw_ns
            or not isinstance(document["final_state"], str)
            or len(document["final_state"]) != 16
            or any(character not in "0123456789abcdef" for character in document["final_state"])
            or type(document["actual_start_raw_ns"]) is not int
            or not start_raw_ns <= document["actual_start_raw_ns"] <= start_raw_ns + 1_000_000
            or type(document["actual_end_raw_ns"]) is not int
            or document["actual_end_raw_ns"] < start_raw_ns + duration_seconds * 1_000_000_000
            or not isinstance(document["buckets"], list)
            or len(document["buckets"]) != duration_seconds
            or any(type(value) is not int or value <= 0 for value in document["buckets"])
        ):
            raise HealthError(f"AMD probe helper contract failed on CPU {expected_cpu}")
        loop_buckets[expected_cpu] = tuple(document["buckets"])
    return AmdProbeEvidence(
        start_raw_ns=start_raw_ns,
        end_raw_ns=end_raw_ns,
        monitor_cpu=housekeeping_cpu,
        counter_samples={cpu: tuple(values) for cpu, values in counters.items()},
        temperature_samples=tuple(temperatures),
        loop_buckets=loop_buckets,
        helper_sha256=helper_sha256,
    )


def derive_counter_windows(
    evidence: AmdProbeEvidence,
    policy: AmdProviderPolicy,
) -> Mapping[int, tuple[AmdCounterWindow, ...]]:
    result: dict[int, tuple[AmdCounterWindow, ...]] = {}
    base_hz = policy.entry.base_frequency_khz * 1_000
    for cpu, samples in evidence.counter_samples.items():
        windows = []
        for before, after in zip(samples, samples[1:]):
            delta_ns = after.raw_ns - before.raw_ns
            aperf_delta = after.aperf - before.aperf
            mperf_delta = after.mperf - before.mperf
            valid = True
            reason = ""
            if before.monitor_cpu != evidence.monitor_cpu or after.monitor_cpu != evidence.monitor_cpu:
                valid, reason = False, "monitor_cpu_migration"
            elif not policy.counter_interval_min_ns <= delta_ns <= policy.counter_interval_max_ns:
                valid, reason = False, "counter_monitor_dropout"
            elif aperf_delta < 0 or mperf_delta < 0:
                valid, reason = False, "counter_nonmonotonic"
            active = (
                valid
                and mperf_delta * 20 * 1_000_000_000 >= base_hz * delta_ns
            )
            ratio = aperf_delta / mperf_delta if valid and mperf_delta > 0 else 0.0
            windows.append(
                AmdCounterWindow(
                    cpu, before.raw_ns + delta_ns // 2, delta_ns, aperf_delta, mperf_delta,
                    ratio, active, valid, reason,
                )
            )
        result[cpu] = tuple(windows)
    return result


def build_calibration_reference(
    evidence: AmdProbeEvidence,
    policy: AmdProviderPolicy,
) -> AmdReference:
    windows = derive_counter_windows(evidence, policy)
    ratio_reference: dict[int, float] = {}
    loop_reference: dict[int, float] = {}
    start = evidence.start_raw_ns + policy.reference_start_second * 1_000_000_000
    end = evidence.start_raw_ns + policy.reference_end_second * 1_000_000_000
    for cpu in sorted(evidence.counter_samples):
        ratios = [
            window.ratio for window in windows[cpu]
            if window.valid and window.active and start <= window.raw_ns < end
        ]
        buckets = evidence.loop_buckets[cpu][
            policy.reference_start_second:policy.reference_end_second
        ]
        if len(ratios) < 190:
            raise HealthError(f"CPU {cpu} lacks reference active windows")
        if len(buckets) != 20 or any(value <= 0 for value in buckets):
            raise HealthError(f"CPU {cpu} lacks all 20 complete reference loop buckets")
        ratio_reference[cpu] = float(statistics.median(ratios))
        loop_reference[cpu] = float(statistics.median(buckets))
        if not math.isfinite(ratio_reference[cpu]) or ratio_reference[cpu] <= 0:
            raise HealthError(f"CPU {cpu} ratio reference is invalid")
        if not math.isfinite(loop_reference[cpu]) or loop_reference[cpu] <= 0:
            raise HealthError(f"CPU {cpu} loop reference is invalid")
    return AmdReference(ratio_reference, loop_reference)


def evaluate_positive_probe(
    evidence: AmdProbeEvidence,
    policy: AmdProviderPolicy,
    reference: AmdReference,
    *,
    evaluation_start_second: int,
    active_windows_minimum: int,
) -> AmdProbeEvaluation:
    reasons: list[str] = []
    cpus = set(evidence.counter_samples)
    if cpus != set(reference.ratio) or cpus != set(reference.loop_iterations):
        raise HealthError("AMD probe and reference CPU sets differ")
    windows = derive_counter_windows(evidence, policy)
    start = evidence.start_raw_ns + evaluation_start_second * 1_000_000_000
    end = evidence.start_raw_ns + len(next(iter(evidence.loop_buckets.values()))) * 1_000_000_000
    active_counts: dict[int, int] = {}
    cumulative: dict[int, float] = {}
    minimum_window: dict[int, float] = {}
    loop_cumulative: dict[int, float] = {}
    minimum_loop: dict[int, float] = {}
    for cpu in sorted(cpus):
        selected = [window for window in windows[cpu] if start <= window.raw_ns <= end]
        invalid = [window for window in selected if not window.valid]
        if invalid:
            reasons.extend(f"cpu{cpu}_{window.reason}" for window in invalid)
        active = [window for window in selected if window.valid and window.active]
        active_counts[cpu] = len(active)
        if len(active) < active_windows_minimum:
            reasons.append(f"cpu{cpu}_active_window_count_below_minimum")
        if active:
            ratio_sum_aperf = sum(window.aperf_delta for window in active)
            ratio_sum_mperf = sum(window.mperf_delta for window in active)
            cumulative[cpu] = (ratio_sum_aperf / ratio_sum_mperf) / reference.ratio[cpu]
            minimum_window[cpu] = min(
                window.ratio / reference.ratio[cpu] for window in active
            )
        else:
            cumulative[cpu] = minimum_window[cpu] = 0.0
        if cumulative[cpu] < float(policy.cumulative_ratio_minimum):
            reasons.append(f"cpu{cpu}_cumulative_ratio_below_99_5_percent")
        if minimum_window[cpu] < float(policy.active_window_ratio_minimum):
            reasons.append(f"cpu{cpu}_active_window_below_98_percent")
        buckets = evidence.loop_buckets[cpu][evaluation_start_second:]
        if not buckets:
            reasons.append(f"cpu{cpu}_loop_bucket_missing")
            loop_cumulative[cpu] = minimum_loop[cpu] = 0.0
        else:
            loop_cumulative[cpu] = (
                sum(buckets) / (reference.loop_iterations[cpu] * len(buckets))
            )
            minimum_loop[cpu] = min(
                value / reference.loop_iterations[cpu] for value in buckets
            )
            if loop_cumulative[cpu] < float(policy.loop_cumulative_minimum):
                reasons.append(f"cpu{cpu}_loop_cumulative_below_99_percent")
            if minimum_loop[cpu] < float(policy.loop_bucket_minimum):
                reasons.append(f"cpu{cpu}_loop_bucket_below_98_percent")
    temperatures = tuple(
        sample for sample in evidence.temperature_samples
        if start <= sample.raw_ns <= end
    )
    if not temperatures:
        reasons.append("tctl_sample_missing")
        maximum_temperature = 0
    else:
        maximum_temperature = max(sample.tctl_millicelsius for sample in temperatures)
        if any(sample.monitor_cpu != evidence.monitor_cpu for sample in temperatures):
            reasons.append("temperature_monitor_cpu_migration")
        if any(
            current.raw_ns <= previous.raw_ns
            or current.raw_ns - previous.raw_ns > policy.temperature_gap_max_ns
            for previous, current in zip(temperatures, temperatures[1:])
        ):
            reasons.append("tctl_monitor_dropout")
        thermal_ceiling = min(
            policy.measurement_ceiling_millicelsius,
            policy.entry.tjmax_millicelsius - policy.tjmax_headroom_millicelsius,
        )
        if any(sample.tctl_millicelsius >= thermal_ceiling for sample in temperatures):
            reasons.append("tctl_thermal_headroom_breach")
    reasons = list(dict.fromkeys(reasons))
    return AmdProbeEvaluation(
        passed=not reasons,
        reasons=tuple(reasons),
        active_windows=active_counts,
        cumulative_fraction_of_reference=cumulative,
        minimum_window_fraction_of_reference=minimum_window,
        loop_cumulative_fraction_of_reference=loop_cumulative,
        minimum_loop_bucket_fraction_of_reference=minimum_loop,
        maximum_tctl_millicelsius=maximum_temperature,
    )


def evaluate_negative_control(
    evidence: AmdProbeEvidence,
    policy: AmdProviderPolicy,
    reference: AmdReference,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    windows = derive_counter_windows(evidence, policy)
    deadline = evidence.start_raw_ns + policy.negative_control_deadline_ns
    for cpu in sorted(evidence.counter_samples):
        run = 0
        detected = False
        for window in windows[cpu]:
            if window.raw_ns > deadline:
                break
            if (
                window.valid
                and window.active
                and window.ratio < float(policy.active_window_ratio_minimum) * reference.ratio[cpu]
            ):
                run += 1
                detected = detected or run >= policy.negative_control_consecutive_windows
            else:
                run = 0
        if not detected:
            reasons.append(f"cpu{cpu}_negative_ratio_control_not_detected")
        buckets = evidence.loop_buckets[cpu]
        if (
            not buckets
            or buckets[0] >= float(policy.loop_bucket_minimum) * reference.loop_iterations[cpu]
        ):
            reasons.append(f"cpu{cpu}_negative_loop_control_not_detected")
    return not reasons, tuple(reasons)


def probe_evidence_document(evidence: AmdProbeEvidence) -> dict[str, Any]:
    return {
        "schema_version": "quicperf.amd-probe-evidence.v2",
        "provider": PROVIDER_VERSION,
        "counter_source": AMD_PERF_COUNTER_SOURCE,
        "start_raw_ns": evidence.start_raw_ns,
        "end_raw_ns": evidence.end_raw_ns,
        "monitor_cpu": evidence.monitor_cpu,
        "helper_sha256": evidence.helper_sha256,
        "counter_samples": {
            str(cpu): [
                {
                    "raw_ns": sample.raw_ns,
                    "aperf": sample.aperf,
                    "mperf": sample.mperf,
                    "monitor_cpu": sample.monitor_cpu,
                }
                for sample in samples
            ]
            for cpu, samples in sorted(evidence.counter_samples.items())
        },
        "temperature_samples": [
            {
                "raw_ns": sample.raw_ns,
                "tctl_millicelsius": sample.tctl_millicelsius,
                "monitor_cpu": sample.monitor_cpu,
            }
            for sample in evidence.temperature_samples
        ],
        "loop_buckets": {
            str(cpu): list(buckets)
            for cpu, buckets in sorted(evidence.loop_buckets.items())
        },
    }


def _write_exact(path: Path, value: str) -> None:
    try:
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise HealthError(f"cannot update AMD policy control {path}: {exc}") from exc
    deadline = time.monotonic() + 1.0
    while True:
        try:
            observed = path.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise HealthError(f"cannot read AMD policy control {path}: {exc}") from exc
        if observed == value:
            return
        if time.monotonic() >= deadline:
            raise HealthError(
                f"AMD policy write did not stick at {path}: "
                f"expected={value} observed={observed}"
            )
        time.sleep(0.01)


def set_policy_frequency(
    cpus: Sequence[int],
    *,
    target_khz: int,
    lowering: bool,
    cpu_sysfs: Path = Path("/sys/devices/system/cpu"),
) -> tuple[AmdPolicyReadback, ...]:
    """Apply the frozen safe min/max write order and verify every readback."""

    before = read_policy_readbacks(cpus, cpu_sysfs)
    names = (
        ("scaling_min_freq", "scaling_max_freq")
        if lowering
        else ("scaling_max_freq", "scaling_min_freq")
    )
    for readback in before:
        for name in names:
            _write_exact(readback.policy_path / name, str(target_khz))
    after = read_policy_readbacks(cpus, cpu_sysfs)
    verify_policy_readbacks(after, expected_frequency_khz=target_khz)
    return after


def wait_for_cool_temperature(
    *,
    housekeeping_cpu: int,
    temperature_source: AmdTemperatureSource,
    policy: AmdProviderPolicy,
) -> tuple[AmdMonitorTemperatureSample, ...]:
    """Require 30 consecutive seconds at or below 60C within 20 minutes."""

    previous_affinity = os.sched_getaffinity(0)
    samples: list[AmdMonitorTemperatureSample] = []
    started = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    cool_started: int | None = None
    next_sample = started
    try:
        os.sched_setaffinity(0, {housekeeping_cpu})
        while True:
            while True:
                now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                if now >= next_sample:
                    break
                time.sleep(min((next_sample - now) / 1_000_000_000, 0.002))
            raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            monitor_cpu = _current_cpu()
            if monitor_cpu != housekeeping_cpu:
                raise HealthError("AMD cooling monitor migrated off its housekeeping CPU")
            if samples and raw_ns - samples[-1].raw_ns > policy.temperature_gap_max_ns:
                raise HealthError("AMD cooling Tctl monitor dropped an interval")
            temperature = _read_temperature(temperature_source.input_path)
            samples.append(AmdMonitorTemperatureSample(raw_ns, temperature, monitor_cpu))
            if temperature <= policy.cooling_ceiling_millicelsius:
                cool_started = raw_ns if cool_started is None else cool_started
                if raw_ns - cool_started >= policy.cooling_consecutive_ns:
                    return tuple(samples)
            else:
                cool_started = None
            if raw_ns - started >= policy.cooling_timeout_ns:
                raise HealthError("AMD provider could not cool within 20 minutes")
            next_sample += policy.temperature_period_ns
    finally:
        os.sched_setaffinity(0, previous_affinity)


def _evaluation_document(evaluation: AmdProbeEvaluation) -> dict[str, Any]:
    return {
        "passed": evaluation.passed,
        "reasons": list(evaluation.reasons),
        "active_windows": {str(cpu): value for cpu, value in sorted(evaluation.active_windows.items())},
        "cumulative_fraction_of_reference": {
            str(cpu): format(value, ".17g")
            for cpu, value in sorted(evaluation.cumulative_fraction_of_reference.items())
        },
        "minimum_window_fraction_of_reference": {
            str(cpu): format(value, ".17g")
            for cpu, value in sorted(evaluation.minimum_window_fraction_of_reference.items())
        },
        "loop_cumulative_fraction_of_reference": {
            str(cpu): format(value, ".17g")
            for cpu, value in sorted(evaluation.loop_cumulative_fraction_of_reference.items())
        },
        "minimum_loop_bucket_fraction_of_reference": {
            str(cpu): format(value, ".17g")
            for cpu, value in sorted(evaluation.minimum_loop_bucket_fraction_of_reference.items())
        },
        "maximum_tctl_millicelsius": evaluation.maximum_tctl_millicelsius,
    }


def _readback_document(readback: AmdPolicyReadback) -> dict[str, Any]:
    return {
        "policy_path": str(readback.policy_path),
        "affected_cpus": list(readback.affected_cpus),
        "scaling_min_khz": readback.scaling_min_khz,
        "scaling_max_khz": readback.scaling_max_khz,
        "governor": readback.governor,
        "epp": readback.epp,
        "boost": readback.boost,
    }


def run_amd_calibration(
    *,
    cpus: Sequence[int],
    housekeeping_cpu: int,
    helper: Path,
    policy_path: Path = DEFAULT_POLICY_PATH,
    cpu_sysfs: Path = Path("/sys/devices/system/cpu"),
    proc_cpuinfo: Path = Path("/proc/cpuinfo"),
    hwmon_root: Path = Path("/sys/class/hwmon"),
) -> tuple[AmdReference, dict[str, Any]]:
    """Execute the frozen cool/positive/negative/restore/cool/positive sequence."""

    model, _flags = read_cpu_model_and_flags(proc_cpuinfo)
    policy = load_amd_provider_policy(cpu_model=model, path=policy_path)
    verify_cpu_prerequisites(policy, proc_cpuinfo=proc_cpuinfo)
    temperature_source = resolve_temperature_source(policy, hwmon_root)
    control_cpus = resolve_smt_control_cpus(cpus, cpu_sysfs)
    before = read_policy_readbacks(control_cpus, cpu_sysfs)
    verify_policy_readbacks(before, expected_frequency_khz=policy.positive_frequency_khz)
    cooling_before = wait_for_cool_temperature(
        housekeeping_cpu=housekeeping_cpu,
        temperature_source=temperature_source,
        policy=policy,
    )
    first = collect_amd_probe(
        cpus=cpus,
        housekeeping_cpu=housekeeping_cpu,
        duration_seconds=policy.calibration_probe_seconds,
        helper=helper,
        policy=policy,
        temperature_source=temperature_source,
    )
    reference = build_calibration_reference(first, policy)
    first_evaluation = evaluate_positive_probe(
        first,
        policy,
        reference,
        evaluation_start_second=policy.qualification_start_second,
        active_windows_minimum=policy.calibration_active_windows_minimum,
    )
    negative: AmdProbeEvidence | None = None
    negative_passed = False
    negative_reasons: tuple[str, ...] = ("negative_control_not_run",)
    try:
        set_policy_frequency(
            control_cpus,
            target_khz=policy.negative_control_frequency_khz,
            lowering=True,
            cpu_sysfs=cpu_sysfs,
        )
        negative = collect_amd_probe(
            cpus=cpus,
            housekeeping_cpu=housekeeping_cpu,
            duration_seconds=2,
            helper=helper,
            policy=policy,
            temperature_source=temperature_source,
            start_lead_ns=100_000_000,
        )
        negative_passed, negative_reasons = evaluate_negative_control(
            negative, policy, reference
        )
    finally:
        set_policy_frequency(
            control_cpus,
            target_khz=policy.positive_frequency_khz,
            lowering=False,
            cpu_sysfs=cpu_sysfs,
        )
    restored = read_policy_readbacks(control_cpus, cpu_sysfs)
    verify_policy_readbacks(restored, expected_frequency_khz=policy.positive_frequency_khz)
    cooling_after = wait_for_cool_temperature(
        housekeeping_cpu=housekeeping_cpu,
        temperature_source=temperature_source,
        policy=policy,
    )
    second = collect_amd_probe(
        cpus=cpus,
        housekeeping_cpu=housekeeping_cpu,
        duration_seconds=policy.calibration_probe_seconds,
        helper=helper,
        policy=policy,
        temperature_source=temperature_source,
    )
    second_evaluation = evaluate_positive_probe(
        second,
        policy,
        reference,
        evaluation_start_second=policy.qualification_start_second,
        active_windows_minimum=policy.calibration_active_windows_minimum,
    )
    after = read_policy_readbacks(control_cpus, cpu_sysfs)
    verify_policy_readbacks(after, expected_frequency_khz=policy.positive_frequency_khz)
    passed = first_evaluation.passed and negative_passed and second_evaluation.passed
    reasons = list(first_evaluation.reasons)
    reasons.extend(negative_reasons)
    reasons.extend(second_evaluation.reasons)
    document = {
        "schema_version": "quicperf.amd-calibration.v1",
        "provider": PROVIDER_VERSION,
        "passed": passed,
        "reasons": list(dict.fromkeys(reasons)),
        "cpu_model": model,
        "measurement_cpus": list(cpus),
        "control_cpus": list(control_cpus),
        "housekeeping_cpu": housekeeping_cpu,
        "temperature_source": {
            "input_path": str(temperature_source.input_path),
            "tjmax_millicelsius": temperature_source.tjmax_millicelsius,
            "tjmax_source": temperature_source.tjmax_source,
        },
        "official_source": {
            "url": policy.entry.official_source_url,
            "retrieved_utc_date": policy.entry.official_source_retrieved_utc_date,
            "captured_content_sha256": policy.entry.official_source_sha256,
        },
        "policy_sha256": _sha256_file(policy_path),
        "helper_sha256": first.helper_sha256,
        "policy_readback_before": [_readback_document(readback) for readback in before],
        "policy_readback_after": [_readback_document(readback) for readback in after],
        "cooling_before": [sample.__dict__ for sample in cooling_before],
        "first_positive": {
            "raw": probe_evidence_document(first),
            "evaluation": _evaluation_document(first_evaluation),
        },
        "reference": {
            "ratio": {str(cpu): format(value, ".17g") for cpu, value in sorted(reference.ratio.items())},
            "loop_iterations": {str(cpu): format(value, ".17g") for cpu, value in sorted(reference.loop_iterations.items())},
        },
        "negative_control": {
            "raw": probe_evidence_document(negative) if negative is not None else None,
            "passed": negative_passed,
            "reasons": list(negative_reasons),
        },
        "cooling_after": [sample.__dict__ for sample in cooling_after],
        "second_positive": {
            "raw": probe_evidence_document(second),
            "evaluation": _evaluation_document(second_evaluation),
        },
    }
    return reference, document


def run_amd_session_probe(
    *,
    cpus: Sequence[int],
    housekeeping_cpu: int,
    helper: Path,
    policy: AmdProviderPolicy,
    reference: AmdReference,
    temperature_source: AmdTemperatureSource,
    cpu_sysfs: Path = Path("/sys/devices/system/cpu"),
) -> tuple[AmdProbeEvaluation, dict[str, Any]]:
    control_cpus = resolve_smt_control_cpus(cpus, cpu_sysfs)
    before = read_policy_readbacks(control_cpus, cpu_sysfs)
    verify_policy_readbacks(before, expected_frequency_khz=policy.positive_frequency_khz)
    evidence = collect_amd_probe(
        cpus=cpus,
        housekeeping_cpu=housekeeping_cpu,
        duration_seconds=policy.session_probe_seconds,
        helper=helper,
        policy=policy,
        temperature_source=temperature_source,
    )
    evaluation = evaluate_positive_probe(
        evidence,
        policy,
        reference,
        evaluation_start_second=0,
        active_windows_minimum=policy.session_active_windows_minimum,
    )
    after = read_policy_readbacks(control_cpus, cpu_sysfs)
    verify_policy_readbacks(after, expected_frequency_khz=policy.positive_frequency_khz)
    return evaluation, {
        "schema_version": "quicperf.amd-session-probe.v1",
        "provider": PROVIDER_VERSION,
        "control_cpus": list(control_cpus),
        "policy_readback_before": [_readback_document(item) for item in before],
        "raw": probe_evidence_document(evidence),
        "evaluation": _evaluation_document(evaluation),
        "policy_readback_after": [_readback_document(item) for item in after],
    }


class _AmdContinuousMonitorWorker:
    """Housekeeping-pinned full-session sampler with exact timed boundaries."""

    def __init__(
        self,
        *,
        cpus: Sequence[int],
        housekeeping_cpu: int,
        spin_helper: Path,
        policy: AmdProviderPolicy,
        reference: AmdReference,
        temperature_source: AmdTemperatureSource,
    ) -> None:
        self.cpus = tuple(cpus)
        if (
            not self.cpus
            or len(set(self.cpus)) != len(self.cpus)
            or housekeeping_cpu in self.cpus
            or set(self.cpus) != set(reference.ratio)
        ):
            raise HealthError("AMD continuous-monitor CPU ownership is invalid")
        self.housekeeping_cpu = housekeeping_cpu
        self.spin_helper = spin_helper
        self.policy = policy
        self.reference = reference
        self.temperature_source = temperature_source
        self._temperature_samples: list[AmdMonitorTemperatureSample] = []
        self._watchdog_temperature_samples: list[AmdMonitorTemperatureSample] = []
        self._watchdog_counter_samples: dict[
            int, list[AmdMonitorCounterSample]
        ] = {cpu: [] for cpu in self.cpus}
        self._temperature_lock = threading.Lock()
        self._boundaries: dict[str, AmdBoundarySnapshot] = {}
        self._evaluations: dict[str, AmdMicroblockEvaluation] = {}
        self._boundary_events: dict[str, threading.Event] = {}
        self._boundary_cgroups: dict[str, tuple[Path, ...]] = {}
        self._pending: list[tuple[int, str]] = []
        self._policy_samples: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._started = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._temperature_process: subprocess.Popen[bytes] | None = None
        self._temperature_socket: socket.socket | None = None
        self._temperature_watchdog_expected_cpu: int | None = None
        self._temperature_watchdog_sequence = -1
        self._temperature_watchdog_started_raw_ns: int | None = None
        self._temperature_watchdog_stopped_raw_ns: int | None = None
        self._temperature_watchdog_pid: int | None = None
        self._temperature_watchdog_cpu_attested: int | None = None
        self._temperature_watchdog_stopped = False
        self._error: BaseException | None = None
        self._start_raw_ns = 0
        self._end_raw_ns = 0
        self._control_cpus: tuple[int, ...] | None = None
        self._counter_reader: AmdPerfCounterReader | None = None
        self._policy_reader: _AmdPersistentPolicyReader | None = None
        self._temperature_fd: int | None = None
        self._previous_switch_interval: float | None = None
        self._spin_library: Any = None
        self._spin_until: Any = None

    def _restore_switch_interval(self) -> None:
        previous = self._previous_switch_interval
        if previous is None:
            return
        self._previous_switch_interval = None
        sys.setswitchinterval(previous)

    def _raise_monitor_error(self) -> None:
        self._drain_temperature_watchdog()
        if self._error is None:
            return
        if isinstance(self._error, AmdMonitorTransientError):
            raise self._error
        raise HealthError(f"AMD continuous monitor failed: {self._error}") from self._error

    def _record_counters(
        self,
        raw_ns: int,
        monitor_cpu: int,
        values: Mapping[int, tuple[int, int]],
    ) -> None:
        samples = self._watchdog_counter_samples
        for cpu, (aperf, mperf) in values.items():
            previous = samples[cpu][-1:]
            if previous and not self.policy.counter_interval_min_ns <= (
                raw_ns - previous[0].raw_ns
            ) <= self.policy.counter_interval_max_ns:
                raise AmdMonitorTransientError(
                    f"CPU {cpu} APERF/MPERF sampling cadence dropped out: "
                    f"gap_ns={raw_ns - previous[0].raw_ns} "
                    f"previous_raw_ns={previous[0].raw_ns} "
                    f"observed_raw_ns={raw_ns}"
                )
            samples[cpu].append(
                AmdMonitorCounterSample(raw_ns, aperf, mperf, monitor_cpu)
            )

    def _sample_temperature(self, monitor_cpu: int) -> tuple[int, int]:
        self._drain_temperature_watchdog()
        if self._temperature_fd is None:
            raise HealthError("AMD continuous Tctl descriptor is unavailable")
        try:
            value = int(
                _pread_text(
                    self._temperature_fd, self.temperature_source.input_path
                )
            )
        except ValueError as exc:
            raise HealthError("AMD Tctl is not an integer") from exc
        if value <= 0:
            raise HealthError("AMD Tctl must be positive")
        with self._temperature_lock:
            raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            self._temperature_samples.append(
                AmdMonitorTemperatureSample(raw_ns, value, monitor_cpu)
            )
        return value, raw_ns

    def _temperature_watchdog_cpu(self) -> int:
        siblings = set(resolve_smt_control_cpus((self.housekeeping_cpu,)))
        candidates = siblings - {self.housekeeping_cpu}
        if len(candidates) != 1 or candidates & set(self.cpus):
            raise HealthError(
                "AMD temperature watchdog lacks one reserved SMT sibling"
            )
        return candidates.pop()

    def _drain_temperature_watchdog(self) -> None:
        channel = self._temperature_socket
        process = self._temperature_process
        if channel is None or process is None:
            return
        with self._temperature_lock:
            while True:
                try:
                    message = channel.recv(4096, socket.MSG_DONTWAIT)
                except BlockingIOError:
                    break
                except OSError as exc:
                    if self._error is None:
                        self._error = HealthError(
                            f"AMD temperature watchdog channel failed: {exc}"
                        )
                    break
                if not message:
                    if self._error is None and not self._temperature_watchdog_stopped:
                        self._error = HealthError(
                            "AMD temperature watchdog channel closed"
                        )
                    break
                if message[:1] == TEMPERATURE_WATCHDOG_ERROR:
                    if self._error is None:
                        self._error = HealthError(
                            "AMD temperature watchdog failed: "
                            + message[1:].decode(errors="replace")
                    )
                    continue
                if message[:1] == TEMPERATURE_WATCHDOG_COUNTER_SAMPLE:
                    if len(message) != TEMPERATURE_WATCHDOG_COUNTER_MESSAGE.size:
                        if self._error is None:
                            self._error = HealthError(
                                "AMD counter watchdog message is malformed"
                            )
                        continue
                    kind, sequence, raw_ns, aperf, mperf, cpu = (
                        TEMPERATURE_WATCHDOG_COUNTER_MESSAGE.unpack(message)
                    )
                    if sequence != self._temperature_watchdog_sequence + 1:
                        if self._error is None:
                            self._error = HealthError(
                                "AMD temperature watchdog sequence is invalid"
                            )
                        continue
                    self._temperature_watchdog_sequence = sequence
                    samples = self._watchdog_counter_samples.get(cpu)
                    if (
                        kind != TEMPERATURE_WATCHDOG_COUNTER_SAMPLE
                        or samples is None
                        or raw_ns <= 0
                        or aperf < 0
                        or mperf < 0
                        or (samples and raw_ns <= samples[-1].raw_ns)
                        or raw_ns
                        > time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                    ):
                        if self._error is None:
                            self._error = HealthError(
                                "AMD counter watchdog sample is invalid"
                            )
                        continue
                    try:
                        self._record_counters(
                            raw_ns,
                            self._temperature_watchdog_expected_cpu
                            if self._temperature_watchdog_expected_cpu is not None
                            else -1,
                            {cpu: (aperf, mperf)},
                        )
                    except BaseException as exc:
                        if self._error is None:
                            self._error = exc
                    continue
                if len(message) != TEMPERATURE_WATCHDOG_MESSAGE.size:
                    if self._error is None:
                        self._error = HealthError(
                            "AMD temperature watchdog message is malformed"
                        )
                    continue
                kind, sequence, raw_ns, value, cpu = (
                    TEMPERATURE_WATCHDOG_MESSAGE.unpack(message)
                )
                if sequence != self._temperature_watchdog_sequence + 1:
                    if self._error is None:
                        self._error = HealthError(
                            "AMD temperature watchdog sequence is invalid"
                        )
                    continue
                self._temperature_watchdog_sequence = sequence
                if kind == TEMPERATURE_WATCHDOG_SAMPLE:
                    if (
                        raw_ns <= 0
                        or value <= 0
                        or cpu != self._temperature_watchdog_expected_cpu
                        or (
                            self._watchdog_temperature_samples
                            and raw_ns
                            <= self._watchdog_temperature_samples[-1].raw_ns
                        )
                        or raw_ns
                        > time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                    ):
                        if self._error is None:
                            self._error = HealthError(
                                "AMD temperature watchdog sample is invalid"
                            )
                        continue
                    self._watchdog_temperature_samples.append(
                        AmdMonitorTemperatureSample(raw_ns, value, cpu)
                    )
                elif kind == TEMPERATURE_WATCHDOG_STOPPED:
                    if (
                        raw_ns <= 0
                        or cpu != self._temperature_watchdog_expected_cpu
                        or (
                            self._watchdog_temperature_samples
                            and raw_ns
                            < self._watchdog_temperature_samples[-1].raw_ns
                        )
                        or raw_ns
                        > time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                    ):
                        if self._error is None:
                            self._error = HealthError(
                                "AMD temperature watchdog stop is invalid"
                            )
                        continue
                    self._temperature_watchdog_stopped_raw_ns = raw_ns
                    self._temperature_watchdog_stopped = True
                else:
                    if self._error is None:
                        self._error = HealthError(
                            "AMD temperature watchdog message type is invalid"
                        )
            if (
                process.poll() is not None
                and not self._temperature_watchdog_stopped
                and self._error is None
            ):
                self._error = HealthError(
                    "AMD temperature watchdog exited unexpectedly"
                )

    def _start_temperature_watchdog(self, cpu: int) -> None:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        helper = Path(__file__).with_name("amd_temperature_watchdog.py")
        try:
            command = [
                sys.executable,
                "-m",
                "quicperf_harness.amd_temperature_watchdog",
                "--channel-fd",
                str(child.fileno()),
                "--cpu",
                str(cpu),
                "--input-path",
                str(self.temperature_source.input_path),
                "--period-ns",
                str(self.policy.temperature_period_ns),
                "--counter-period-ns",
                str(self.policy.counter_period_ns),
                "--priority",
                str(CONTINUOUS_MONITOR_SCHED_FIFO_PRIORITY),
                "--parent-pid",
                str(os.getpid()),
            ]
            for counter_cpu in self.cpus:
                command.extend(("--counter-cpu", str(counter_cpu)))
            process = subprocess.Popen(
                command,
                cwd=helper.resolve().parents[1],
                close_fds=True,
                pass_fds=(child.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except BaseException:
            parent.close()
            child.close()
            raise
        child.close()
        self._temperature_process = process
        self._temperature_socket = parent
        self._temperature_watchdog_expected_cpu = cpu
        self._temperature_watchdog_pid = process.pid
        self._temperature_watchdog_cpu_attested = cpu
        readable, _, _ = select.select((parent,), (), (), 2)
        if not readable:
            raise HealthError("AMD temperature watchdog did not start")
        message = parent.recv(4096)
        if len(message) != TEMPERATURE_WATCHDOG_MESSAGE.size:
            detail = (
                message[1:].decode(errors="replace")
                if message[:1] == TEMPERATURE_WATCHDOG_ERROR
                else "malformed startup message"
            )
            raise HealthError(f"AMD temperature watchdog failed: {detail}")
        kind, sequence, raw_ns, value, observed_cpu = (
            TEMPERATURE_WATCHDOG_MESSAGE.unpack(message)
        )
        if (
            kind != TEMPERATURE_WATCHDOG_STARTED
            or sequence != 0
            or raw_ns <= 0
            or value <= 0
            or observed_cpu != cpu
            or raw_ns > time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        ):
            raise HealthError("AMD temperature watchdog startup is invalid")
        self._temperature_watchdog_sequence = sequence
        self._temperature_watchdog_started_raw_ns = raw_ns
        self._watchdog_temperature_samples.append(
            AmdMonitorTemperatureSample(raw_ns, value, observed_cpu)
        )

    def _stop_temperature_watchdog(self) -> None:
        channel = self._temperature_socket
        process = self._temperature_process
        if channel is None or process is None:
            return
        try:
            try:
                channel.send(TEMPERATURE_WATCHDOG_STOP)
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                if self._error is None:
                    self._error = HealthError(
                        "AMD temperature watchdog did not stop"
                    )
            self._drain_temperature_watchdog()
            if process.returncode != 0 and self._error is None:
                self._error = HealthError(
                    "AMD temperature watchdog exited unsuccessfully"
                )
            if not self._temperature_watchdog_stopped and self._error is None:
                self._error = HealthError(
                    "AMD temperature watchdog omitted its stop attestation"
                )
        finally:
            channel.close()
            self._temperature_socket = None
            self._temperature_process = None
            self._temperature_watchdog_expected_cpu = None

    def _run(self) -> None:
        try:
            os.sched_setaffinity(0, {self.housekeeping_cpu})
            if os.sched_getaffinity(0) != {self.housekeeping_cpu}:
                raise HealthError("AMD continuous monitor affinity did not stick")
            try:
                os.sched_setscheduler(
                    0,
                    os.SCHED_FIFO,
                    os.sched_param(CONTINUOUS_MONITOR_SCHED_FIFO_PRIORITY),
                )
            except OSError as exc:
                raise HealthError(
                    f"AMD continuous monitor real-time scheduling failed: {exc}"
                ) from exc
            if (
                os.sched_getscheduler(0) != os.SCHED_FIFO
                or os.sched_getparam(0).sched_priority
                != CONTINUOUS_MONITOR_SCHED_FIFO_PRIORITY
            ):
                raise HealthError(
                    "AMD continuous monitor real-time scheduling did not stick"
                )
            try:
                self._spin_library = ctypes.PyDLL(str(self.spin_helper))
                self._spin_until = (
                    self._spin_library.quicperf_monitor_spin_until_raw_ns
                )
                self._spin_until.argtypes = [ctypes.c_int64]
                self._spin_until.restype = ctypes.c_int64
            except (OSError, AttributeError) as exc:
                raise HealthError(
                    f"AMD continuous monitor spin helper is unavailable: {exc}"
                ) from exc
            self._counter_reader = AmdPerfCounterReader(self.cpus)
            self._temperature_fd = os.open(
                self.temperature_source.input_path,
                os.O_RDONLY | os.O_CLOEXEC,
            )
            temperature_cpu = self._temperature_watchdog_cpu()
            self._start_temperature_watchdog(temperature_cpu)
            self._raise_monitor_error()
            now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            self._start_raw_ns = now
            self._control_cpus = resolve_smt_control_cpus(self.cpus)
            monitor_cpu = _current_cpu()
            _temperature, temperature_now = self._sample_temperature(monitor_cpu)
            self._counter_reader.read()
            initial_policy = read_policy_readbacks(self._control_cpus)
            verify_policy_readbacks(
                initial_policy,
                expected_frequency_khz=self.policy.positive_frequency_khz,
            )
            self._policy_reader = _AmdPersistentPolicyReader(initial_policy)
            self._policy_samples.append(
                {
                    "raw_ns": now,
                    "readbacks": [_readback_document(item) for item in initial_policy],
                }
            )
            next_temperature = (
                temperature_now + self.policy.temperature_period_ns
            )
            next_policy = now + self.policy.counter_period_ns
            self._started.set()
            while not self._stop.is_set():
                with self._lock:
                    next_boundary = self._pending[0][0] if self._pending else None
                now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                due = _continuous_monitor_due_ns(
                    now,
                    next_temperature,
                    next_policy,
                    next_boundary,
                )
                if now < due:
                    wait_ns = _continuous_monitor_wait_ns(now, due, next_boundary)
                    if wait_ns:
                        self._wake.wait(min(wait_ns / 1_000_000_000, 0.02))
                        self._wake.clear()
                        continue
                    if self._spin_until is None:
                        raise HealthError(
                            "AMD continuous monitor spin helper is unavailable"
                        )
                    now = int(self._spin_until(due))
                    if now < due:
                        raise HealthError(
                            "AMD continuous monitor spin helper failed"
                        )
                now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                monitor_cpu = _current_cpu()
                if monitor_cpu != self.housekeeping_cpu:
                    raise HealthError("AMD continuous monitor migrated")
                with self._lock:
                    due_boundaries = []
                    while self._pending and self._pending[0][0] <= now:
                        due_boundaries.append(heapq.heappop(self._pending))
                grouped_boundaries: dict[int, list[str]] = {}
                for target, token in due_boundaries:
                    grouped_boundaries.setdefault(target, []).append(token)
                for target, tokens in grouped_boundaries.items():
                    boundary_cpu = _current_cpu()
                    temperature, temperature_now = self._sample_temperature(
                        boundary_cpu
                    )
                    while next_temperature <= temperature_now:
                        next_temperature += self.policy.temperature_period_ns
                    if self._counter_reader is None:
                        raise HealthError(
                            "AMD continuous perf counter reader is unavailable"
                        )
                    counter_before_raw_ns = time.clock_gettime_ns(
                        time.CLOCK_MONOTONIC_RAW
                    )
                    counters = self._counter_reader.read()
                    counter_after_raw_ns = time.clock_gettime_ns(
                        time.CLOCK_MONOTONIC_RAW
                    )
                    boundary_now = counter_before_raw_ns + (
                        counter_after_raw_ns - counter_before_raw_ns
                    ) // 2
                    for token in tokens:
                        cgroup_throttling = {
                            str(path): _read_cgroup_throttling(path)
                            for path in self._boundary_cgroups[token]
                        }
                        snapshot = AmdBoundarySnapshot(
                            token=token,
                            target_raw_ns=target,
                            observed_raw_ns=boundary_now,
                            monitor_cpu=boundary_cpu,
                            counters=counters,
                            tctl_millicelsius=temperature,
                            cgroup_throttling=cgroup_throttling,
                        )
                        with self._lock:
                            self._boundaries[token] = snapshot
                            self._boundary_events[token].set()
                if (
                    now >= next_temperature
                    and _continuous_monitor_periodic_allowed(
                        now,
                        next_boundary,
                        CONTINUOUS_MONITOR_BOUNDARY_SPIN_LEAD_NS,
                    )
                ):
                    _temperature, temperature_now = self._sample_temperature(
                        monitor_cpu
                    )
                    while next_temperature <= temperature_now:
                        next_temperature += self.policy.temperature_period_ns
                if (
                    now >= next_policy
                    and _continuous_monitor_periodic_allowed(
                        now,
                        next_boundary,
                        CONTINUOUS_MONITOR_BOUNDARY_POLICY_GUARD_NS,
                    )
                ):
                    if self._policy_reader is None:
                        raise HealthError(
                            "AMD continuous policy reader is unavailable"
                        )
                    readbacks = self._policy_reader.read()
                    verify_policy_readbacks(
                        readbacks,
                        expected_frequency_khz=self.policy.positive_frequency_khz,
                    )
                    self._policy_samples.append(
                        {
                            "raw_ns": time.clock_gettime_ns(
                                time.CLOCK_MONOTONIC_RAW
                            ),
                            "readbacks": [
                                _readback_document(item) for item in readbacks
                            ],
                        }
                    )
                    next_policy = time.clock_gettime_ns(
                        time.CLOCK_MONOTONIC_RAW
                    ) + self.policy.counter_period_ns
            self._end_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        except BaseException as exc:
            self._end_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            self._error = exc
            self._stop.set()
            self._started.set()
            with self._lock:
                for event in self._boundary_events.values():
                    event.set()
        finally:
            self._stop_temperature_watchdog()
            if self._policy_reader is not None:
                self._policy_reader.close()
                self._policy_reader = None
            if self._temperature_fd is not None:
                os.close(self._temperature_fd)
                self._temperature_fd = None
            if self._counter_reader is not None:
                self._counter_reader.close()
                self._counter_reader = None

    def start(self) -> None:
        if self._thread is not None:
            raise HealthError("AMD continuous monitor already started")
        self._previous_switch_interval = sys.getswitchinterval()
        sys.setswitchinterval(CONTINUOUS_MONITOR_SWITCH_INTERVAL_SECONDS)
        self._thread = threading.Thread(
            target=self._run,
            name="quicperf-amd-session-monitor",
            daemon=True,
        )
        try:
            self._thread.start()
        except BaseException:
            self._restore_switch_interval()
            raise
        if not self._started.wait(timeout=2):
            self._stop.set()
            self._wake.set()
            self._thread.join(timeout=2)
            self._restore_switch_interval()
            raise HealthError("AMD continuous monitor did not start")
        if self._error is not None:
            self._restore_switch_interval()
            if isinstance(self._error, AmdMonitorTransientError):
                raise self._error
            raise HealthError(f"AMD continuous monitor failed: {self._error}") from self._error

    def schedule_interval(
        self,
        token: str,
        start_raw_ns: int,
        end_raw_ns: int,
        *,
        cgroup_paths: Sequence[Path],
    ) -> None:
        self._raise_monitor_error()
        if (
            not token
            or end_raw_ns <= start_raw_ns
            or self._thread is None
            or self._stop.is_set()
        ):
            raise HealthError("AMD microblock boundary request is invalid")
        now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        if start_raw_ns - now < 10_000_000:
            raise AmdBoundaryMonitorTransientError(
                "AMD microblock start boundary lacks 10 ms scheduling lead"
            )
        paths = tuple(cgroup_paths)
        if not paths or len(set(paths)) != len(paths):
            raise HealthError("AMD microblock boundary requires distinct cgroups")
        with self._lock:
            for suffix, target in (("start", start_raw_ns), ("end", end_raw_ns)):
                name = f"{token}:{suffix}"
                if name in self._boundary_events:
                    raise HealthError("AMD microblock boundary token is duplicate")
                self._boundary_events[name] = threading.Event()
                self._boundary_cgroups[name] = paths
                heapq.heappush(self._pending, (target, name))
        self._wake.set()

    def cancel_interval(self, token: str) -> None:
        """Cancel a not-yet-observed boundary pair before an ARM rebase."""

        self._raise_monitor_error()
        names = {f"{token}:start", f"{token}:end"}
        with self._lock:
            pending_names = {name for _target, name in self._pending}
            if (
                not token
                or not names <= set(self._boundary_events)
                or not names <= pending_names
                or names & set(self._boundaries)
                or any(self._boundary_events[name].is_set() for name in names)
            ):
                raise HealthError(
                    "AMD microblock boundary cannot be cancelled after observation"
                )
            self._pending = [
                item for item in self._pending if item[1] not in names
            ]
            heapq.heapify(self._pending)
            for name in names:
                del self._boundary_events[name]
                del self._boundary_cgroups[name]
        self._wake.set()

    def finish_interval(
        self,
        token: str,
        *,
        duration_ns: int,
    ) -> AmdMicroblockEvaluation:
        names = (f"{token}:start", f"{token}:end")
        with self._lock:
            events = [self._boundary_events.get(name) for name in names]
        if any(event is None for event in events):
            raise HealthError("AMD microblock boundary token is unknown")
        for event in events:
            assert event is not None
            if not event.wait(timeout=max(2.0, duration_ns / 1_000_000_000 + 2.0)):
                raise AmdBoundaryMonitorTransientError(
                    "AMD microblock boundary was not sampled"
                )
        self._raise_monitor_error()
        with self._lock:
            start = self._boundaries[names[0]]
            end = self._boundaries[names[1]]
        evaluation = evaluate_microblock_boundaries(
            start, end, duration_ns=duration_ns, policy=self.policy, reference=self.reference
        )
        with self._lock:
            self._evaluations[token] = evaluation
        return evaluation

    def stop(self) -> dict[str, Any]:
        if self._thread is None:
            raise HealthError("AMD continuous monitor was not started")
        self._stop.set()
        self._wake.set()
        self._thread.join(timeout=2)
        if self._thread.is_alive():
            self._restore_switch_interval()
            raise HealthError("AMD continuous monitor did not stop")
        self._restore_switch_interval()
        reasons = []
        monitor_error = None
        if self._error is not None:
            reasons.append(f"monitor_error:{self._error}")
            monitor_error = {
                "type": type(self._error).__name__,
                "message": str(self._error),
                "treatment_independent_transient": isinstance(
                    self._error, AmdMonitorTransientError
                ),
            }
        else:
            try:
                if self._control_cpus is None:
                    raise HealthError("AMD continuous monitor lacks SMT policy ownership")
                final_policy = read_policy_readbacks(self._control_cpus)
                verify_policy_readbacks(
                    final_policy,
                    expected_frequency_khz=self.policy.positive_frequency_khz,
                )
                self._policy_samples.append(
                    {
                        "raw_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
                        "readbacks": [
                            _readback_document(item) for item in final_policy
                        ],
                    }
                )
            except HealthError as exc:
                reasons.append(f"policy_readback_after_failed:{exc}")
        temperature_samples = tuple(
            sorted(
                self._temperature_samples + self._watchdog_temperature_samples,
                key=lambda sample: sample.raw_ns,
            )
        )
        evidence = AmdProbeEvidence(
            start_raw_ns=self._start_raw_ns,
            end_raw_ns=self._end_raw_ns,
            monitor_cpu=(
                self._temperature_watchdog_cpu_attested
                if self._temperature_watchdog_cpu_attested is not None
                else self.housekeeping_cpu
            ),
            counter_samples={
                cpu: tuple(values)
                for cpu, values in self._watchdog_counter_samples.items()
            },
            temperature_samples=temperature_samples,
            loop_buckets={cpu: () for cpu in self.cpus},
            helper_sha256=_sha256_file(Path(__file__)),
        )
        windows = derive_counter_windows(evidence, self.policy)
        for cpu, samples in evidence.counter_samples.items():
            if not samples:
                reasons.append(f"cpu{cpu}_counter_sample_missing")
            elif (
                samples[0].raw_ns - evidence.start_raw_ns
                > self.policy.counter_interval_max_ns
                or evidence.end_raw_ns - samples[-1].raw_ns
                > self.policy.counter_interval_max_ns
            ):
                reasons.append(f"cpu{cpu}_counter_monitor_dropout")
        for cpu, values in windows.items():
            for window in values:
                if not window.valid:
                    reasons.append(f"cpu{cpu}_{window.reason}")
                elif window.active and window.ratio / self.reference.ratio[cpu] < float(
                    self.policy.active_window_ratio_minimum
                ):
                    reasons.append(f"cpu{cpu}_active_window_below_98_percent")
        reasons.extend(
            _continuous_temperature_reasons(
                evidence.temperature_samples,
                start_raw_ns=evidence.start_raw_ns,
                end_raw_ns=evidence.end_raw_ns,
                policy=self.policy,
            )
        )
        return {
            "schema_version": "quicperf.amd-continuous-session.v1",
            "provider": PROVIDER_VERSION,
            "passed": not reasons,
            "reasons": list(dict.fromkeys(reasons)),
            "monitor_error": monitor_error,
            "monitor_source_sha256": _sha256_file(Path(__file__)),
            "temperature_watchdog": {
                "process_isolated": True,
                "pid": self._temperature_watchdog_pid,
                "cpu": self._temperature_watchdog_cpu_attested,
                "scheduler": "SCHED_FIFO",
                "priority": CONTINUOUS_MONITOR_SCHED_FIFO_PRIORITY,
                "period_ns": self.policy.temperature_period_ns,
                "counter_period_ns": self.policy.counter_period_ns,
                "counter_cpus": list(self.cpus),
                "counter_samples": sum(
                    len(values)
                    for values in self._watchdog_counter_samples.values()
                ),
                "phase_offset_ns": self.policy.temperature_period_ns // 2,
                "helper_sha256": _sha256_file(
                    Path(__file__).with_name("amd_temperature_watchdog.py")
                ),
                "started_raw_ns": self._temperature_watchdog_started_raw_ns,
                "stopped_raw_ns": self._temperature_watchdog_stopped_raw_ns,
                "samples": len(self._watchdog_temperature_samples),
            },
            "raw": probe_evidence_document(evidence),
            "policy_samples": self._policy_samples,
            "microblock_evaluations": {
                token: {
                    "passed": value.passed,
                    "reasons": list(value.reasons),
                    "active_cpus": list(value.active_cpus),
                    "start_lateness_ns": value.start_lateness_ns,
                    "end_lateness_ns": value.end_lateness_ns,
                    "target_interval_ns": value.target_interval_ns,
                    "observed_interval_ns": value.observed_interval_ns,
                    "interval_duration_error_ns": (
                        value.interval_duration_error_ns
                    ),
                    "phase_offset_max_ns": self.policy.phase_offset_max_ns,
                    "interval_duration_error_max_fraction": format(
                        self.policy.interval_duration_error_max_fraction,
                        "f",
                    ),
                    "fraction_of_reference": {
                        str(cpu): format(fraction, ".17g")
                        for cpu, fraction in sorted(
                            value.fraction_of_reference.items()
                        )
                    },
                }
                for token, value in sorted(self._evaluations.items())
            },
            "boundaries": {
                token: {
                    "target_raw_ns": value.target_raw_ns,
                    "observed_raw_ns": value.observed_raw_ns,
                    "monitor_cpu": value.monitor_cpu,
                    "counters": {
                        str(cpu): {"aperf": pair[0], "mperf": pair[1]}
                        for cpu, pair in sorted(value.counters.items())
                    },
                    "tctl_millicelsius": value.tctl_millicelsius,
                    "cgroup_throttling": {
                        path: {
                            "nr_throttled": counters[0],
                            "throttled_usec": counters[1],
                        }
                        for path, counters in sorted(value.cgroup_throttling.items())
                    },
                }
                for token, value in sorted(self._boundaries.items())
            },
        }


class _AmdMonitorManager(BaseManager):
    pass


_AmdMonitorManager.register(
    "create_monitor",
    _AmdContinuousMonitorWorker,
)


class AmdContinuousMonitor:
    """Process-isolated facade for the exact-boundary AMD monitor."""

    def __init__(
        self,
        *,
        cpus: Sequence[int],
        housekeeping_cpu: int,
        spin_helper: Path,
        policy: AmdProviderPolicy,
        reference: AmdReference,
        temperature_source: AmdTemperatureSource,
    ) -> None:
        self._arguments = {
            "cpus": tuple(cpus),
            "housekeeping_cpu": housekeeping_cpu,
            "spin_helper": spin_helper,
            "policy": policy,
            "reference": reference,
            "temperature_source": temperature_source,
        }
        self._manager: _AmdMonitorManager | None = None
        self._monitor: Any = None

    def start(self) -> None:
        if self._manager is not None:
            raise HealthError("AMD continuous monitor already started")
        if len(threading.enumerate()) != 1:
            raise HealthError(
                "AMD monitor process must start before coordinator worker threads"
            )
        manager = _AmdMonitorManager(ctx=multiprocessing.get_context("fork"))
        try:
            manager.start()
            monitor = manager.create_monitor(**self._arguments)
            monitor.start()
        except BaseException:
            manager.shutdown()
            raise
        self._manager = manager
        self._monitor = monitor

    def schedule_interval(
        self,
        token: str,
        start_raw_ns: int,
        end_raw_ns: int,
        *,
        cgroup_paths: Sequence[Path],
    ) -> None:
        if self._monitor is None:
            raise HealthError("AMD continuous monitor was not started")
        self._monitor.schedule_interval(
            token,
            start_raw_ns,
            end_raw_ns,
            cgroup_paths=tuple(cgroup_paths),
        )

    def cancel_interval(self, token: str) -> None:
        if self._monitor is None:
            raise HealthError("AMD continuous monitor was not started")
        self._monitor.cancel_interval(token)

    def finish_interval(
        self,
        token: str,
        *,
        duration_ns: int,
    ) -> AmdMicroblockEvaluation:
        if self._monitor is None:
            raise HealthError("AMD continuous monitor was not started")
        return self._monitor.finish_interval(token, duration_ns=duration_ns)

    def stop(self) -> dict[str, Any]:
        manager = self._manager
        monitor = self._monitor
        if manager is None or monitor is None:
            raise HealthError("AMD continuous monitor was not started")
        self._manager = None
        self._monitor = None
        try:
            return monitor.stop()
        finally:
            manager.shutdown()


def evaluate_microblock_boundaries(
    start: AmdBoundarySnapshot,
    end: AmdBoundarySnapshot,
    *,
    duration_ns: int,
    policy: AmdProviderPolicy,
    reference: AmdReference,
) -> AmdMicroblockEvaluation:
    reasons: list[str] = []
    start_lateness_ns = start.observed_raw_ns - start.target_raw_ns
    end_lateness_ns = end.observed_raw_ns - end.target_raw_ns
    target_interval_ns = end.target_raw_ns - start.target_raw_ns
    observed_interval_ns = end.observed_raw_ns - start.observed_raw_ns
    interval_duration_error_ns = abs(observed_interval_ns - target_interval_ns)
    if start.monitor_cpu != end.monitor_cpu or start.monitor_cpu < 0:
        reasons.append("microblock_boundary_monitor_error")
    if policy.boundary_timestamp_semantics == "observed_interval":
        if (
            abs(start_lateness_ns) > policy.phase_offset_max_ns
            or abs(end_lateness_ns) > policy.phase_offset_max_ns
        ):
            reasons.append("microblock_boundary_phase_offset_exceeded")
        if (
            duration_ns <= 0
            or Decimal(interval_duration_error_ns)
            > Decimal(duration_ns)
            * policy.interval_duration_error_max_fraction
        ):
            reasons.append("microblock_boundary_interval_duration_error_exceeded")
        activity_interval_ns = observed_interval_ns
    else:
        if (
            abs(start_lateness_ns) > policy.phase_offset_max_ns
            or abs(end_lateness_ns) > policy.phase_offset_max_ns
        ):
            reasons.append("microblock_boundary_monitor_error")
        activity_interval_ns = duration_ns
    if target_interval_ns != duration_ns or duration_ns <= 0:
        reasons.append("microblock_exact_duration_mismatch")
    if set(start.counters) != set(end.counters) or set(start.counters) != set(reference.ratio):
        raise HealthError("AMD microblock boundary CPU sets differ")
    if set(start.cgroup_throttling) != set(end.cgroup_throttling):
        raise HealthError("AMD microblock boundary cgroup sets differ")
    for path in sorted(start.cgroup_throttling):
        before_nr, before_usec = start.cgroup_throttling[path]
        after_nr, after_usec = end.cgroup_throttling[path]
        if after_nr < before_nr or after_usec < before_usec:
            reasons.append(f"cgroup_counter_nonmonotonic:{path}")
        elif after_nr != before_nr or after_usec != before_usec:
            reasons.append(f"cgroup_cpu_throttling_detected:{path}")
    active = []
    fractions: dict[int, float] = {}
    base_hz = policy.entry.base_frequency_khz * 1_000
    for cpu in sorted(start.counters):
        aperf_delta = end.counters[cpu][0] - start.counters[cpu][0]
        mperf_delta = end.counters[cpu][1] - start.counters[cpu][1]
        if aperf_delta < 0 or mperf_delta < 0:
            reasons.append(f"cpu{cpu}_counter_nonmonotonic")
            continue
        if (
            activity_interval_ns <= 0
            or mperf_delta * 20 * 1_000_000_000
            < base_hz * activity_interval_ns
        ):
            continue
        active.append(cpu)
        fraction = (aperf_delta / mperf_delta) / reference.ratio[cpu]
        fractions[cpu] = fraction
        if fraction < float(policy.cumulative_ratio_minimum):
            reasons.append(f"cpu{cpu}_microblock_ratio_below_99_5_percent")
    if (
        start.tctl_millicelsius >= policy.measurement_ceiling_millicelsius
        or end.tctl_millicelsius >= policy.measurement_ceiling_millicelsius
    ):
        reasons.append("microblock_tctl_thermal_headroom_breach")
    reasons = list(dict.fromkeys(reasons))
    return AmdMicroblockEvaluation(
        passed=not reasons,
        reasons=tuple(reasons),
        active_cpus=tuple(active),
        fraction_of_reference=fractions,
        start_lateness_ns=start_lateness_ns,
        end_lateness_ns=end_lateness_ns,
        target_interval_ns=target_interval_ns,
        observed_interval_ns=observed_interval_ns,
        interval_duration_error_ns=interval_duration_error_ns,
    )
