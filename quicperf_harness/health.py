"""Exact lane-health telemetry collected outside endpoint hot paths."""

from __future__ import annotations

import ctypes
import fcntl
import math
import os
import platform
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


class HealthError(RuntimeError):
    pass


AMD_PERF_COUNTER_SOURCE = "linux_perf_event_msr_group"
_PERF_FORMAT_TOTAL_TIME_ENABLED = 1 << 0
_PERF_FORMAT_TOTAL_TIME_RUNNING = 1 << 1
_PERF_FORMAT_ID = 1 << 2
_PERF_FORMAT_GROUP = 1 << 3
_PERF_EVENT_IOC_ENABLE = 0x2400
_PERF_EVENT_IOC_RESET = 0x2403
_PERF_EVENT_IOC_ID = 0x80082407
_PERF_IOC_FLAG_GROUP = 1
_PERF_FLAG_FD_CLOEXEC = 1 << 3


class _PerfEventAttr(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("sample_period", ctypes.c_uint64),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("reserved", ctypes.c_ubyte * 72),
    ]


def _perf_event_open(
    attributes: _PerfEventAttr,
    *,
    cpu: int,
    group_fd: int,
) -> int:
    if platform.machine() != "x86_64":
        raise HealthError("AMD APERF/MPERF perf events require x86_64")
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.syscall(
        298,
        ctypes.byref(attributes),
        -1,
        cpu,
        group_fd,
        _PERF_FLAG_FD_CLOEXEC,
    )
    if descriptor < 0:
        error = ctypes.get_errno()
        raise HealthError(
            f"cannot open CPU {cpu} APERF/MPERF perf event: "
            f"[{error}] {os.strerror(error)}"
        )
    return int(descriptor)


def _perf_event_id(descriptor: int) -> int:
    encoded = bytearray(8)
    try:
        fcntl.ioctl(descriptor, _PERF_EVENT_IOC_ID, encoded, True)
    except OSError as exc:
        raise HealthError(f"cannot identify APERF/MPERF perf event: {exc}") from exc
    return struct.unpack("=Q", encoded)[0]


def _read_perf_event_definition(path: Path, label: str) -> int:
    try:
        text = path.read_text(encoding="ascii").strip()
        prefix, separator, value = text.partition("=")
        if prefix != "event" or separator != "=":
            raise ValueError
        result = int(value, 0)
    except (OSError, ValueError) as exc:
        raise HealthError(f"cannot read {label} perf event from {path}: {exc}") from exc
    if result < 0:
        raise HealthError(f"{label} perf event is negative")
    return result


class AmdPerfCounterReader:
    """Persistent, coherent, nonmultiplexed APERF/MPERF groups per CPU."""

    def __init__(
        self,
        cpus: Sequence[int],
        event_source: Path = Path("/sys/bus/event_source/devices/msr"),
    ) -> None:
        self.cpus = tuple(cpus)
        if (
            not self.cpus
            or len(set(self.cpus)) != len(self.cpus)
            or any(type(cpu) is not int or cpu < 0 for cpu in self.cpus)
        ):
            raise HealthError("APERF/MPERF requires distinct nonnegative CPUs")
        try:
            event_type = int((event_source / "type").read_text(encoding="ascii").strip())
        except (OSError, ValueError) as exc:
            raise HealthError(f"cannot read MSR perf event type: {exc}") from exc
        if event_type <= 0:
            raise HealthError("MSR perf event type is invalid")
        configs = {
            "aperf": _read_perf_event_definition(
                event_source / "events/aperf", "APERF"
            ),
            "mperf": _read_perf_event_definition(
                event_source / "events/mperf", "MPERF"
            ),
        }
        if configs["aperf"] == configs["mperf"]:
            raise HealthError("APERF and MPERF perf events are identical")

        self._groups: dict[int, tuple[int, int, Mapping[int, str]]] = {}
        self._last_time_enabled: dict[int, int] = {}
        try:
            for cpu in self.cpus:
                leader = self._open(
                    cpu=cpu,
                    event_type=event_type,
                    config=configs["aperf"],
                    group_fd=-1,
                    disabled=True,
                )
                try:
                    member = self._open(
                        cpu=cpu,
                        event_type=event_type,
                        config=configs["mperf"],
                        group_fd=leader,
                        disabled=False,
                    )
                except BaseException:
                    os.close(leader)
                    raise
                try:
                    identities = {
                        _perf_event_id(leader): "aperf",
                        _perf_event_id(member): "mperf",
                    }
                    if len(identities) != 2:
                        raise HealthError("APERF/MPERF perf event IDs are not distinct")
                    try:
                        fcntl.ioctl(
                            leader,
                            _PERF_EVENT_IOC_RESET,
                            _PERF_IOC_FLAG_GROUP,
                        )
                        fcntl.ioctl(
                            leader,
                            _PERF_EVENT_IOC_ENABLE,
                            _PERF_IOC_FLAG_GROUP,
                        )
                    except OSError as exc:
                        raise HealthError(
                            f"cannot activate CPU {cpu} APERF/MPERF perf group: {exc}"
                        ) from exc
                except BaseException:
                    os.close(member)
                    os.close(leader)
                    raise
                self._groups[cpu] = (leader, member, identities)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _open(
        *,
        cpu: int,
        event_type: int,
        config: int,
        group_fd: int,
        disabled: bool,
    ) -> int:
        attributes = _PerfEventAttr()
        attributes.type = event_type
        attributes.size = ctypes.sizeof(attributes)
        attributes.config = config
        attributes.read_format = (
            _PERF_FORMAT_TOTAL_TIME_ENABLED
            | _PERF_FORMAT_TOTAL_TIME_RUNNING
            | _PERF_FORMAT_ID
            | _PERF_FORMAT_GROUP
        )
        attributes.flags = 1 if disabled else 0
        return _perf_event_open(attributes, cpu=cpu, group_fd=group_fd)

    def read(self) -> dict[int, tuple[int, int]]:
        result: dict[int, tuple[int, int]] = {}
        for cpu, (leader, _member, identities) in self._groups.items():
            try:
                payload = os.read(leader, 56)
            except OSError as exc:
                raise HealthError(
                    f"cannot read CPU {cpu} APERF/MPERF perf group: {exc}"
                ) from exc
            if len(payload) != 56:
                raise HealthError(f"short CPU {cpu} APERF/MPERF perf-group read")
            values = struct.unpack("=7Q", payload)
            count, time_enabled, time_running = values[:3]
            if count != 2:
                raise HealthError(f"CPU {cpu} APERF/MPERF perf group has {count} events")
            if time_enabled == 0 or time_enabled != time_running:
                raise HealthError(f"CPU {cpu} APERF/MPERF perf group was multiplexed")
            previous = self._last_time_enabled.get(cpu)
            if previous is not None and time_enabled <= previous:
                raise HealthError(f"CPU {cpu} APERF/MPERF perf time did not advance")
            self._last_time_enabled[cpu] = time_enabled
            observed: dict[str, int] = {}
            for value, identity in ((values[3], values[4]), (values[5], values[6])):
                label = identities.get(identity)
                if label is None or label in observed:
                    raise HealthError(
                        f"CPU {cpu} APERF/MPERF perf-group identity is invalid"
                    )
                observed[label] = value
            if set(observed) != {"aperf", "mperf"}:
                raise HealthError(f"CPU {cpu} APERF/MPERF perf group is incomplete")
            result[cpu] = (observed["aperf"], observed["mperf"])
        return result

    def close(self) -> None:
        groups, self._groups = self._groups, {}
        for leader, member, _identities in groups.values():
            os.close(member)
            os.close(leader)

    def __enter__(self) -> AmdPerfCounterReader:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


@dataclass(frozen=True)
class AmdCounterSample:
    raw_ns: int
    aperf: int
    mperf: int


@dataclass(frozen=True)
class AmdTemperatureSample:
    raw_ns: int
    tctl_millicelsius: int


@dataclass(frozen=True)
class AmdDeliveredPerformanceResult:
    aggregate_fraction_of_reference: float
    minimum_active_window_fraction: float
    maximum_tctl_millicelsius: int
    active_windows: int
    passed: bool
    reasons: tuple[str, ...]


def amd_k10temp_sources(
    hwmon_root: Path = Path("/sys/class/hwmon"),
) -> tuple[Path, Path]:
    """Return the k10temp Tctl input and mandatory critical-temperature metadata."""

    matches: list[tuple[Path, Path]] = []
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
            if input_path.is_file() and critical_path.is_file():
                matches.append((input_path.resolve(), critical_path.resolve()))
    if len(matches) != 1:
        raise HealthError(
            "amd_delivered_performance_v1 requires exactly one k10temp Tctl "
            "input with critical-temperature metadata"
        )
    return matches[0]


def evaluate_amd_delivered_performance(
    *,
    counter_samples: Mapping[int, Sequence[AmdCounterSample]],
    active_windows: Mapping[int, Sequence[bool]],
    cool_reference_ratios: Mapping[int, float],
    temperature_samples: Sequence[AmdTemperatureSample],
    critical_millicelsius: int,
) -> AmdDeliveredPerformanceResult:
    """Evaluate the frozen AMD v1 delivered-performance and thermal invariants."""

    reasons: list[str] = []
    cpus = set(counter_samples)
    if not cpus or cpus != set(active_windows) or cpus != set(cool_reference_ratios):
        raise HealthError("AMD performance inputs must name the same nonempty CPU set")
    if critical_millicelsius <= 15_000:
        raise HealthError("critical temperature metadata is invalid")
    thermal_limit = min(80_000, critical_millicelsius - 15_000)
    if not temperature_samples:
        reasons.append("tctl_sample_missing")
        maximum_temperature = 0
    else:
        maximum_temperature = max(sample.tctl_millicelsius for sample in temperature_samples)
        if any(
            current.raw_ns <= previous.raw_ns
            or current.raw_ns - previous.raw_ns > 20_000_000
            for previous, current in zip(
                temperature_samples, temperature_samples[1:]
            )
        ):
            reasons.append("tctl_sampling_dropout")
        if maximum_temperature >= thermal_limit:
            reasons.append("tctl_thermal_headroom_breach")

    normalized_windows: list[tuple[float, int]] = []
    for cpu in sorted(cpus):
        samples = tuple(counter_samples[cpu])
        active = tuple(active_windows[cpu])
        reference = float(cool_reference_ratios[cpu])
        if not math.isfinite(reference) or reference <= 0.0:
            raise HealthError(f"CPU {cpu} cool reference is invalid")
        if len(samples) < 2 or len(active) != len(samples) - 1:
            raise HealthError(f"CPU {cpu} window/sample cardinality mismatch")
        for index, (before, after) in enumerate(zip(samples, samples[1:])):
            if after.raw_ns <= before.raw_ns:
                reasons.append(f"cpu{cpu}_counter_timestamp_regressed")
                continue
            if after.raw_ns - before.raw_ns != 100_000_000:
                reasons.append(f"cpu{cpu}_active_window_not_100ms")
            aperf_delta = after.aperf - before.aperf
            mperf_delta = after.mperf - before.mperf
            if aperf_delta < 0 or mperf_delta < 0:
                reasons.append(f"cpu{cpu}_counter_discontinuity")
                continue
            if not active[index]:
                continue
            if aperf_delta == 0 or mperf_delta == 0:
                reasons.append(f"cpu{cpu}_active_window_counter_missing")
                continue
            normalized = (aperf_delta / mperf_delta) / reference
            normalized_windows.append((normalized, mperf_delta))
            if normalized < 0.98:
                reasons.append(f"cpu{cpu}_active_window_below_98_percent")
    if not normalized_windows:
        reasons.append("active_window_missing")
        aggregate = minimum = 0.0
    else:
        total_weight = sum(weight for _, weight in normalized_windows)
        aggregate = sum(value * weight for value, weight in normalized_windows) / total_weight
        minimum = min(value for value, _ in normalized_windows)
        if aggregate < 0.99:
            reasons.append("aggregate_delivered_performance_below_99_percent")
    unique_reasons = tuple(dict.fromkeys(reasons))
    return AmdDeliveredPerformanceResult(
        aggregate_fraction_of_reference=aggregate,
        minimum_active_window_fraction=minimum,
        maximum_tctl_millicelsius=maximum_temperature,
        active_windows=len(normalized_windows),
        passed=not unique_reasons,
        reasons=unique_reasons,
    )


def read_device_irq_counts(
    cpus: Sequence[int], proc_interrupts: Path = Path("/proc/interrupts")
) -> dict[int, dict[int, int]]:
    """Return every numeric device-IRQ counter for each requested CPU."""

    requested = set(cpus)
    if not requested or any(type(cpu) is not int or cpu < 0 for cpu in requested):
        raise HealthError("IRQ telemetry requires nonnegative CPU IDs")
    try:
        lines = proc_interrupts.read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise HealthError(f"cannot read {proc_interrupts}: {exc}") from exc
    if not lines:
        raise HealthError(f"empty interrupt table: {proc_interrupts}")
    labels = lines[0].split()
    positions: dict[int, int] = {}
    for position, label in enumerate(labels):
        if not label.startswith("CPU") or not label[3:].isdecimal():
            raise HealthError(f"malformed interrupt CPU header: {label!r}")
        cpu = int(label[3:])
        if cpu in positions:
            raise HealthError(f"duplicate interrupt CPU header: CPU{cpu}")
        positions[cpu] = position
    missing = requested - positions.keys()
    if missing:
        raise HealthError(f"missing interrupt CPU columns: {sorted(missing)}")
    result = {cpu: {} for cpu in requested}
    seen: set[int] = set()
    for line in lines[1:]:
        label, separator, payload = line.partition(":")
        label = label.strip()
        if not separator or not label.isdecimal():
            continue
        irq = int(label)
        if irq in seen:
            raise HealthError(f"duplicate numeric IRQ row: {irq}")
        seen.add(irq)
        fields = payload.split()
        if len(fields) < len(labels) or any(
            not field.isdecimal() for field in fields[: len(labels)]
        ):
            raise HealthError(f"malformed numeric IRQ row: {irq}")
        for cpu in requested:
            result[cpu][irq] = int(fields[positions[cpu]])
    if not seen:
        raise HealthError("interrupt table contains no numeric IRQ rows")
    return result


def _read_nonnegative(path: Path) -> int:
    try:
        text = path.read_text(encoding="ascii").strip()
        value = int(text)
    except (OSError, ValueError) as exc:
        raise HealthError(f"cannot read integer health counter {path}: {exc}") from exc
    if value < 0:
        raise HealthError(f"negative health counter {path}")
    return value


def read_frequency_hz(
    cpus: Sequence[int], sys_cpu: Path = Path("/sys/devices/system/cpu")
) -> dict[int, int]:
    frequencies: dict[int, int] = {}
    for cpu in cpus:
        base = sys_cpu / f"cpu{cpu}" / "cpufreq"
        paths = (base / "scaling_cur_freq", base / "cpuinfo_cur_freq")
        selected = next((path for path in paths if path.is_file()), None)
        if selected is None:
            raise HealthError(f"CPU {cpu} exposes no current-frequency counter")
        frequencies[cpu] = _read_nonnegative(selected) * 1_000
    return frequencies


def thermal_counter_paths(
    cpus: Sequence[int], sys_cpu: Path = Path("/sys/devices/system/cpu")
) -> tuple[Path, ...]:
    paths: set[Path] = set()
    for cpu in cpus:
        root = sys_cpu / f"cpu{cpu}" / "thermal_throttle"
        for name in ("core_throttle_count", "package_throttle_count"):
            candidate = root / name
            if candidate.is_file():
                paths.add(candidate.resolve())
    if not paths:
        raise HealthError("eligible CPUs expose no thermal-throttle counters")
    return tuple(sorted(paths))


def read_thermal_counts(paths: Sequence[Path]) -> dict[str, int]:
    if not paths:
        raise HealthError("thermal counter path set is empty")
    return {str(path): _read_nonnegative(path) for path in paths}


def swap_is_disabled(proc_swaps: Path = Path("/proc/swaps")) -> bool:
    try:
        lines = proc_swaps.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise HealthError(f"cannot read {proc_swaps}: {exc}") from exc
    return not any(line.strip() for line in lines[1:])


@dataclass(frozen=True)
class HealthSummary:
    frequency_min_hz: int
    frequency_max_hz: int
    thermal_throttle_delta: int
    swap_active: bool
    samples: int


class LaneHealthMonitor:
    """Poll frequency/thermal/swap from housekeeping CPUs during a trial."""

    def __init__(
        self,
        cpus: Sequence[int],
        *,
        interval_seconds: float = 0.025,
        sys_cpu: Path = Path("/sys/devices/system/cpu"),
        proc_swaps: Path = Path("/proc/swaps"),
        external_thermal_provider: bool = False,
    ) -> None:
        if not cpus or interval_seconds <= 0:
            raise HealthError("health monitor requires CPUs and a positive cadence")
        self.cpus = tuple(cpus)
        self.interval_seconds = interval_seconds
        self.sys_cpu = sys_cpu
        self.proc_swaps = proc_swaps
        self.external_thermal_provider = external_thermal_provider
        self.thermal_paths = (
            ()
            if external_thermal_provider
            else thermal_counter_paths(self.cpus, self.sys_cpu)
        )
        self._initial_thermal = (
            {} if external_thermal_provider else read_thermal_counts(self.thermal_paths)
        )
        self._minimum: int | None = None
        self._maximum: int | None = None
        self._swap_active = False
        self._samples = 0
        self._error: BaseException | None = None
        self._summary: HealthSummary | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample(self) -> None:
        frequencies = read_frequency_hz(self.cpus, self.sys_cpu).values()
        current_min = min(frequencies)
        current_max = max(frequencies)
        self._minimum = current_min if self._minimum is None else min(self._minimum, current_min)
        self._maximum = current_max if self._maximum is None else max(self._maximum, current_max)
        self._swap_active = self._swap_active or not swap_is_disabled(self.proc_swaps)
        self._samples += 1

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                self._sample()
                self._stop.wait(self.interval_seconds)
        except BaseException as exc:
            self._error = exc
            self._stop.set()

    def start(self) -> None:
        if self._thread is not None:
            raise HealthError("health monitor was already started")
        self._sample()
        self._thread = threading.Thread(target=self._run, name="quicperf-health", daemon=True)
        self._thread.start()

    def stop(self) -> HealthSummary:
        if self._summary is not None:
            return self._summary
        if self._thread is None:
            raise HealthError("health monitor was not started")
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.interval_seconds * 4))
        if self._thread.is_alive():
            raise HealthError("health monitor did not stop")
        if self._error is not None:
            raise HealthError(f"health monitor failed: {self._error}") from self._error
        self._sample()
        final = (
            {}
            if self.external_thermal_provider
            else read_thermal_counts(self.thermal_paths)
        )
        delta = 0
        for path, initial in self._initial_thermal.items():
            value = final[path]
            if value < initial:
                raise HealthError(f"thermal counter regressed: {path}")
            delta += value - initial
        assert self._minimum is not None and self._maximum is not None
        self._summary = HealthSummary(
            frequency_min_hz=self._minimum,
            frequency_max_hz=self._maximum,
            thermal_throttle_delta=delta,
            swap_active=self._swap_active,
            samples=self._samples,
        )
        return self._summary


class PerCpuNonOwnedClock:
    """Count non-idle scheduler runtime outside two owned cgroups.

    The embedded tracepoint program performs this operation at each context
    switch, with one array entry per observed CPU:

        if active and previous_pid != 0:
            if current_cgroup_id not in {server_cgroup_id, client_cgroup_id}:
                non_owned_ns += now_ns - last_ns
        last_ns = now_ns

    Direct classification computes every numerator interval from one scheduler
    tracepoint clock. In particular, it does not subtract a perf cgroup clock
    from the runqueue clock exposed by /proc/schedstat.
    """

    _BPF_SYSCALLS = {"x86_64": 321, "amd64": 321, "aarch64": 280, "arm64": 280}
    _PERF_EVENT_OPEN_SYSCALLS = {
        "x86_64": 298,
        "amd64": 298,
        "aarch64": 241,
        "arm64": 241,
    }
    _BPF_MAP_CREATE = 0
    _BPF_MAP_LOOKUP_ELEM = 1
    _BPF_MAP_UPDATE_ELEM = 2
    _BPF_PROG_LOAD = 5
    _BPF_MAP_TYPE_ARRAY = 2
    _BPF_PROG_TYPE_TRACEPOINT = 5
    _PERF_TYPE_TRACEPOINT = 2
    _PERF_FLAG_FD_CLOEXEC = 1 << 3
    _PERF_EVENT_IOC_ENABLE = 0x2400
    _PERF_EVENT_IOC_DISABLE = 0x2401
    _PERF_EVENT_IOC_SET_BPF = 0x40042408
    _STATE = struct.Struct("=QQQQII")
    _PROGRAM_INSTRUCTIONS = 31

    def __init__(
        self,
        cpus: Sequence[int],
        tracepoint_id: Path = Path(
            "/sys/kernel/tracing/events/sched/sched_switch/id"
        ),
    ) -> None:
        self.cpus = tuple(cpus)
        if not self.cpus or len(set(self.cpus)) != len(self.cpus):
            raise HealthError("non-owned scheduler clock requires unique CPUs")
        if any(type(cpu) is not int or cpu < 0 or cpu >= 1024 for cpu in self.cpus):
            raise HealthError("non-owned scheduler clock CPU is outside [0,1024)")
        machine = platform.machine().lower()
        try:
            self._bpf_syscall = self._BPF_SYSCALLS[machine]
            self._perf_syscall = self._PERF_EVENT_OPEN_SYSCALLS[machine]
        except KeyError as exc:
            raise HealthError(f"BPF scheduler accounting is unknown for {machine}") from exc
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._map_fd = -1
        self._program_fds: dict[int, int] = {}
        self._event_fds: dict[int, int] = {}
        self._armed = False
        try:
            event_id = int(tracepoint_id.read_text(encoding="ascii").strip())
            if event_id <= 0:
                raise ValueError("nonpositive tracepoint ID")
        except (OSError, ValueError) as exc:
            raise HealthError(f"cannot resolve sched_switch tracepoint: {exc}") from exc
        try:
            self._map_fd = self._create_map()
            for cpu in self.cpus:
                program_fd = self._load_program(self._map_fd)
                self._program_fds[cpu] = program_fd
                self._event_fds[cpu] = self._attach(cpu, event_id, program_fd)
        except BaseException:
            self.close()
            raise

    def _syscall(self, number: int, *arguments: object) -> int:
        result = int(self._libc.syscall(number, *arguments))
        if result < 0:
            error = ctypes.get_errno()
            raise HealthError(f"kernel telemetry syscall failed: [{error}] {os.strerror(error)}")
        return result

    def _bpf(self, command: int, attr: bytearray) -> int:
        raw = (ctypes.c_ubyte * len(attr)).from_buffer(attr)
        return self._syscall(
            self._bpf_syscall, command, ctypes.byref(raw), len(attr)
        )

    def _create_map(self) -> int:
        attr = bytearray(144)
        struct.pack_into(
            "=IIIII",
            attr,
            0,
            self._BPF_MAP_TYPE_ARRAY,
            4,
            self._STATE.size,
            1024,
            0,
        )
        attr[28:44] = b"qpf_cpu_state\0\0\0"
        return self._bpf(self._BPF_MAP_CREATE, attr)

    @staticmethod
    def _instruction(
        code: int,
        dst: int = 0,
        src: int = 0,
        offset: int = 0,
        immediate: int = 0,
    ) -> bytes:
        return struct.pack("=BBhi", code, dst | (src << 4), offset, immediate)

    @classmethod
    def _program(cls, map_fd: int) -> bytes:
        instruction = cls._instruction
        return b"".join(
            (
                instruction(0x85, immediate=8),
                instruction(0x63, dst=10, src=0, offset=-4),
                instruction(0xBF, dst=2, src=10),
                instruction(0x07, dst=2, immediate=-4),
                instruction(0x18, dst=1, src=1, immediate=map_fd),
                instruction(0x00),
                instruction(0x85, immediate=1),
                instruction(0xBF, dst=6, src=0),
                instruction(0x15, dst=6, offset=20),
                instruction(0x61, dst=1, src=6, offset=32),
                instruction(0x16, dst=1, offset=18),
                instruction(0x85, immediate=5),
                instruction(0xBF, dst=7, src=0),
                instruction(0x85, immediate=14),
                instruction(0x16, dst=0, offset=13),
                instruction(0x79, dst=1, src=6, offset=16),
                instruction(0x15, dst=1, offset=11),
                instruction(0x85, immediate=80),
                instruction(0x79, dst=1, src=6, offset=0),
                instruction(0x1D, dst=0, src=1, offset=8),
                instruction(0x79, dst=1, src=6, offset=8),
                instruction(0x1D, dst=0, src=1, offset=6),
                instruction(0x79, dst=1, src=6, offset=16),
                instruction(0xBF, dst=2, src=7),
                instruction(0x1F, dst=2, src=1),
                instruction(0x79, dst=1, src=6, offset=24),
                instruction(0x0F, dst=2, src=1),
                instruction(0x7B, dst=6, src=2, offset=24),
                instruction(0x7B, dst=6, src=7, offset=16),
                instruction(0xB4, dst=0),
                instruction(0x95),
            )
        )

    def _load_program(self, map_fd: int) -> int:
        program = self._program(map_fd)
        if len(program) != self._PROGRAM_INSTRUCTIONS * 8:
            raise HealthError("scheduler accounting program has an invalid length")
        instructions = ctypes.create_string_buffer(program)
        license_text = ctypes.create_string_buffer(b"GPL\0")
        verifier_log = ctypes.create_string_buffer(65_536)
        attr = bytearray(144)
        struct.pack_into(
            "=IIQQIIQ",
            attr,
            0,
            self._BPF_PROG_TYPE_TRACEPOINT,
            self._PROGRAM_INSTRUCTIONS,
            ctypes.addressof(instructions),
            ctypes.addressof(license_text),
            1,
            len(verifier_log),
            ctypes.addressof(verifier_log),
        )
        attr[48:64] = b"qpf_sched\0\0\0\0\0\0\0"
        try:
            return self._bpf(self._BPF_PROG_LOAD, attr)
        except HealthError as exc:
            detail = verifier_log.value.decode("utf-8", errors="replace").strip()
            raise HealthError(
                f"cannot load scheduler accounting program: {exc}; {detail}"
            ) from exc

    @classmethod
    def _tracepoint_attr(cls, event_id: int) -> bytearray:
        attr = bytearray(120)
        struct.pack_into(
            "=IIQQQ",
            attr,
            0,
            cls._PERF_TYPE_TRACEPOINT,
            len(attr),
            event_id,
            1,
            1 << 10,
        )
        # disabled=1: no tracepoint may execute before the map is configured.
        struct.pack_into("=Q", attr, 40, 1)
        return attr

    def _attach(self, cpu: int, event_id: int, program_fd: int) -> int:
        attr = self._tracepoint_attr(event_id)
        raw = (ctypes.c_ubyte * len(attr)).from_buffer(attr)
        fd = self._syscall(
            self._perf_syscall,
            ctypes.byref(raw),
            -1,
            cpu,
            -1,
            self._PERF_FLAG_FD_CLOEXEC,
        )
        try:
            fcntl.ioctl(fd, self._PERF_EVENT_IOC_SET_BPF, program_fd)
        except OSError as exc:
            os.close(fd)
            raise HealthError(
                f"cannot attach scheduler accounting on CPU {cpu}: {exc}"
            ) from exc
        return fd

    def _map_update(self, cpu: int, state: bytes) -> None:
        key = ctypes.c_uint32(cpu)
        value = ctypes.create_string_buffer(state)
        attr = bytearray(144)
        struct.pack_into(
            "=I4xQQQ",
            attr,
            0,
            self._map_fd,
            ctypes.addressof(key),
            ctypes.addressof(value),
            0,
        )
        self._bpf(self._BPF_MAP_UPDATE_ELEM, attr)

    def _map_lookup(self, cpu: int) -> tuple[int, int, int, int, int, int]:
        key = ctypes.c_uint32(cpu)
        value = ctypes.create_string_buffer(self._STATE.size)
        attr = bytearray(144)
        struct.pack_into(
            "=I4xQQ",
            attr,
            0,
            self._map_fd,
            ctypes.addressof(key),
            ctypes.addressof(value),
        )
        self._bpf(self._BPF_MAP_LOOKUP_ELEM, attr)
        return self._STATE.unpack(value.raw)

    def arm(self, server_cgroup: Path, client_cgroup: Path) -> None:
        if self._armed:
            raise HealthError("non-owned scheduler clock is already armed")
        try:
            server_id = server_cgroup.stat().st_ino
            client_id = client_cgroup.stat().st_ino
        except OSError as exc:
            raise HealthError(f"cannot identify endpoint cgroups: {exc}") from exc
        if server_id <= 0 or client_id <= 0 or server_id == client_id:
            raise HealthError("endpoint cgroup identities are invalid")
        started = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        for cpu in self.cpus:
            self._map_update(
                cpu,
                self._STATE.pack(server_id, client_id, started, 0, 1, 0),
            )
        try:
            for fd in self._event_fds.values():
                fcntl.ioctl(fd, self._PERF_EVENT_IOC_ENABLE, 0)
        except OSError as exc:
            self._disable()
            raise HealthError(f"cannot arm non-owned scheduler clock: {exc}") from exc
        self._armed = True

    def _disable(self) -> None:
        for fd in self._event_fds.values():
            try:
                fcntl.ioctl(fd, self._PERF_EVENT_IOC_DISABLE, 0)
            except OSError:
                pass
        self._armed = False

    def finish(self) -> dict[int, int]:
        if not self._armed:
            raise HealthError("non-owned scheduler clock is not armed")
        try:
            for fd in self._event_fds.values():
                fcntl.ioctl(fd, self._PERF_EVENT_IOC_DISABLE, 0)
        except OSError as exc:
            self._disable()
            raise HealthError(f"cannot stop non-owned scheduler clock: {exc}") from exc
        self._armed = False
        return {cpu: self._map_lookup(cpu)[3] for cpu in self.cpus}

    def close(self) -> None:
        self._disable()
        for fd in self._event_fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self._event_fds.clear()
        for fd in self._program_fds.values():
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._program_fds.clear()
        if self._map_fd >= 0:
            try:
                os.close(self._map_fd)
            except OSError:
                pass
        self._map_fd = -1

    def __enter__(self) -> "PerCpuNonOwnedClock":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


@dataclass(frozen=True)
class TrialHealthResult:
    thermal_throttle_delta: int
    frequency_min_hz: int
    frequency_max_hz: int
    swap_active: bool
    health_samples: int
    non_owned_cpu_fraction_max: float
    non_owned_cpu_ns: Mapping[int, int]
    device_irq_deltas: Mapping[int, Mapping[int, int]]


class TrialLaneHealth:
    """Own all causal host-health observations for one production trial."""

    def __init__(
        self,
        *,
        server_cpu: int,
        client_cpus: Sequence[int],
        server_cgroup: Path,
        client_cgroup: Path,
        external_thermal_provider: bool = False,
        proc_interrupts: Path = Path("/proc/interrupts"),
    ) -> None:
        self.server_cpu = server_cpu
        self.client_cpus = tuple(client_cpus)
        self.cpus = (server_cpu, *self.client_cpus)
        if len(self.client_cpus) not in {2, 4} or len(set(self.cpus)) != len(self.cpus):
            raise HealthError(
                "trial health requires one server and two or four disjoint client CPUs"
            )
        self.server_cgroup = server_cgroup
        self.client_cgroup = client_cgroup
        self.external_thermal_provider = external_thermal_provider
        self.proc_interrupts = proc_interrupts
        self._non_owned_clock: PerCpuNonOwnedClock | None = None
        self._monitor: LaneHealthMonitor | None = None
        self._irq_before: dict[int, dict[int, int]] = {}
        self._started_raw_ns = 0
        self._result: TrialHealthResult | None = None
        self._endpoints_frozen = False

    def __enter__(self) -> "TrialLaneHealth":
        try:
            self._non_owned_clock = PerCpuNonOwnedClock(self.cpus)
            return self
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _frozen_state(cgroup: Path) -> bool:
        try:
            rows = [
                line.split()
                for line in (cgroup / "cgroup.events")
                .read_text(encoding="ascii")
                .splitlines()
            ]
            if any(len(row) != 2 for row in rows):
                raise ValueError("malformed cgroup.events")
            values = {name: value for name, value in rows}
            if len(values) != len(rows) or values.get("frozen") not in {"0", "1"}:
                raise ValueError("cgroup.events lacks an exact frozen state")
            return values["frozen"] == "1"
        except (OSError, ValueError) as exc:
            raise HealthError(f"cannot read cgroup freeze state for {cgroup}: {exc}") from exc

    def _set_endpoints_frozen(self, frozen: bool) -> None:
        cgroups = (self.server_cgroup, self.client_cgroup)
        value = "1" if frozen else "0"
        try:
            for cgroup in cgroups:
                (cgroup / "cgroup.freeze").write_text(value, encoding="ascii")
            deadline = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) + 25_000_000
            while any(self._frozen_state(cgroup) != frozen for cgroup in cgroups):
                if time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) >= deadline:
                    raise HealthError(
                        f"endpoint cgroups did not become {'frozen' if frozen else 'thawed'}"
                    )
                time.sleep(0.0001)
            self._endpoints_frozen = frozen
        except BaseException:
            recovery_failed = False
            for cgroup in cgroups:
                try:
                    (cgroup / "cgroup.freeze").write_text("0", encoding="ascii")
                except OSError:
                    recovery_failed = True
            self._endpoints_frozen = recovery_failed
            raise

    def arm(self, start_raw_ns: int) -> None:
        if self._started_raw_ns or self._non_owned_clock is None:
            raise HealthError("trial health cannot be armed in its current state")
        self._monitor = (
            LaneHealthMonitor(self.cpus, external_thermal_provider=True)
            if self.external_thermal_provider
            else LaneHealthMonitor(self.cpus)
        )
        self._monitor.start()
        self._set_endpoints_frozen(True)
        try:
            # Snapshot every potentially blocking source before the exact endpoint
            # boundary. The resulting health interval is a conservative superset:
            # any pre-boundary device IRQ or non-owned CPU work is also rejected.
            self._irq_before = read_device_irq_counts(self.cpus, self.proc_interrupts)
            self._non_owned_clock.arm(self.server_cgroup, self.client_cgroup)
        finally:
            self._set_endpoints_frozen(False)
        if time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) > start_raw_ns:
            raise HealthError("host-health baselines completed after interval start")
        # Counters cover a superset beginning before T0, while the denominator
        # begins exactly at T0. Pre-boundary interference can therefore only
        # make the causal gate stricter, and no scheduler wakeup is required.
        self._started_raw_ns = start_raw_ns

    def finish(self) -> TrialHealthResult:
        if self._result is not None:
            return self._result
        if (
            self._started_raw_ns == 0
            or self._monitor is None
            or self._non_owned_clock is None
        ):
            raise HealthError("trial health was not armed")
        self._set_endpoints_frozen(True)
        try:
            summary = self._monitor.stop()
            ended_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            non_owned = self._non_owned_clock.finish()
            irq_after = read_device_irq_counts(self.cpus, self.proc_interrupts)
        finally:
            self._set_endpoints_frozen(False)
        elapsed = ended_raw_ns - self._started_raw_ns
        if elapsed <= 0:
            raise HealthError("trial health interval is nonpositive")
        maximum = max(non_owned.values()) / elapsed
        irq_deltas: dict[int, dict[int, int]] = {}
        for cpu in self.cpus:
            if self._irq_before[cpu].keys() - irq_after[cpu].keys():
                raise HealthError(f"device IRQ rows disappeared for CPU {cpu}")
            deltas = {
                irq: irq_after[cpu][irq] - self._irq_before[cpu].get(irq, 0)
                for irq in irq_after[cpu]
            }
            if any(delta < 0 for delta in deltas.values()):
                raise HealthError(f"device IRQ counter regressed for CPU {cpu}")
            irq_deltas[cpu] = {
                irq: delta for irq, delta in deltas.items() if delta
            }
        self._result = TrialHealthResult(
            thermal_throttle_delta=summary.thermal_throttle_delta,
            frequency_min_hz=summary.frequency_min_hz,
            frequency_max_hz=summary.frequency_max_hz,
            swap_active=summary.swap_active,
            health_samples=summary.samples,
            non_owned_cpu_fraction_max=maximum,
            non_owned_cpu_ns=non_owned,
            device_irq_deltas=irq_deltas,
        )
        return self._result

    def close(self) -> None:
        if self._endpoints_frozen:
            try:
                self._set_endpoints_frozen(False)
            except HealthError:
                pass
        if self._monitor is not None:
            try:
                self._monitor.stop()
            except HealthError:
                pass
        if self._non_owned_clock is not None:
            self._non_owned_clock.close()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        try:
            if exc_type is None and self._started_raw_ns:
                self.finish()
        finally:
            self.close()
