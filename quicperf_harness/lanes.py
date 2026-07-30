from __future__ import annotations

import hashlib
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .topology import LaneTopology


class LaneError(RuntimeError):
    pass


REQUIRED_CGROUP_CONTROLLERS = frozenset({"cpu", "cpuset", "memory", "pids"})
CGROUP_ROOT_ENV = "QUICPERF_CGROUP_ROOT"


def _current_unified_cgroup(
    proc_self_cgroup: Path = Path("/proc/self/cgroup"),
) -> Path:
    try:
        rows = [
            line.split(":", 2)
            for line in proc_self_cgroup.read_text(encoding="ascii").splitlines()
            if line.strip()
        ]
    except OSError as exc:
        raise LaneError(f"cannot read unified cgroup identity: {exc}") from exc
    matches = [row[2] for row in rows if len(row) == 3 and row[0] == "0" and row[1] == ""]
    if len(matches) != 1 or not matches[0].startswith("/"):
        raise LaneError("process has no unique absolute cgroup-v2 identity")
    relative = Path(matches[0].lstrip("/"))
    if ".." in relative.parts:
        raise LaneError("process cgroup identity contains parent traversal")
    return relative


def _checked_cgroup_path(path: Path, mount: Path) -> Path:
    try:
        resolved_mount = mount.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LaneError(f"cannot resolve delegated cgroup path {path}: {exc}") from exc
    if resolved == resolved_mount or not resolved.is_relative_to(resolved_mount):
        raise LaneError("delegated cgroup must be a non-root child of the cgroup-v2 mount")
    return resolved


def delegated_cgroup_root(
    *,
    cgroup_mount: Path = Path("/sys/fs/cgroup"),
    proc_self_cgroup: Path = Path("/proc/self/cgroup"),
    environment: Mapping[str, str] | None = None,
) -> Path:
    """Return the nearest enabled cgroup root delegated to this process."""

    environment = os.environ if environment is None else environment
    current = _checked_cgroup_path(
        cgroup_mount / _current_unified_cgroup(proc_self_cgroup), cgroup_mount
    )
    explicit = environment.get(CGROUP_ROOT_ENV)
    candidates: list[Path]
    if explicit:
        candidates = [_checked_cgroup_path(Path(explicit), cgroup_mount)]
        if not current.is_relative_to(candidates[0]):
            raise LaneError("explicit delegated cgroup does not own the current process")
    else:
        candidates = []
        candidate = current
        while candidate != cgroup_mount:
            candidates.append(candidate)
            candidate = candidate.parent
    observations: list[str] = []
    for candidate in candidates:
        try:
            available = set(
                (candidate / "cgroup.controllers").read_text(encoding="ascii").split()
            )
            enabled = set(
                (candidate / "cgroup.subtree_control")
                .read_text(encoding="ascii")
                .split()
            )
        except OSError as exc:
            observations.append(f"{candidate}:{exc}")
            continue
        missing = REQUIRED_CGROUP_CONTROLLERS - available
        disabled = REQUIRED_CGROUP_CONTROLLERS - enabled
        if not missing and not disabled:
            return candidate
        observations.append(
            f"{candidate}:missing={','.join(sorted(missing)) or '-'}:"
            f"disabled={','.join(sorted(disabled)) or '-'}"
        )
    raise LaneError(
        "no enabled cpu/cpuset/memory/pids delegation owns this process: "
        + "; ".join(observations)
    )


def activate_delegated_controllers(
    root: Path,
    *,
    cgroup_mount: Path = Path("/sys/fs/cgroup"),
    proc_self_cgroup: Path = Path("/proc/self/cgroup"),
) -> None:
    """Enable required controllers in an empty, explicitly delegated unit root."""

    root = _checked_cgroup_path(root, cgroup_mount)
    current = _checked_cgroup_path(
        cgroup_mount / _current_unified_cgroup(proc_self_cgroup), cgroup_mount
    )
    if not current.is_relative_to(root) or current == root:
        raise LaneError("delegated root must be an ancestor of the coordinator subgroup")
    try:
        available = set(
            (root / "cgroup.controllers").read_text(encoding="ascii").split()
        )
        root_processes = (root / "cgroup.procs").read_text(encoding="ascii").split()
    except OSError as exc:
        raise LaneError(f"cannot inspect delegated cgroup root {root}: {exc}") from exc
    missing = REQUIRED_CGROUP_CONTROLLERS - available
    if missing:
        raise LaneError(f"delegated root is missing controllers: {sorted(missing)}")
    if root_processes:
        raise LaneError("delegated root contains processes instead of an ownership subgroup")
    try:
        (root / "cgroup.subtree_control").write_text(
            "+cpu +cpuset +memory +pids", encoding="ascii"
        )
        enabled = set(
            (root / "cgroup.subtree_control").read_text(encoding="ascii").split()
        )
    except OSError as exc:
        raise LaneError(f"cannot enable delegated cgroup controllers: {exc}") from exc
    disabled = REQUIRED_CGROUP_CONTROLLERS - enabled
    if disabled:
        raise LaneError(f"delegated controllers did not activate: {sorted(disabled)}")


@dataclass(frozen=True)
class CgroupLimits:
    cpu_max: str
    memory_max: int = 8_589_934_592
    memory_swap_max: int = 0
    pids_max: int = 1_024


CPU_MAX = "max 100000"
SERVER_LIMITS = CgroupLimits(CPU_MAX)
CLIENT_LIMITS = CgroupLimits(CPU_MAX)


def client_limits(client_cpu_count: int) -> CgroupLimits:
    if client_cpu_count not in {2, 4}:
        raise LaneError("a client cgroup treatment requires exactly two or four CPUs")
    return CLIENT_LIMITS


@dataclass(frozen=True)
class CgroupSnapshot:
    cpu_usage_ns: int
    cpu_throttled_ns: int
    memory_current_bytes: int
    pids_current: int
    memory_peak_bytes: int = 0
    cpu_nr_throttled: int = 0

    def delta(self, earlier: "CgroupSnapshot") -> "CgroupSnapshot":
        fields = {
            "cpu_usage_ns": self.cpu_usage_ns - earlier.cpu_usage_ns,
            "cpu_throttled_ns": self.cpu_throttled_ns - earlier.cpu_throttled_ns,
            "memory_current_bytes": self.memory_current_bytes,
            "pids_current": self.pids_current,
            "memory_peak_bytes": self.memory_peak_bytes,
            "cpu_nr_throttled": self.cpu_nr_throttled - earlier.cpu_nr_throttled,
        }
        if any(value < 0 for value in fields.values()):
            raise LaneError("cgroup counters regressed")
        return CgroupSnapshot(**fields)


def read_cgroup_snapshot(path: Path) -> CgroupSnapshot:
    try:
        cpu_rows = [line.split() for line in (path / "cpu.stat").read_text(encoding="ascii").splitlines()]
        if any(len(row) != 2 for row in cpu_rows):
            raise ValueError("malformed cpu.stat")
        cpu = {name: int(value) for name, value in cpu_rows}
        if len(cpu) != len(cpu_rows) or not {
            "usage_usec", "nr_throttled", "throttled_usec"
        }.issubset(cpu):
            raise ValueError("cpu.stat is missing or duplicates required counters")
        memory = int((path / "memory.current").read_text(encoding="ascii").strip())
        memory_peak = int((path / "memory.peak").read_text(encoding="ascii").strip())
        pids = int((path / "pids.current").read_text(encoding="ascii").strip())
    except (OSError, ValueError) as exc:
        raise LaneError(f"cannot read cgroup telemetry from {path}: {exc}") from exc
    if any(value < 0 for value in (*cpu.values(), memory, memory_peak, pids)):
        raise LaneError("cgroup telemetry counters must be nonnegative")
    return CgroupSnapshot(
        cpu_usage_ns=cpu["usage_usec"] * 1_000,
        cpu_throttled_ns=cpu["throttled_usec"] * 1_000,
        memory_current_bytes=memory,
        pids_current=pids,
        memory_peak_bytes=memory_peak,
        cpu_nr_throttled=cpu["nr_throttled"],
    )


class LaneCgroups:
    def __init__(self, root: Path, topology: LaneTopology):
        self.root = root
        self.topology = topology
        self.created: list[Path] = []
        self.domains: dict[str, Path] = {}
        self.leaves: dict[tuple[str, str], Path] = {}
        self.available_mems = ""

    def _create_leaf(self, role: str, identity: str) -> Path:
        if role not in self.domains or not identity:
            raise LaneError("cgroup leaf requires a created role domain and identity")
        key = (role, identity)
        existing = self.leaves.get(key)
        if existing is not None:
            return existing
        name = (
            "fresh"
            if identity == "fresh"
            else "worker-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        )
        path = self.domains[role] / name
        path.mkdir(parents=False, exist_ok=False)
        self.created.append(path)
        cpus = (
            str(self.topology.server_cpu)
            if role == "server"
            else ",".join(map(str, self.topology.client_cpus))
        )
        limits = (
            SERVER_LIMITS
            if role == "server"
            else client_limits(len(self.topology.client_cpus))
        )
        (path / "cpuset.mems").write_text(self.available_mems, encoding="ascii")
        (path / "cpuset.cpus").write_text(cpus, encoding="ascii")
        (path / "cpu.max").write_text(limits.cpu_max, encoding="ascii")
        (path / "memory.max").write_text(str(limits.memory_max), encoding="ascii")
        (path / "memory.swap.max").write_text(
            str(limits.memory_swap_max), encoding="ascii"
        )
        (path / "pids.max").write_text(str(limits.pids_max), encoding="ascii")
        self.leaves[key] = path
        return path

    def create(self) -> tuple[Path, Path]:
        controllers = (self.root / "cgroup.controllers").read_text(encoding="ascii").split()
        required = set(REQUIRED_CGROUP_CONTROLLERS)
        if not required.issubset(controllers):
            raise LaneError(f"missing cgroup v2 controllers: {sorted(required - set(controllers))}")
        lane = self.root / f"quicperf-v2-lane-{self.topology.lane}-{os.getpid()}"
        lane.mkdir(parents=False, exist_ok=False)
        self.created.append(lane)
        self.available_mems = (
            (self.root / "cpuset.mems.effective")
            .read_text(encoding="ascii")
            .strip()
        )
        if not self.available_mems:
            raise LaneError("root cgroup has no effective NUMA memory nodes")
        (lane / "cgroup.subtree_control").write_text(
            "+cpu +cpuset +memory +pids", encoding="ascii"
        )
        (lane / "cpuset.mems").write_text(self.available_mems, encoding="ascii")
        server = lane / "server"
        client = lane / "client"
        for role, path, cpus in (
            ("server", server, str(self.topology.server_cpu)),
            (
                "client",
                client,
                ",".join(map(str, self.topology.client_cpus)),
            ),
        ):
            path.mkdir(parents=False, exist_ok=False)
            self.created.append(path)
            self.domains[role] = path
            (path / "cpuset.mems").write_text(
                self.available_mems, encoding="ascii"
            )
            (path / "cpuset.cpus").write_text(cpus, encoding="ascii")
            (path / "cgroup.subtree_control").write_text(
                "+cpu +cpuset +memory +pids", encoding="ascii"
            )
        return self._create_leaf("server", "fresh"), self._create_leaf(
            "client", "fresh"
        )

    def create_worker(self, role: str, identity: str) -> Path:
        """Return a stable, treatment-specific leaf below the lane role domain."""

        return self._create_leaf(role, identity)

    @staticmethod
    def reap_stale(root: Path, *, timeout_seconds: float = 5.0) -> tuple[Path, ...]:
        """Reap only dead-coordinator cgroups bearing the exact v2 ownership name."""

        if timeout_seconds <= 0.0:
            raise LaneError("stale cgroup cleanup timeout must be positive")
        pattern = re.compile(r"^quicperf-v2-lane-[0-9]+-([1-9][0-9]*)$")
        reaped: list[Path] = []
        for lane in sorted(root.glob("quicperf-v2-lane-*-*")):
            match = pattern.fullmatch(lane.name)
            if match is None or not lane.is_dir():
                continue
            owner_pid = int(match.group(1))
            try:
                os.kill(owner_pid, 0)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise LaneError(
                    f"cannot attest owner of existing quicperf cgroup {lane}"
                ) from exc
            else:
                raise LaneError(
                    f"quicperf cgroup {lane} still belongs to live coordinator PID {owner_pid}"
                )
            kill = lane / "cgroup.kill"
            if kill.exists():
                try:
                    kill.write_text("1", encoding="ascii")
                except OSError as exc:
                    raise LaneError(f"cannot kill stale cgroup {lane}: {exc}") from exc
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    populated = any(
                        int((child / "pids.current").read_text(encoding="ascii").strip())
                        for child in lane.iterdir()
                        if child.is_dir() and (child / "pids.current").is_file()
                    )
                except (OSError, ValueError) as exc:
                    raise LaneError(f"cannot inspect stale cgroup {lane}: {exc}") from exc
                if not populated:
                    break
                if time.monotonic() >= deadline:
                    raise LaneError(f"stale cgroup remained populated after cleanup: {lane}")
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            try:
                directories = [lane]
                for directory in directories:
                    directories.extend(
                        path for path in directory.iterdir() if path.is_dir()
                    )
                for directory in reversed(directories):
                    directory.rmdir()
            except OSError as exc:
                raise LaneError(f"cannot remove stale cgroup {lane}: {exc}") from exc
            reaped.append(lane)
        return tuple(reaped)

    @staticmethod
    def add_pid(cgroup: Path, pid: int) -> None:
        if pid <= 0:
            raise LaneError("invalid pid")
        (cgroup / "cgroup.procs").write_text(str(pid), encoding="ascii")

    def cleanup(self) -> None:
        for path in reversed(self.created):
            try:
                path.rmdir()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise LaneError(f"cgroup remains populated: {path}") from exc
        self.created.clear()
