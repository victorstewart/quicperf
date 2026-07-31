from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class TopologyError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class PhysicalCore:
    package: int
    core: int
    cpus: tuple[int, ...]
    numa_node: int

    @property
    def primary_cpu(self) -> int:
        return self.cpus[0]


@dataclass(frozen=True)
class LaneTopology:
    lane: int
    server_cpu: int
    client_cpus: tuple[int, ...]
    housekeeping_cpus: tuple[int, int]

    def all_cpus(self) -> tuple[int, ...]:
        return (self.server_cpu, *self.client_cpus, *self.housekeeping_cpus)


def _read_int(path: Path) -> int:
    return int(path.read_text(encoding="ascii").strip())


def _numa_node(cpu_dir: Path) -> int:
    nodes = sorted(cpu_dir.glob("node[0-9]*"))
    return int(nodes[0].name[4:]) if nodes else 0


def discover_physical_cores(
    sysfs: Path = Path("/sys/devices/system/cpu"),
    *,
    respect_process_affinity: bool = True,
) -> tuple[PhysicalCore, ...]:
    online_text = (sysfs / "online").read_text(encoding="ascii").strip()
    online: set[int] = set()
    for part in online_text.split(","):
        if "-" in part:
            begin, end = map(int, part.split("-", 1))
            online.update(range(begin, end + 1))
        else:
            online.add(int(part))
    if respect_process_affinity:
        # A container or service-level cpuset can expose online CPUs that this
        # process may not use. Such CPUs are not eligible benchmark resources.
        online.intersection_update(os.sched_getaffinity(0))
    if not online:
        raise TopologyError("no online CPUs are available to this process")
    grouped: dict[tuple[int, int], list[int]] = {}
    numa: dict[tuple[int, int], int] = {}
    for cpu in sorted(online):
        cpu_dir = sysfs / f"cpu{cpu}"
        topology = cpu_dir / "topology"
        package = _read_int(topology / "physical_package_id")
        core = _read_int(topology / "core_id")
        key = (package, core)
        grouped.setdefault(key, []).append(cpu)
        numa[key] = _numa_node(cpu_dir)
    return tuple(PhysicalCore(package, core, tuple(cpus), numa[(package, core)]) for (package, core), cpus in sorted(grouped.items()))


def allocate_lanes(
    cores: tuple[PhysicalCore, ...],
    requested_lanes: int,
    *,
    client_cores_per_lane: int = 2,
) -> tuple[LaneTopology, ...]:
    if requested_lanes not in {1, 2}:
        raise TopologyError("publication supports one or two lanes")
    if client_cores_per_lane not in {2, 4}:
        raise TopologyError("a lane treatment supports exactly two or four client cores")
    required = 2 + requested_lanes * (1 + client_cores_per_lane)
    if len(cores) < required:
        raise TopologyError(
            f"{requested_lanes} lane(s) with {client_cores_per_lane} client cores "
            f"per lane require at least {required} physical cores"
        )
    selected = list(cores[:required])
    housekeeping = (selected[0].primary_cpu, selected[1].primary_cpu)
    lanes = []
    offset = 2
    for lane in range(requested_lanes):
        lane_cores = selected[offset : offset + 1 + client_cores_per_lane]
        offset += 1 + client_cores_per_lane
        lanes.append(
            LaneTopology(
                lane,
                lane_cores[0].primary_cpu,
                tuple(core.primary_cpu for core in lane_cores[1:]),
                housekeeping,
            )
        )
    all_benchmark = [cpu for lane in lanes for cpu in (lane.server_cpu, *lane.client_cpus)]
    if len(all_benchmark) != len(set(all_benchmark)) or set(all_benchmark) & set(housekeeping):
        raise TopologyError("lane cores are not disjoint")
    return tuple(lanes)


def swap_is_disabled(proc_swaps: Path = Path("/proc/swaps")) -> bool:
    lines = proc_swaps.read_text(encoding="utf-8").splitlines()
    return len([line for line in lines[1:] if line.strip()]) == 0
