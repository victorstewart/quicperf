from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from .canonical import canonical_sha256
from .host_policy import irq_policy_identity
from .manifest import load_manifest
from .model import ExperimentSpecV2, ImmutableIdentityManifest


class ManifestCollectionError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run(root: Path, command: list[str], *, required: bool = True) -> str:
    completed = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if required and completed.returncode != 0:
        raise ManifestCollectionError(f"command failed ({completed.returncode}): {' '.join(command)}: {completed.stderr.strip()}")
    return completed.stdout


def _run_bytes(root: Path, command: list[str], *, required: bool = True) -> bytes:
    completed = subprocess.run(
        command,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if required and completed.returncode != 0:
        raise ManifestCollectionError(
            f"command failed ({completed.returncode}): {' '.join(command)}: "
            f"{completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return completed.stdout


def _source_manifest(root: Path) -> dict[str, Any]:
    commit = _run(root, ["git", "rev-parse", "HEAD"]).strip()
    tracked = [item for item in _run(root, ["git", "ls-files", "-z"]).split("\0") if item]
    tree_digest = hashlib.sha256()
    for relative in sorted(tracked):
        path = root / relative
        if path.is_file():
            name = relative.encode("utf-8")
            content = path.read_bytes()
            tree_digest.update(len(name).to_bytes(8, "big"))
            tree_digest.update(name)
            tree_digest.update(len(content).to_bytes(8, "big"))
            tree_digest.update(content)
    dirty_patch_bytes = _run_bytes(
        root, ["git", "diff", "--binary", "--no-ext-diff", "HEAD", "--"], required=False
    )
    untracked = [item for item in _run(root, ["git", "ls-files", "--others", "--exclude-standard", "-z"]).split("\0") if item]
    for relative in sorted(untracked):
        path = root / relative
        if not path.is_file():
            continue
        dirty_patch_bytes += _run_bytes(
            root,
            ["git", "diff", "--no-index", "--binary", "--no-ext-diff", "--", "/dev/null", relative],
            required=False,
        )
    try:
        dirty_patch = dirty_patch_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ManifestCollectionError("Git binary patch is not valid UTF-8") from exc
    clean = not dirty_patch_bytes
    archive = _run_bytes(root, ["git", "archive", "--format=tar", "HEAD"])
    return {
        "tree_sha256": tree_digest.hexdigest(),
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "git_commit": commit,
        "clean": clean,
        "dirty_patch_sha256": None if clean else hashlib.sha256(dirty_patch_bytes).hexdigest(),
        "dirty_patch": None if clean else dirty_patch,
    }


def _elf_build_id(root: Path, path: Path) -> str:
    output = _run(root, ["readelf", "-n", str(path)], required=False)
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", output)
    return match.group(1).lower() if match else f"sha256:{_sha256(path)}"


def _mapped_elf_identity(root: Path, map_file: Path, displayed_path: str) -> dict[str, str] | None:
    """Hash one mapped inode through procfs, never by reopening its pathname."""

    try:
        fd = os.open(map_file, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        raise ManifestCollectionError(
            f"cannot open race-safe mapped object {map_file}: {exc}"
        ) from exc
    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode):
            return None
        if os.read(fd, 4) != b"\x7fELF":
            return None
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        fd_path = Path(f"/proc/{os.getpid()}/fd/{fd}")
        output = _run(root, ["readelf", "-n", str(fd_path)], required=False)
        match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", output)
        sha256 = digest.hexdigest()
        return {
            "path": displayed_path,
            "sha256": sha256,
            "elf_build_id": match.group(1).lower() if match else f"sha256:{sha256}",
        }
    finally:
        os.close(fd)


def _loaded_libraries(root: Path, binary: Path) -> list[dict[str, str]]:
    output = _run(root, ["ldd", str(binary)], required=False)
    paths: set[Path] = set()
    for line in output.splitlines():
        match = re.search(r"(?:=>\s*)?(/[^ ]+)", line)
        if match:
            path = Path(match.group(1)).resolve()
            if path.is_file():
                paths.add(path)
    return [
        {"path": str(path), "sha256": _sha256(path), "elf_build_id": _elf_build_id(root, path)}
        for path in sorted(paths)
    ]


def mapped_process_libraries(
    root: Path, pid: int, executable: Path
) -> list[dict[str, str]]:
    """Hash the regular ELF objects actually mapped by a live endpoint."""

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ManifestCollectionError("endpoint PID must be a positive integer")
    executable = executable.resolve()
    maps = Path(f"/proc/{pid}/maps")
    try:
        lines = maps.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ManifestCollectionError(f"cannot read live endpoint mappings: {exc}") from exc
    objects: dict[str, dict[str, str]] = {}
    for line in lines:
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or not fields[5].startswith("/"):
            continue
        raw = fields[5]
        if raw.endswith(" (deleted)"):
            raise ManifestCollectionError(f"live endpoint maps a deleted object: {raw}")
        if raw in objects:
            continue
        mapping = fields[0]
        identity = _mapped_elf_identity(
            root, Path(f"/proc/{pid}/map_files/{mapping}"), raw
        )
        if identity is not None:
            objects[raw] = identity
    executable_identity = objects.pop(str(executable), None)
    if executable_identity is None:
        raise ManifestCollectionError("live endpoint executable mapping is missing")
    expected_executable = {
        "path": str(executable),
        "sha256": _sha256(executable),
        "elf_build_id": _elf_build_id(root, executable),
    }
    if executable_identity != expected_executable:
        raise ManifestCollectionError(
            "live endpoint executable inode differs from the frozen binary"
        )
    return [objects[path] for path in sorted(objects)]


def attest_process_libraries(
    root: Path,
    pid: int,
    executable: Path,
    expected: Any,
) -> None:
    actual = mapped_process_libraries(root, pid, executable)
    if actual != [dict(item) for item in expected]:
        expected_paths = [str(item["path"]) for item in expected]
        actual_paths = [str(item["path"]) for item in actual]
        raise ManifestCollectionError(
            "live endpoint library identity differs from the frozen manifest: "
            f"expected={expected_paths}, actual={actual_paths}"
        )


def _binary_manifest(root: Path, spec: ExperimentSpecV2, bin_dir: Path) -> list[dict[str, Any]]:
    servers = set(spec.servers)
    clients = set(spec.reference_clients)
    binaries = []
    for name in sorted(servers | clients):
        path = (bin_dir / name).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ManifestCollectionError(f"configured binary is missing or nonexecutable: {path}")
        role = "server_reference_client" if name in servers and name in clients else ("server" if name in servers else "reference_client")
        binaries.append({
            "name": name,
            "role": role,
            "path": str(path),
            "sha256": _sha256(path),
            "elf_build_id": _elf_build_id(root, path),
            "expected_loaded_libraries": _loaded_libraries(root, path),
        })
    for name, filename in (
        ("quicperf-amd-stability-probe", "quicperf-amd-stability-probe"),
        ("quicperf-monitor-spin", "quicperf-monitor-spin.so"),
    ):
        helper = (bin_dir / filename).resolve()
        if not helper.is_file() or not os.access(helper, os.X_OK):
            raise ManifestCollectionError(
                f"configured coordinator helper is missing or nonexecutable: {helper}"
            )
        binaries.append(
            {
                "name": name,
                "role": "coordinator",
                "path": str(helper),
                "sha256": _sha256(helper),
                "elf_build_id": _elf_build_id(root, helper),
                "expected_loaded_libraries": _loaded_libraries(root, helper),
            }
        )
    binaries.sort(key=lambda entry: str(entry["name"]))
    return binaries


def _dependencies(root: Path) -> list[dict[str, str | None]]:
    dependencies = []
    for path in sorted((root / "depofiles").glob("*.DepoFile")):
        text = path.read_text(encoding="utf-8")
        match = re.search(r"^VERSION\s+([^\s]+)", text, re.MULTILINE)
        dependencies.append({
            "name": path.stem,
            "revision": match.group(1) if match else "content-addressed",
            "content_sha256": _sha256(path),
            "lockfile_sha256": None,
        })
    for name, path in (
        ("rust-packet-ffi-lock", root / "rust-packet-ffi" / "Cargo.lock"),
        ("zig-packet-ffi-lock", root / "zig-packet-ffi" / "build.zig.zon"),
    ):
        if path.is_file():
            dependencies.append({
                "name": name,
                "revision": "lockfile",
                "content_sha256": _sha256(path),
                "lockfile_sha256": _sha256(path),
            })
    return dependencies


def _build_policy_flags(
    root: Path, build_dir: Path, spec: ExperimentSpecV2
) -> dict[str, tuple[list[str], list[str]]]:
    compile_flags: list[str] = []
    link_flags: list[str] = []
    for binary in sorted(set(spec.servers) | set(spec.reference_clients)):
        flags_path = build_dir / "CMakeFiles" / f"{binary}.dir" / "flags.make"
        link_path = build_dir / "CMakeFiles" / f"{binary}.dir" / "link.txt"
        if not flags_path.is_file() or not link_path.is_file():
            raise ManifestCollectionError(f"configured build policy is missing for {binary}")
        for line in flags_path.read_text(encoding="utf-8").splitlines():
            if line.startswith(("CXX_FLAGS =", "C_FLAGS =")):
                compile_flags.extend(shlex.split(line.split("=", 1)[1]))
        link_flags.extend(shlex.split(link_path.read_text(encoding="utf-8")))
    rust_build = build_dir / "CMakeFiles" / "quicperf_rust_packet_ffi_build.dir" / "build.make"
    zig_build = build_dir / "CMakeFiles" / "quicperf_zig_packet_ffi_build.dir" / "build.make"
    rust_line = next((line.strip() for line in rust_build.read_text(encoding="utf-8").splitlines() if "cargo build --release" in line), "") if rust_build.is_file() else ""
    zig_line = next((line.strip() for line in zig_build.read_text(encoding="utf-8").splitlines() if "zig build" in line), "") if zig_build.is_file() else ""
    zig_tokens = shlex.split(zig_line)
    zig_source = root / "zig-packet-ffi" / "src" / "lib.zig"
    if zig_source.is_file() and "std.heap.c_allocator" in zig_source.read_text(encoding="utf-8"):
        zig_tokens.append("allocator=c_allocator")
    rust_tokens = shlex.split(rust_line)
    if "CARGO_INCREMENTAL=0" in rust_line:
        rust_tokens.append("incremental=false")
    return {
        "c++": (sorted(set(compile_flags)), link_flags),
        "rustc": (rust_tokens, []),
        "zig": (zig_tokens, []),
        "python": ([], []),
    }


def _toolchains(
    root: Path, build_dir: Path, spec: ExperimentSpecV2
) -> list[dict[str, Any]]:
    policy = {
        "c++": (["c++", "--version"], ["-O3", "-DNDEBUG", "-march=native", "-mtune=native", "-flto=auto"], ["-flto=auto"]),
        "rustc": (["rustc", "--version", "--verbose"], ["opt-level=3", "lto=fat", "codegen-units=1", "panic=abort", "debug=0", "incremental=false", "target-cpu=native"], ["lto=fat"]),
        "zig": (["zig", "version"], ["ReleaseFast", "cpu=native", "allocator=c_allocator"], []),
        "python": ([sys.executable, "--version"], [], []),
    }
    observed_policy = _build_policy_flags(root, build_dir, spec)
    result = []
    for name, (command, compile_flags, link_flags) in policy.items():
        executable = shutil.which(command[0])
        if executable is None:
            raise ManifestCollectionError(f"required toolchain is missing: {command[0]}")
        observed_compile, observed_link = observed_policy[name]
        if spec.raw["manifest_policy"]["require_release_policy"]:
            missing = [
                flag for flag in compile_flags
                if not any(
                    flag == token or flag.lower() in token.lower().replace("_", "-")
                    for token in observed_compile
                )
            ]
            if missing:
                raise ManifestCollectionError(
                    f"effective {name} build policy is missing: {', '.join(missing)}"
                )
        result.append({
            "name": name,
            "version": _run(root, [executable, *command[1:]]).splitlines()[0],
            "executable_sha256": _sha256(Path(executable).resolve()),
            "effective_compile_flags": observed_compile,
            "effective_link_flags": observed_link,
        })
    return result


def _read_first(paths: list[Path], default: str) -> str:
    for path in paths:
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return default


def _turbo_enabled(cpu_sysfs: Path = Path("/sys/devices/system/cpu")) -> bool:
    """Read Intel no_turbo and generic AMD/ACPI boost controls fail-closed."""

    states: list[bool] = []
    no_turbo = _read_first([cpu_sysfs / "intel_pstate/no_turbo"], "unavailable")
    if no_turbo in {"0", "1"}:
        states.append(no_turbo == "0")
    boost = _read_first([cpu_sysfs / "cpufreq/boost"], "unavailable")
    if boost in {"0", "1"}:
        states.append(boost == "1")
    return any(states) if states else True


def _host_policy(spec: ExperimentSpecV2) -> dict[str, Any]:
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    def cpu_value(label: str, default: str = "unknown") -> str:
        match = re.search(rf"^{re.escape(label)}\s*:\s*(.+)$", cpuinfo, re.MULTILINE)
        return match.group(1).strip() if match else default

    from .topology import TopologyError, allocate_lanes, discover_physical_cores

    cores = discover_physical_cores()
    resources = spec.raw["treatment"]["resources"]
    client_cores = int(resources["client_physical_cores"])
    requested_lanes = (
        1
        if spec.raw["schedule"]["lane_assignment"] == "single_lane"
        else 2
    )
    try:
        lanes = allocate_lanes(
            cores,
            requested_lanes,
            client_cores_per_lane=client_cores,
        )
    except TopologyError:
        if requested_lanes == 1:
            raise
        lanes = allocate_lanes(
            cores,
            1,
            client_cores_per_lane=client_cores,
        )
    topology = [
        {"package": core.package, "core": core.core, "cpus": core.cpus, "numa_node": core.numa_node}
        for core in cores
    ]
    governors = sorted({_read_first([path], "unavailable") for path in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_governor")})
    epps = sorted({_read_first([path], "unavailable") for path in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/energy_performance_preference")})
    frequency_minima = sorted({_read_first([path], "unavailable") for path in Path("/sys/devices/system/cpu/cpufreq").glob("policy[0-9]*/scaling_min_freq")})
    frequency_maxima = sorted({_read_first([path], "unavailable") for path in Path("/sys/devices/system/cpu/cpufreq").glob("policy[0-9]*/scaling_max_freq")})
    governor = governors[0] if len(governors) == 1 else "mixed:" + ",".join(governors) if governors else "unavailable"
    epp = epps[0] if len(epps) == 1 else "mixed:" + ",".join(epps) if epps else "unavailable"
    frequency_min_khz = frequency_minima[0] if len(frequency_minima) == 1 else "mixed:" + ",".join(frequency_minima) if frequency_minima else "unavailable"
    frequency_max_khz = frequency_maxima[0] if len(frequency_maxima) == 1 else "mixed:" + ",".join(frequency_maxima) if frequency_maxima else "unavailable"
    lane_layout = [
        {
            "lane": lane.lane,
            "server_cpu": lane.server_cpu,
            "client_cpus": list(lane.client_cpus),
            "housekeeping_cpus": list(lane.housekeeping_cpus),
        }
        for lane in lanes
    ]
    return {
        "kernel_release": platform.release(),
        "microcode": cpu_value("microcode"),
        "cpu_model": cpu_value("model name"),
        "cpu_stepping": cpu_value("stepping"),
        "topology": topology,
        "topology_sha256": canonical_sha256(topology),
        "numa_sha256": canonical_sha256(_read_first([Path("/sys/devices/system/node/online")], "0")),
        "clocksource": _read_first([Path("/sys/devices/system/clocksource/clocksource0/current_clocksource")], "unknown"),
        "cgroup_mode": "v2" if Path("/sys/fs/cgroup/cgroup.controllers").is_file() else "unavailable",
        "smt_policy": "no_overlap",
        "governor": governor,
        "epp": epp,
        "frequency_min_khz": frequency_min_khz,
        "frequency_max_khz": frequency_max_khz,
        "turbo": _turbo_enabled(),
        "irq_affinity_sha256": canonical_sha256(irq_policy_identity()),
        "offloads_sha256": canonical_sha256(dict(spec.raw["treatment"]["socket"])),
        "sysctls_sha256": canonical_sha256({"rmem": _read_first([Path("/proc/sys/net/core/rmem_max")], "unknown"), "wmem": _read_first([Path("/proc/sys/net/core/wmem_max")], "unknown")}),
        "socket_policy_sha256": canonical_sha256(dict(spec.raw["treatment"]["socket"])),
        "lane_layout": lane_layout,
        "lane_layout_sha256": canonical_sha256(lane_layout),
    }


def collect_manifest(root: Path, spec: ExperimentSpecV2, *, bin_dir: Path | None = None) -> ImmutableIdentityManifest:
    root = root.resolve()
    bin_dir = (bin_dir or root / "build" / "bin").resolve()
    path_profiles = []
    for path in spec.raw["paths"]:
        content = dict(path)
        content.pop("content_hash")
        path_profiles.append({"name": path["name"], "content_hash": path["content_hash"], "content": content})
    capabilities = {"servers": spec.servers, "clients": spec.reference_clients, "scenarios": spec.scenarios, "backends": spec.server_backends}
    manifest = {
        "schema_version": "quicperf.manifest.v2",
        "source": _source_manifest(root),
        "binaries": _binary_manifest(root, spec, bin_dir),
        "dependencies": _dependencies(root),
        "toolchains": _toolchains(root, bin_dir.parent, spec),
        "protocols": {
            "adapter_abi_version": "2",
            "control_protocol_version": "1",
            "workload_protocol_version": "QPF2-1",
            "capability_schema_version": "2",
            "adapter_capabilities_sha256": canonical_sha256(capabilities),
        },
        "host_policy": _host_policy(spec),
        "path_profiles": path_profiles,
    }
    return load_manifest(manifest)
