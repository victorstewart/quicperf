"""Immutable source/build/binary/host-policy manifest validation."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any, NoReturn

from .canonical import canonical_sha256, load_strict, loads_strict
from .errors import ManifestValidationError
from .identity import identity_manifest_hash
from .model import ImmutableIdentityManifest, freeze_json


SCHEMA_VERSION = "quicperf.manifest.v2"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40,64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
BUILD_ID = re.compile(r"^(?:[0-9a-f]{2})+$")
TOP = {"schema_version", "source", "binaries", "dependencies", "toolchains", "protocols", "host_policy", "path_profiles"}


def _fail(path: str, message: str) -> NoReturn:
    raise ManifestValidationError(f"{path}: {message}")


def _object(value: Any, path: str, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(path, "must be an object")
    missing, unknown = fields - set(value), set(value) - fields
    if missing:
        _fail(path, f"missing fields: {', '.join(sorted(missing))}")
    if unknown:
        _fail(path, f"unknown fields: {', '.join(sorted(unknown))}")
    return value


def _array(value: Any, path: str, *, empty_ok: bool = False) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)) or (not value and not empty_ok):
        _fail(path, "must be a non-empty array" if not empty_ok else "must be an array")
    return tuple(value)


def _string(value: Any, path: str, *, empty_ok: bool = False) -> str:
    if not isinstance(value, str) or (not value and not empty_ok):
        _fail(path, "must be a string")
    if "\x00" in value or value.strip() != value:
        _fail(path, "contains forbidden whitespace or NUL")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail(path, "must be valid UTF-8 text")
    return value


def _digest(value: Any, path: str) -> str:
    text = _string(value, path)
    if not SHA256.fullmatch(text):
        _fail(path, "must be a lowercase full SHA-256 digest")
    return text


def _path(value: Any, path: str) -> str:
    text = _string(value, path)
    if ".." in PurePosixPath(text).parts or "//" in text or text.endswith("/"):
        _fail(path, "must be normalized and contain no parent traversal")
    return text


def _identifier(value: Any, path: str) -> str:
    text = _string(value, path)
    if not IDENTIFIER.fullmatch(text):
        _fail(path, "must be a canonical identifier")
    return text


def _nonnegative_int(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(path, "must be a nonnegative integer")
    return value


def _unique(items: tuple[Mapping[str, Any], ...], key: str, path: str) -> None:
    values = [item[key] for item in items]
    if len(values) != len(set(values)):
        _fail(path, f"duplicate {key}")


def validate_manifest(data: Any) -> ImmutableIdentityManifest:
    root = _object(data, "$", TOP)
    if root["schema_version"] != SCHEMA_VERSION:
        _fail("$.schema_version", f"must equal {SCHEMA_VERSION!r}")
    source = _object(root["source"], "$.source", {
        "tree_sha256", "archive_sha256", "git_commit", "clean", "dirty_patch_sha256", "dirty_patch",
    })
    _digest(source["tree_sha256"], "$.source.tree_sha256")
    _digest(source["archive_sha256"], "$.source.archive_sha256")
    commit = _string(source["git_commit"], "$.source.git_commit")
    if not GIT_COMMIT.fullmatch(commit):
        _fail("$.source.git_commit", "must be a full Git object ID")
    if not isinstance(source["clean"], bool):
        _fail("$.source.clean", "must be a boolean")
    if source["clean"]:
        if source["dirty_patch_sha256"] is not None or source["dirty_patch"] is not None:
            _fail("$.source", "clean manifests cannot contain a dirty patch")
    else:
        _digest(source["dirty_patch_sha256"], "$.source.dirty_patch_sha256")
        patch = source["dirty_patch"]
        if not isinstance(patch, str) or not patch or "\x00" in patch:
            _fail("$.source.dirty_patch", "must be non-empty UTF-8 text without NUL")
        try:
            patch.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            _fail("$.source.dirty_patch", "must be valid UTF-8 text")
        if hashlib.sha256(patch.encode("utf-8")).hexdigest() != source["dirty_patch_sha256"]:
            _fail("$.source.dirty_patch_sha256", "does not match exact dirty patch bytes")

    binaries: list[Mapping[str, Any]] = []
    for index, value in enumerate(_array(root["binaries"], "$.binaries")):
        path = f"$.binaries[{index}]"
        item = _object(value, path, {"name", "role", "path", "sha256", "elf_build_id", "expected_loaded_libraries"})
        _identifier(item["name"], f"{path}.name")
        if item["role"] not in {"server", "reference_client", "server_reference_client", "coordinator", "path_controller"}:
            _fail(f"{path}.role", "invalid binary role")
        _path(item["path"], f"{path}.path")
        _digest(item["sha256"], f"{path}.sha256")
        build_id = _string(item["elf_build_id"], f"{path}.elf_build_id")
        if not BUILD_ID.fullmatch(build_id):
            _fail(f"{path}.elf_build_id", "must be a non-empty even-length lowercase hex build ID")
        libraries = []
        for lib_index, lib_value in enumerate(_array(item["expected_loaded_libraries"], f"{path}.expected_loaded_libraries", empty_ok=True)):
            lib_path = f"{path}.expected_loaded_libraries[{lib_index}]"
            lib = _object(lib_value, lib_path, {"path", "sha256", "elf_build_id"})
            _path(lib["path"], f"{lib_path}.path")
            _digest(lib["sha256"], f"{lib_path}.sha256")
            lib_build_id = _string(lib["elf_build_id"], f"{lib_path}.elf_build_id")
            if not BUILD_ID.fullmatch(lib_build_id):
                _fail(f"{lib_path}.elf_build_id", "must be a non-empty even-length lowercase hex build ID")
            libraries.append(lib)
        if len({lib["path"] for lib in libraries}) != len(libraries):
            _fail(f"{path}.expected_loaded_libraries", "contains duplicate paths")
        binaries.append(item)
    _unique(tuple(binaries), "name", "$.binaries")

    dependencies: list[Mapping[str, Any]] = []
    for index, value in enumerate(_array(root["dependencies"], "$.dependencies")):
        path = f"$.dependencies[{index}]"
        item = _object(value, path, {"name", "revision", "content_sha256", "lockfile_sha256"})
        _identifier(item["name"], f"{path}.name")
        _string(item["revision"], f"{path}.revision")
        _digest(item["content_sha256"], f"{path}.content_sha256")
        if item["lockfile_sha256"] is not None:
            _digest(item["lockfile_sha256"], f"{path}.lockfile_sha256")
        dependencies.append(item)
    _unique(tuple(dependencies), "name", "$.dependencies")

    toolchains: list[Mapping[str, Any]] = []
    for index, value in enumerate(_array(root["toolchains"], "$.toolchains")):
        path = f"$.toolchains[{index}]"
        item = _object(value, path, {"name", "version", "executable_sha256", "effective_compile_flags", "effective_link_flags"})
        _identifier(item["name"], f"{path}.name")
        _string(item["version"], f"{path}.version")
        _digest(item["executable_sha256"], f"{path}.executable_sha256")
        for field in ("effective_compile_flags", "effective_link_flags"):
            for flag_index, flag in enumerate(_array(item[field], f"{path}.{field}", empty_ok=True)):
                _string(flag, f"{path}.{field}[{flag_index}]")
        toolchains.append(item)
    _unique(tuple(toolchains), "name", "$.toolchains")

    protocols = _object(root["protocols"], "$.protocols", {
        "adapter_abi_version", "control_protocol_version", "workload_protocol_version",
        "capability_schema_version", "adapter_capabilities_sha256",
    })
    for field in ("adapter_abi_version", "control_protocol_version", "workload_protocol_version", "capability_schema_version"):
        _string(protocols[field], f"$.protocols.{field}")
    _digest(protocols["adapter_capabilities_sha256"], "$.protocols.adapter_capabilities_sha256")

    host = _object(root["host_policy"], "$.host_policy", {
        "kernel_release", "microcode", "cpu_model", "cpu_stepping", "topology_sha256",
        "numa_sha256", "clocksource", "cgroup_mode", "smt_policy", "governor", "epp",
        "frequency_min_khz", "frequency_max_khz", "turbo", "irq_affinity_sha256", "offloads_sha256", "sysctls_sha256",
        "socket_policy_sha256", "lane_layout_sha256", "topology", "lane_layout",
    })
    for field in ("kernel_release", "microcode", "cpu_model", "cpu_stepping", "clocksource",
                  "cgroup_mode", "smt_policy", "governor", "epp"):
        _string(host[field], f"$.host_policy.{field}")
    for field in ("frequency_min_khz", "frequency_max_khz"):
        value = _string(host[field], f"$.host_policy.{field}")
        if not value.isdecimal() or int(value) <= 0:
            _fail(f"$.host_policy.{field}", "must be a positive decimal kHz value")
    if not isinstance(host["turbo"], bool):
        _fail("$.host_policy.turbo", "must be a boolean")
    for field in ("topology_sha256", "numa_sha256", "irq_affinity_sha256", "offloads_sha256",
                  "sysctls_sha256", "socket_policy_sha256", "lane_layout_sha256"):
        _digest(host[field], f"$.host_policy.{field}")
    topology = []
    for index, value in enumerate(_array(host["topology"], "$.host_policy.topology")):
        path = f"$.host_policy.topology[{index}]"
        item = _object(value, path, {"package", "core", "cpus", "numa_node"})
        for field in ("package", "core", "numa_node"):
            _nonnegative_int(item[field], f"{path}.{field}")
        cpus = tuple(
            _nonnegative_int(cpu, f"{path}.cpus[{cpu_index}]")
            for cpu_index, cpu in enumerate(_array(item["cpus"], f"{path}.cpus"))
        )
        if len(cpus) != len(set(cpus)):
            _fail(f"{path}.cpus", "contains duplicate CPU IDs")
        topology.append(item)
    if canonical_sha256(topology) != host["topology_sha256"]:
        _fail("$.host_policy.topology_sha256", "does not match canonical topology")
    lanes = []
    for index, value in enumerate(_array(host["lane_layout"], "$.host_policy.lane_layout")):
        path = f"$.host_policy.lane_layout[{index}]"
        item = _object(value, path, {"lane", "server_cpu", "client_cpus", "housekeeping_cpus"})
        _nonnegative_int(item["lane"], f"{path}.lane")
        _nonnegative_int(item["server_cpu"], f"{path}.server_cpu")
        for field in ("client_cpus", "housekeeping_cpus"):
            values = tuple(
                _nonnegative_int(cpu, f"{path}.{field}[{cpu_index}]")
                for cpu_index, cpu in enumerate(_array(item[field], f"{path}.{field}"))
            )
            allowed_lengths = {2, 4} if field == "client_cpus" else {2}
            if len(values) not in allowed_lengths or len(values) != len(set(values)):
                expected = "two or four" if field == "client_cpus" else "two"
                _fail(
                    f"{path}.{field}",
                    f"must contain exactly {expected} distinct CPU IDs",
                )
        lanes.append(item)
    client_widths = {len(tuple(item["client_cpus"])) for item in lanes}
    if len(client_widths) > 1:
        _fail(
            "$.host_policy.lane_layout",
            "all lanes must use the same client CPU cardinality",
        )
    if canonical_sha256(lanes) != host["lane_layout_sha256"]:
        _fail("$.host_policy.lane_layout_sha256", "does not match canonical lane layout")

    path_profiles: list[Mapping[str, Any]] = []
    for index, value in enumerate(_array(root["path_profiles"], "$.path_profiles")):
        path = f"$.path_profiles[{index}]"
        item = _object(value, path, {"name", "content_hash", "content"})
        _identifier(item["name"], f"{path}.name")
        _digest(item["content_hash"], f"{path}.content_hash")
        if not isinstance(item["content"], Mapping):
            _fail(f"{path}.content", "must be an object")
        if canonical_sha256(item["content"]) != item["content_hash"]:
            _fail(f"{path}.content_hash", "does not match canonical path-profile content")
        path_profiles.append(item)
    _unique(tuple(path_profiles), "name", "$.path_profiles")

    frozen = freeze_json(root)
    assert isinstance(frozen, Mapping)
    return ImmutableIdentityManifest(
        SCHEMA_VERSION,
        freeze_json(source),
        tuple(freeze_json(item) for item in binaries),
        tuple(freeze_json(item) for item in dependencies),
        tuple(freeze_json(item) for item in toolchains),
        freeze_json(protocols),
        freeze_json(host),
        tuple(freeze_json(item) for item in path_profiles),
        frozen,
    )


def load_manifest(source: str | bytes | bytearray | Path | Mapping[str, Any]) -> ImmutableIdentityManifest:
    if isinstance(source, Mapping):
        data = source
    elif isinstance(source, Path):
        data = load_strict(source)
    elif isinstance(source, (bytes, bytearray)):
        data = loads_strict(source)
    elif isinstance(source, str):
        stripped = source.lstrip()
        data = loads_strict(source) if stripped.startswith("{") else load_strict(source)
    else:
        _fail("$", "manifest source must be a mapping, JSON document, or path")
    return validate_manifest(data)


def manifest_hash(manifest: ImmutableIdentityManifest) -> str:
    return identity_manifest_hash(manifest.raw)
