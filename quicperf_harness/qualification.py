"""Deterministic qualification gates and reusable decision artifacts.

Physical qualification runners produce the evidence consumed here.  This module
does not execute benchmark trials and its artifacts are decisions, never sample
inputs.  Every evaluator fails closed on missing, duplicate, or malformed
evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import errno
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Callable, Mapping, Sequence, TypeVar

from .canonical import canonical_bytes, loads_strict
from .errors import InvalidConfigurationError
from .identity import analysis_plan_hash, domain_hash, spec_hash
from .model import ExperimentSpecV2, ImmutableIdentityManifest
from .tail_window import (
    DURATION_LADDER_SECONDS,
    HELD_OUT_SIGN_PATTERNS,
    TailHeldOutBlock,
    TailScreenCell,
    analyze_tail_window_qualification,
)


ARTIFACT_SCHEMA_VERSION = 1
ARTIFACT_KINDS = frozenset(
    {
        "worker-reuse",
        "host-stability",
        "lane-interference",
        "client-headroom",
        "window-qualification",
        "tail-window",
    }
)
WORKER_SENTINELS = (
    "multistream_download",
    "reqresp",
    "datagram",
    "loss_recovery",
)
WORKER_FRESH_PROCESS_SCENARIOS = frozenset(
    {"connect", "resumed_connect", "zero_rtt_reqresp", "memory_curve"}
)


def worker_reuse_eligible_scenario(scenario: str) -> bool:
    return scenario not in WORKER_FRESH_PROCESS_SCENARIOS


HEADROOM_SCENARIOS = (
    "multistream_download",
    "small_payload_pps",
    "datagram",
)
LANE_DIMENSIONS = {
    "combined_endpoint_cpu": "reqresp",
    "udp_packet_rate": "datagram",
    "validated_byte_rate": "multistream_download",
    "timer_recovery_wakeups": "loss_recovery",
}

COMMON_IDENTITY_FIELDS = frozenset(
    {
        "binary_hashes",
        "dependency_hashes",
        "source_hash",
        "host_policy_hash",
        "profile_hash",
        "analysis_plan_hash",
    }
)
REQUIRED_IDENTITY_FIELDS = {
    "host-stability": COMMON_IDENTITY_FIELDS
    | {
        "provider_policy_hash",
        "boot_id_hash",
    },
    "worker-reuse": COMMON_IDENTITY_FIELDS
    | {
        "packet_protocol_hash",
        "workload_protocol_hash",
        "control_protocol_hash",
        "reset_protocol_hash",
    },
    "lane-interference": COMMON_IDENTITY_FIELDS
    | {
        "packet_protocol_hash",
        "workload_protocol_hash",
        "control_protocol_hash",
    },
    "client-headroom": COMMON_IDENTITY_FIELDS
    | {
        "packet_protocol_hash",
        "workload_protocol_hash",
        "control_protocol_hash",
    },
    "window-qualification": {
        "adapter_binary_hashes",
        "library_hashes",
        "build_hash",
        "driver_hash",
        "workload_protocol_hash",
        "control_protocol_hash",
        "payload_policy_hash",
        "window_policy_hash",
        "resource_policy_hash",
        "path_policy_hash",
        "host_kernel_microcode_hash",
        "source_hash",
        "profile_hash",
        "analysis_plan_hash",
    },
    "tail-window": {
        "adapter_binary_hashes",
        "library_hashes",
        "build_hash",
        "driver_hash",
        "workload_protocol_hash",
        "control_protocol_hash",
        "payload_policy_hash",
        "window_policy_hash",
        "tail_window_policy_hash",
        "resource_policy_hash",
        "path_policy_hash",
        "host_kernel_microcode_hash",
        "source_hash",
        "profile_hash",
        "analysis_plan_hash",
    },
}

_HASH_TEXT_FIELDS = frozenset(
    field
    for fields in REQUIRED_IDENTITY_FIELDS.values()
    for field in fields
    if field.endswith("_hash")
)
_HASH_MAP_FIELDS = frozenset(
    field
    for fields in REQUIRED_IDENTITY_FIELDS.values()
    for field in fields
    if field.endswith("_hashes")
)


class QualificationError(InvalidConfigurationError):
    """Qualification evidence or a reusable artifact is invalid."""


class QualificationArtifactBusyError(QualificationError):
    """Another writer may be producing the same identity-bound artifact."""


@dataclass(frozen=True)
class QualificationDecision:
    kind: str
    status: str
    reasons: tuple[str, ...]
    evidence: Mapping[str, Any]

    @property
    def qualified(self) -> bool:
        return self.status == "qualified"


@dataclass(frozen=True)
class StoredQualificationArtifact:
    path: Path
    artifact_hash: str
    identity_hash: str
    decision: QualificationDecision


def build_qualification_identity(
    kind: str,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
) -> dict[str, Any]:
    """Derive a reusable gate identity only from frozen campaign inputs."""

    _require_kind(kind)
    binaries = {str(item["name"]): str(item["sha256"]) for item in manifest.binaries}
    dependencies = {
        str(item["name"]): domain_hash("qualification-dependency", canonical_bytes(item))
        for item in manifest.dependencies
    }
    protocols = manifest.protocols
    common = {
        "binary_hashes": binaries,
        "dependency_hashes": dependencies,
        "source_hash": domain_hash(
            "qualification-source", canonical_bytes(manifest.source)
        ),
        "host_policy_hash": domain_hash(
            "qualification-host-policy", canonical_bytes(manifest.host_policy)
        ),
        "profile_hash": spec_hash(spec.raw),
        "analysis_plan_hash": analysis_plan_hash(spec.raw["analysis"]),
        "packet_protocol_hash": domain_hash(
            "qualification-packet-protocol",
            canonical_bytes(
                {
                    "adapter_abi_version": protocols["adapter_abi_version"],
                    "capability_schema_version": protocols["capability_schema_version"],
                    "adapter_capabilities_sha256": protocols[
                        "adapter_capabilities_sha256"
                    ],
                }
            ),
        ),
        "workload_protocol_hash": domain_hash(
            "qualification-workload-protocol",
            canonical_bytes(protocols["workload_protocol_version"]),
        ),
        "control_protocol_hash": domain_hash(
            "qualification-control-protocol",
            canonical_bytes(protocols["control_protocol_version"]),
        ),
    }
    if kind == "host-stability":
        policy_path = (
            Path(__file__).resolve().parents[1]
            / "profiles/v2/host-stability/amd-delivered-performance-v1.json"
        )
        try:
            policy_content = policy_path.read_bytes()
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError as exc:
            raise QualificationError(
                f"host-stability identity input is unavailable: {exc}"
            ) from exc
        if not boot_id:
            raise QualificationError("host-stability boot identity is empty")
        common["provider_policy_hash"] = domain_hash(
            "qualification-host-stability-policy", policy_content
        )
        common["boot_id_hash"] = domain_hash(
            "qualification-host-stability-boot", boot_id.encode("ascii")
        )
        validate_qualification_identity(kind, common)
        return common
    if kind not in {"window-qualification", "tail-window"}:
        if kind == "worker-reuse":
            common["reset_protocol_hash"] = domain_hash(
                "qualification-reset-protocol",
                bytes.fromhex(common["packet_protocol_hash"]),
                bytes.fromhex(common["workload_protocol_hash"]),
                b"QPF2-reset-v1",
            )
        validate_qualification_identity(kind, common)
        return common

    libraries: dict[str, str] = {}
    for binary in manifest.binaries:
        for library in binary["expected_loaded_libraries"]:
            name = str(library["path"])
            digest = str(library["sha256"])
            previous = libraries.setdefault(name, digest)
            if previous != digest:
                raise QualificationError(
                    f"loaded library {name!r} has conflicting frozen hashes"
                )
    workloads = [dict(workload) for workload in spec.raw["workloads"]]
    payload_fields = {
        "scenario",
        "connections",
        "streams_per_connection",
        "request_body_bytes",
        "response_body_bytes",
        "message_body_bytes",
        "datagram_body_bytes",
        "application_chunk_bytes",
        "operation_slots",
        "ticket_chains",
        "eligible_operation_limit",
        "datagram_unreturned_per_connection",
        "datagram_unreturned_aggregate",
    }
    payload_policy = [
        {field: workload[field] for field in sorted(payload_fields)} for workload in workloads
    ]
    window_policy = [
        {
            "scenario": workload["scenario"],
            "path_profile": workload["path_profile"],
            "measurement_ns": workload["measurement_ns"],
            "warmup_ns": workload["warmup_ns"],
            "connection_window_bytes": workload["connection_window_bytes"],
            "stream_window_bytes": workload["stream_window_bytes"],
        }
        for workload in workloads
    ]
    host = manifest.host_policy
    identity = {
        "adapter_binary_hashes": binaries,
        "library_hashes": libraries or {"statically_linked": domain_hash(
            "qualification-static-libraries", canonical_bytes(manifest.dependencies)
        )},
        "build_hash": domain_hash(
            "qualification-build",
            canonical_bytes(manifest.source),
            canonical_bytes(manifest.toolchains),
            canonical_bytes(manifest.dependencies),
        ),
        "driver_hash": domain_hash(
            "qualification-driver",
            bytes.fromhex(common["packet_protocol_hash"]),
            canonical_bytes(spec.raw["treatment"]["socket"]),
        ),
        "workload_protocol_hash": common["workload_protocol_hash"],
        "control_protocol_hash": common["control_protocol_hash"],
        "payload_policy_hash": domain_hash(
            "qualification-payload-policy", canonical_bytes(payload_policy)
        ),
        "window_policy_hash": domain_hash(
            "qualification-window-policy", canonical_bytes(window_policy)
        ),
        "resource_policy_hash": domain_hash(
            "qualification-resource-policy",
            canonical_bytes(spec.raw["treatment"]["resources"]),
        ),
        "path_policy_hash": domain_hash(
            "qualification-path-policy", canonical_bytes(manifest.path_profiles)
        ),
        "host_kernel_microcode_hash": domain_hash(
            "qualification-host-kernel-microcode",
            canonical_bytes(
                {
                    "kernel_release": host["kernel_release"],
                    "microcode": host["microcode"],
                    "cpu_model": host["cpu_model"],
                    "cpu_stepping": host["cpu_stepping"],
                    "topology_sha256": host["topology_sha256"],
                }
            ),
        ),
        "source_hash": common["source_hash"],
        "profile_hash": common["profile_hash"],
        "analysis_plan_hash": common["analysis_plan_hash"],
    }
    if kind == "tail-window":
        identity["tail_window_policy_hash"] = domain_hash(
            "qualification-tail-window-policy",
            canonical_bytes(
                {
                    "durations_seconds": list(DURATION_LADDER_SECONDS),
                    "screening_primary_trials": 384,
                    "held_out_possible_primary_trials": 7_680,
                    "held_out_blocks": 20,
                    "common_sign_patterns": HELD_OUT_SIGN_PATTERNS,
                    "screening_eligible_minimum": 1_280,
                    "held_out_eligible_minimum": 1_024,
                    "wilson_failure_upper_maximum": "0.01",
                    "p99_log_margin": "0.01980262729617973",
                }
            ),
        )
    validate_qualification_identity(kind, identity)
    return identity


def not_run(kind: str, reason: str) -> QualificationDecision:
    _require_kind(kind)
    if not isinstance(reason, str) or not reason:
        raise QualificationError("NOT_RUN requires a nonempty reason")
    return QualificationDecision(kind, "not_run", (reason,), {"physical_gate": "NOT_RUN"})


def _require_kind(kind: str) -> None:
    if kind not in ARTIFACT_KINDS:
        raise QualificationError(f"unknown qualification artifact kind {kind!r}")


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_qualification_identity(kind: str, identity: Mapping[str, Any]) -> None:
    _require_kind(kind)
    if not isinstance(identity, Mapping):
        raise QualificationError("qualification identity must be an object")
    missing = sorted(REQUIRED_IDENTITY_FIELDS[kind] - set(identity))
    if missing:
        raise QualificationError(
            f"{kind} identity is missing required fields: {', '.join(missing)}"
        )
    for field in _HASH_TEXT_FIELDS & set(identity):
        if not _is_hash(identity[field]):
            raise QualificationError(f"identity field {field} must be a SHA-256 digest")
    for field in _HASH_MAP_FIELDS & set(identity):
        values = identity[field]
        if not isinstance(values, Mapping) or not values:
            raise QualificationError(f"identity field {field} must be a nonempty object")
        for name, digest in values.items():
            if not isinstance(name, str) or not name or not _is_hash(digest):
                raise QualificationError(
                    f"identity field {field} must map nonempty names to SHA-256 digests"
                )
    try:
        canonical_bytes(identity)
    except Exception as exc:
        raise QualificationError(f"qualification identity is not canonical: {exc}") from exc


def qualification_identity_hash(kind: str, identity: Mapping[str, Any]) -> str:
    validate_qualification_identity(kind, identity)
    return domain_hash(
        "qualification-identity", kind.encode("ascii"), canonical_bytes(identity)
    )


def encode_qualification_artifact(
    kind: str,
    identity: Mapping[str, Any],
    decision: QualificationDecision,
) -> tuple[bytes, str, str]:
    identity_hash = qualification_identity_hash(kind, identity)
    if decision.kind != kind:
        raise QualificationError("decision kind does not match artifact kind")
    if decision.status not in {"qualified", "not_qualified"}:
        raise QualificationError("only completed pass/fail decisions are reusable")
    if decision.qualified == bool(decision.reasons):
        raise QualificationError("qualified decisions must have no reasons; failures need reasons")
    payload = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "artifact_kind": kind,
        "identity": identity,
        "identity_hash": identity_hash,
        "qualified": decision.qualified,
        "status": decision.status,
        "reasons": list(decision.reasons),
        "evidence": decision.evidence,
    }
    artifact_hash = domain_hash("qualification-artifact", canonical_bytes(payload))
    document = dict(payload)
    document["artifact_hash"] = artifact_hash
    return canonical_bytes(document) + b"\n", artifact_hash, identity_hash


def decode_qualification_artifact(
    content: bytes,
    *,
    expected_kind: str,
    expected_identity: Mapping[str, Any],
) -> tuple[QualificationDecision, str, str]:
    expected_identity_hash = qualification_identity_hash(expected_kind, expected_identity)
    try:
        document = loads_strict(content)
    except Exception as exc:
        raise QualificationError(f"qualification artifact is not strict JSON: {exc}") from exc
    if not isinstance(document, Mapping):
        raise QualificationError("qualification artifact must be an object")
    expected_keys = {
        "schema_version",
        "artifact_kind",
        "identity",
        "identity_hash",
        "qualified",
        "status",
        "reasons",
        "evidence",
        "artifact_hash",
    }
    if set(document) != expected_keys:
        raise QualificationError("qualification artifact fields do not match schema v1")
    canonical = canonical_bytes(document) + b"\n"
    if canonical != content:
        raise QualificationError("qualification artifact is not canonical")
    if document["schema_version"] != ARTIFACT_SCHEMA_VERSION:
        raise QualificationError("qualification artifact schema version is not supported")
    if document["artifact_kind"] != expected_kind:
        raise QualificationError("qualification artifact kind mismatch")
    if canonical_bytes(document["identity"]) != canonical_bytes(expected_identity):
        raise QualificationError("qualification artifact identity mismatch")
    if document["identity_hash"] != expected_identity_hash:
        raise QualificationError("qualification artifact identity hash mismatch")
    payload = {key: value for key, value in document.items() if key != "artifact_hash"}
    artifact_hash = domain_hash("qualification-artifact", canonical_bytes(payload))
    if document["artifact_hash"] != artifact_hash:
        raise QualificationError("qualification artifact content hash mismatch")
    status = document["status"]
    qualified = document["qualified"]
    reasons = document["reasons"]
    evidence = document["evidence"]
    if status not in {"qualified", "not_qualified"} or not isinstance(qualified, bool):
        raise QualificationError("qualification artifact decision is malformed")
    if qualified != (status == "qualified"):
        raise QualificationError("qualification artifact decision fields disagree")
    if (
        not isinstance(reasons, Sequence)
        or isinstance(reasons, (str, bytes, bytearray))
        or any(not isinstance(reason, str) or not reason for reason in reasons)
        or not isinstance(evidence, Mapping)
    ):
        raise QualificationError("qualification artifact evidence is malformed")
    if qualified == bool(reasons):
        raise QualificationError("qualification artifact reasons disagree with its decision")
    return (
        QualificationDecision(expected_kind, status, tuple(reasons), evidence),
        artifact_hash,
        expected_identity_hash,
    )


class QualificationArtifactStore:
    """Fail-closed content-addressed storage for reusable qualification decisions."""

    def __init__(self, root: os.PathLike[str] | str) -> None:
        self.root = Path(root)

    def store(
        self,
        kind: str,
        identity: Mapping[str, Any],
        decision: QualificationDecision,
    ) -> StoredQualificationArtifact:
        content, artifact_hash, identity_hash = encode_qualification_artifact(
            kind, identity, decision
        )
        if len(content) > 8 * 1024 * 1024:
            raise QualificationError("qualification artifact exceeds the 8 MiB bound")
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise QualificationError(
                f"cannot create qualification artifact store: {exc}"
            ) from exc
        self._require_directory(self.root)
        kind_dir = self.root / kind
        identity_dir = kind_dir / identity_hash
        target = identity_dir / f"{artifact_hash}.json"
        try:
            kind_dir.mkdir(exist_ok=True)
        except OSError as exc:
            raise QualificationError(
                f"cannot create qualification artifact kind directory: {exc}"
            ) from exc
        self._require_directory(kind_dir)
        lock = kind_dir / f"{identity_hash}.lock"
        try:
            lock_fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise QualificationArtifactBusyError(
                    f"qualification artifact writer lock exists: {lock}"
                ) from exc
            raise QualificationError(f"cannot create qualification artifact lock: {exc}") from exc
        temporary: Path | None = None
        try:
            os.write(lock_fd, f"pid={os.getpid()}\n".encode("ascii"))
            os.fsync(lock_fd)
            os.close(lock_fd)
            lock_fd = -1
            identity_dir.mkdir(mode=0o700, exist_ok=True)
            self._require_directory(identity_dir)
            existing = list(identity_dir.iterdir())
            if existing:
                loaded = self.load(kind, identity, _ignore_lock=True)
                if loaded.artifact_hash != artifact_hash:
                    raise QualificationError(
                        "a different decision already exists for this qualification identity"
                    )
                return loaded
            temporary = identity_dir / f".{artifact_hash}.tmp-{secrets.token_hex(8)}"
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                view = memoryview(content)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise QualificationError("short qualification artifact write")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temporary, target)
            temporary = None
            self._fsync_directory(identity_dir)
            return StoredQualificationArtifact(target, artifact_hash, identity_hash, decision)
        except OSError as exc:
            raise QualificationError(f"cannot store qualification artifact: {exc}") from exc
        finally:
            if 'lock_fd' in locals() and lock_fd >= 0:
                os.close(lock_fd)
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            try:
                lock.unlink()
                self._fsync_directory(kind_dir)
            except FileNotFoundError:
                pass

    def load(
        self,
        kind: str,
        identity: Mapping[str, Any],
        *,
        _ignore_lock: bool = False,
    ) -> StoredQualificationArtifact:
        identity_hash = qualification_identity_hash(kind, identity)
        if os.path.lexists(self.root):
            self._require_directory(self.root)
        kind_dir = self.root / kind
        lock = kind_dir / f"{identity_hash}.lock"
        if not _ignore_lock and os.path.lexists(lock):
            raise QualificationArtifactBusyError(
                f"qualification artifact writer lock exists: {lock}"
            )
        identity_dir = kind_dir / identity_hash
        if os.path.lexists(identity_dir):
            self._require_directory(identity_dir)
        try:
            entries = list(identity_dir.iterdir())
        except FileNotFoundError as exc:
            raise QualificationError(
                f"no {kind} artifact exists for identity {identity_hash}"
            ) from exc
        if len(entries) != 1:
            raise QualificationError(
                "qualification artifact directory must contain exactly one complete artifact"
            )
        path = entries[0]
        content = self._read_bounded_regular_file(path)
        decision, artifact_hash, checked_identity_hash = decode_qualification_artifact(
            content, expected_kind=kind, expected_identity=identity
        )
        if path.name != f"{artifact_hash}.json":
            raise QualificationError("qualification artifact filename hash mismatch")
        return StoredQualificationArtifact(
            path, artifact_hash, checked_identity_hash, decision
        )

    def load_optional(
        self,
        kind: str,
        identity: Mapping[str, Any],
    ) -> StoredQualificationArtifact | None:
        """Return the exact artifact, or ``None`` only when it has never been stored."""

        identity_hash = qualification_identity_hash(kind, identity)
        if os.path.lexists(self.root):
            self._require_directory(self.root)
        kind_dir = self.root / kind
        lock = kind_dir / f"{identity_hash}.lock"
        if os.path.lexists(lock):
            raise QualificationArtifactBusyError(
                f"qualification artifact writer lock exists: {lock}"
            )
        identity_dir = kind_dir / identity_hash
        if not os.path.lexists(identity_dir):
            if os.path.lexists(kind_dir):
                self._require_directory(kind_dir)
            return None
        return self.load(kind, identity)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _read_bounded_regular_file(path: Path) -> bytes:
        try:
            fd = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError as exc:
            raise QualificationError(f"cannot open qualification artifact: {exc}") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise QualificationError(
                    "qualification artifact must be a regular non-symlink file"
                )
            limit = 8 * 1024 * 1024
            if metadata.st_size > limit:
                raise QualificationError("qualification artifact exceeds the 8 MiB bound")
            content = bytearray()
            while len(content) <= limit:
                chunk = os.read(fd, min(1 << 20, limit + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            if len(content) > limit:
                raise QualificationError("qualification artifact exceeds the 8 MiB bound")
            return bytes(content)
        except OSError as exc:
            raise QualificationError(f"cannot read qualification artifact: {exc}") from exc
        finally:
            os.close(fd)

    @staticmethod
    def _require_directory(path: Path) -> None:
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
            raise QualificationError(
                f"qualification artifact path must be a real directory: {path}"
            )


DecimalInput = Decimal | int | str | float


def _decimal(value: DecimalInput, name: str) -> Decimal:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not result.is_finite():
        raise ValueError(f"{name} must be finite")
    return result


def _inside_ratio(low: DecimalInput, high: DecimalInput, margin: str) -> bool:
    lower = _decimal(low, "interval low")
    upper = _decimal(high, "interval high")
    bound = Decimal(margin)
    return lower <= upper and lower >= Decimal(1) - bound and upper <= Decimal(1) + bound


def _is_ninety_percent(value: DecimalInput) -> bool:
    return _decimal(value, "confidence level") == Decimal("0.90")


T = TypeVar("T")
K = TypeVar("K")


def _index_exact(
    records: Sequence[T],
    expected: set[K],
    key: Callable[[T], K],
    label: str,
) -> tuple[dict[K, T], list[str]]:
    indexed: dict[K, T] = {}
    reasons: list[str] = []
    for record in records:
        record_key = key(record)
        if record_key in indexed:
            reasons.append(f"duplicate_{label}:{record_key!r}")
        elif record_key not in expected:
            reasons.append(f"unexpected_{label}:{record_key!r}")
        else:
            indexed[record_key] = record
    for missing in sorted(expected - set(indexed), key=repr):
        reasons.append(f"missing_{label}:{missing!r}")
    return indexed, reasons


def _decision(kind: str, reasons: Sequence[str], evidence: Mapping[str, Any]) -> QualificationDecision:
    unique = tuple(dict.fromkeys(reasons))
    return QualificationDecision(
        kind,
        "not_qualified" if unique else "qualified",
        unique,
        evidence,
    )


@dataclass(frozen=True)
class ResetCycleEvidence:
    adapter: str
    backend: str
    scenario: str
    cycle: int
    live_connections: int
    live_streams: int
    live_tickets: int
    work_inventory: int


@dataclass(frozen=True)
class EnduranceCheckpointEvidence:
    adapter: str
    backend: str
    cycle: int
    baseline_fd_count: int
    fd_count: int
    live_connections: int
    live_streams: int
    live_tickets: int
    baseline_memory_bytes: int
    reset_memory_bytes: int


@dataclass(frozen=True)
class ReuseParityEvidence:
    adapter: str
    backend: str
    sentinel: str
    paired_blocks: int
    interval_low_ratio: DecimalInput
    interval_high_ratio: DecimalInput
    reordered_ratio: DecimalInput
    confidence_level: DecimalInput = "0.90"


@dataclass(frozen=True)
class LeakSlopeEvidence:
    adapter: str
    backend: str
    baseline_memory_bytes: int
    interval_low_bytes_per_cycle: DecimalInput
    interval_high_bytes_per_cycle: DecimalInput
    confidence_level: DecimalInput = "0.90"


def evaluate_worker_reuse(
    *,
    expected_reset_cells: Sequence[tuple[str, str, str]],
    expected_adapter_backends: Sequence[tuple[str, str]],
    reset_cycles: Sequence[ResetCycleEvidence],
    endurance_checkpoints: Sequence[EnduranceCheckpointEvidence],
    parity: Sequence[ReuseParityEvidence],
    leak_slopes: Sequence[LeakSlopeEvidence],
) -> QualificationDecision:
    reasons: list[str] = []
    reset_expected = {
        (adapter, backend, scenario, cycle)
        for adapter, backend, scenario in expected_reset_cells
        for cycle in range(1, 33)
    }
    resets, found = _index_exact(
        reset_cycles,
        reset_expected,
        lambda item: (item.adapter, item.backend, item.scenario, item.cycle),
        "reset_cycle",
    )
    reasons.extend(found)
    for key, item in resets.items():
        if any(
            value != 0
            for value in (
                item.live_connections,
                item.live_streams,
                item.live_tickets,
                item.work_inventory,
            )
        ):
            reasons.append(f"reset_state_not_empty:{key!r}")

    adapter_backends = set(expected_adapter_backends)
    endurance_expected = {
        (adapter, backend, cycle)
        for adapter, backend in adapter_backends
        for cycle in range(32, 1025, 32)
    }
    checkpoints, found = _index_exact(
        endurance_checkpoints,
        endurance_expected,
        lambda item: (item.adapter, item.backend, item.cycle),
        "endurance_checkpoint",
    )
    reasons.extend(found)
    for key, item in checkpoints.items():
        if item.fd_count != item.baseline_fd_count:
            reasons.append(f"endurance_fd_not_at_baseline:{key!r}")
        if any(
            value != 0
            for value in (item.live_connections, item.live_streams, item.live_tickets)
        ):
            reasons.append(f"endurance_live_state_not_empty:{key!r}")
        if item.baseline_memory_bytes < 0 or item.reset_memory_bytes < 0:
            reasons.append(f"endurance_negative_memory:{key!r}")
        else:
            tolerance = max(1 << 20, Decimal(item.baseline_memory_bytes) * Decimal("0.01"))
            if abs(Decimal(item.reset_memory_bytes - item.baseline_memory_bytes)) > tolerance:
                reasons.append(f"endurance_memory_not_at_baseline:{key!r}")
    for adapter, backend in adapter_backends:
        group = [
            item
            for key, item in checkpoints.items()
            if key[0] == adapter and key[1] == backend
        ]
        if group and (
            len({item.baseline_fd_count for item in group}) != 1
            or len({item.baseline_memory_bytes for item in group}) != 1
        ):
            reasons.append(f"endurance_baseline_changed:{(adapter, backend)!r}")

    parity_expected = {
        (adapter, backend, sentinel)
        for adapter, backend in adapter_backends
        for sentinel in WORKER_SENTINELS
    }
    parity_by_key, found = _index_exact(
        parity,
        parity_expected,
        lambda item: (item.adapter, item.backend, item.sentinel),
        "reuse_parity",
    )
    reasons.extend(found)
    for key, item in parity_by_key.items():
        try:
            if item.paired_blocks != 12:
                reasons.append(f"reuse_parity_block_count:{key!r}")
            if not _is_ninety_percent(item.confidence_level):
                reasons.append(f"reuse_parity_confidence:{key!r}")
            if not _inside_ratio(item.interval_low_ratio, item.interval_high_ratio, "0.02"):
                reasons.append(f"reuse_parity_interval:{key!r}")
            reordered = _decimal(item.reordered_ratio, "reordered ratio")
            if not Decimal("0.98") <= reordered <= Decimal("1.02"):
                reasons.append(f"reuse_reordering_effect:{key!r}")
        except ValueError:
            reasons.append(f"reuse_parity_nonfinite:{key!r}")

    leaks, found = _index_exact(
        leak_slopes,
        adapter_backends,
        lambda item: (item.adapter, item.backend),
        "leak_slope",
    )
    reasons.extend(found)
    for key, item in leaks.items():
        try:
            if item.baseline_memory_bytes < 0:
                raise ValueError("negative baseline")
            checkpoint_baselines = {
                checkpoint.baseline_memory_bytes
                for checkpoint_key, checkpoint in checkpoints.items()
                if checkpoint_key[:2] == key
            }
            if checkpoint_baselines and checkpoint_baselines != {item.baseline_memory_bytes}:
                reasons.append(f"leak_slope_baseline_mismatch:{key!r}")
            low = _decimal(item.interval_low_bytes_per_cycle, "leak interval low")
            high = _decimal(item.interval_high_bytes_per_cycle, "leak interval high")
            if not _is_ninety_percent(item.confidence_level):
                reasons.append(f"leak_slope_confidence:{key!r}")
            margin = max(
                Decimal(1024), Decimal(item.baseline_memory_bytes) * Decimal("0.00001")
            )
            if low > high or low < -margin or high > margin:
                reasons.append(f"leak_slope_interval:{key!r}")
        except ValueError:
            reasons.append(f"leak_slope_nonfinite:{key!r}")
    return _decision(
        "worker-reuse",
        reasons,
        {
            "reset_cycles": len(resets),
            "endurance_cycles": 1024,
            "endurance_checkpoints": len(checkpoints),
            "paired_blocks_per_sentinel": 12,
            "sentinels": list(WORKER_SENTINELS),
        },
    )


@dataclass(frozen=True)
class HeadroomScreenEvidence:
    server: str
    backend: str
    scenario: str
    client_cpu_ns_per_wall_ns: DecimalInput


@dataclass(frozen=True)
class HeadroomPairEvidence:
    server: str
    backend: str
    scenario: str
    blocks: int
    treatment_client_cores: int
    treatment_p95_cpu: tuple[DecimalInput, ...]


def evaluate_client_headroom(
    *,
    servers: Sequence[str],
    backends: Sequence[str],
    treatment_client_cores: int,
    screens: Sequence[HeadroomScreenEvidence],
    held_out: HeadroomPairEvidence,
) -> QualificationDecision:
    expected = {
        (server, backend, scenario)
        for server in servers
        for backend in backends
        for scenario in HEADROOM_SCENARIOS
    }
    indexed, reasons = _index_exact(
        screens,
        expected,
        lambda item: (item.server, item.backend, item.scenario),
        "headroom_screen",
    )
    rank = {
        (server, backend, scenario): ordinal
        for ordinal, (server, backend, scenario) in enumerate(
            (s, b, c) for s in servers for b in backends for c in HEADROOM_SCENARIOS
        )
    }
    selected: tuple[str, str, str] | None = None
    scored: list[tuple[Decimal, int, tuple[str, str, str]]] = []
    for key, item in indexed.items():
        try:
            pressure = _decimal(item.client_cpu_ns_per_wall_ns, "client CPU pressure")
            if pressure < 0:
                raise ValueError("negative pressure")
            scored.append((pressure, -rank[key], key))
        except ValueError:
            reasons.append(f"headroom_screen_nonfinite:{key!r}")
    if len(scored) == len(expected):
        selected = max(scored)[2]
    held_key = (held_out.server, held_out.backend, held_out.scenario)
    if selected is None or held_key != selected:
        reasons.append("headroom_held_out_cell_mismatch")
    if (
        treatment_client_cores not in {2, 4}
        or held_out.treatment_client_cores != treatment_client_cores
    ):
        reasons.append("headroom_treatment_core_count")
    if held_out.blocks != 12 or len(held_out.treatment_p95_cpu) != 12:
        reasons.append("headroom_block_count")
    try:
        if any(
            _decimal(value, "treatment p95 CPU") >= Decimal("0.80")
            for value in held_out.treatment_p95_cpu
        ):
            reasons.append("headroom_treatment_cpu")
    except ValueError:
        reasons.append("headroom_nonfinite")
    return _decision(
        "client-headroom",
        reasons,
        {
            "screen_duration_ms": 500,
            "screen_observations_used_as_qualification": 0,
            "selected_cell": list(selected) if selected is not None else None,
            "held_out_blocks": held_out.blocks,
            "treatment_client_cores": treatment_client_cores,
        },
    )


@dataclass(frozen=True)
class LaneScreenEvidence:
    server: str
    backend: str
    scenario: str
    pressure: DecimalInput


@dataclass(frozen=True)
class LanePairEvidence:
    dimension: str
    server: str
    backend: str
    scenario: str
    paired_blocks: int
    rate_interval_low_ratio: DecimalInput
    rate_interval_high_ratio: DecimalInput
    memory_interval_low_ratio: DecimalInput
    memory_interval_high_ratio: DecimalInput
    one_lane_variance: DecimalInput
    two_lane_variance: DecimalInput
    one_lane_ci_width: DecimalInput
    two_lane_ci_width: DecimalInput
    confidence_level: DecimalInput = "0.90"


def evaluate_lane_interference(
    *,
    servers: Sequence[str],
    backends: Sequence[str],
    screens: Sequence[LaneScreenEvidence],
    held_out: Sequence[LanePairEvidence],
) -> QualificationDecision:
    scenarios = tuple(LANE_DIMENSIONS.values())
    expected = {
        (server, backend, scenario)
        for server in servers
        for backend in backends
        for scenario in scenarios
    }
    indexed, reasons = _index_exact(
        screens,
        expected,
        lambda item: (item.server, item.backend, item.scenario),
        "lane_screen",
    )
    rank = {
        (server, backend): ordinal
        for ordinal, (server, backend) in enumerate(
            (server, backend) for server in servers for backend in backends
        )
    }
    selected: dict[str, tuple[str, str, str]] = {}
    for dimension, scenario in LANE_DIMENSIONS.items():
        candidates: list[tuple[Decimal, int, tuple[str, str, str]]] = []
        for key, item in indexed.items():
            if key[2] != scenario:
                continue
            try:
                pressure = _decimal(item.pressure, "lane screen pressure")
                if pressure < 0:
                    raise ValueError("negative pressure")
                candidates.append((pressure, -rank[(key[0], key[1])], key))
            except ValueError:
                reasons.append(f"lane_screen_nonfinite:{key!r}")
        if len(candidates) == len(servers) * len(backends):
            selected[dimension] = max(candidates)[2]
    held_expected = set(LANE_DIMENSIONS)
    held, found = _index_exact(
        held_out,
        held_expected,
        lambda item: item.dimension,
        "lane_held_out",
    )
    reasons.extend(found)
    for dimension, item in held.items():
        expected_cell = selected.get(dimension)
        if expected_cell != (item.server, item.backend, item.scenario):
            reasons.append(f"lane_held_out_cell_mismatch:{dimension}")
        if item.paired_blocks != 20:
            reasons.append(f"lane_block_count:{dimension}")
        try:
            if not _is_ninety_percent(item.confidence_level):
                reasons.append(f"lane_confidence:{dimension}")
            if not _inside_ratio(
                item.rate_interval_low_ratio, item.rate_interval_high_ratio, "0.02"
            ):
                reasons.append(f"lane_rate_interval:{dimension}")
            if not _inside_ratio(
                item.memory_interval_low_ratio, item.memory_interval_high_ratio, "0.05"
            ):
                reasons.append(f"lane_memory_interval:{dimension}")
            one_variance = _decimal(item.one_lane_variance, "one-lane variance")
            two_variance = _decimal(item.two_lane_variance, "two-lane variance")
            one_width = _decimal(item.one_lane_ci_width, "one-lane CI width")
            two_width = _decimal(item.two_lane_ci_width, "two-lane CI width")
            if min(one_variance, two_variance, one_width, two_width) < 0:
                raise ValueError("negative variance or width")
            if two_variance > Decimal("1.25") * one_variance:
                reasons.append(f"lane_variance_inflation:{dimension}")
            if two_width > Decimal("1.25") * one_width:
                reasons.append(f"lane_ci_width_inflation:{dimension}")
        except ValueError:
            reasons.append(f"lane_nonfinite:{dimension}")
    return _decision(
        "lane-interference",
        reasons,
        {
            "screen_duration_ms": 500,
            "screen_observations_used_as_qualification": 0,
            "selected_cells": {key: list(value) for key, value in sorted(selected.items())},
            "held_out_paired_blocks_per_cell": 20,
            "max_lanes": 1 if reasons else 2,
        },
    )


@dataclass(frozen=True)
class WindowScreenEvidence:
    server: str
    backend: str
    scenario: str
    short_rate: DecimalInput
    reference_rate: DecimalInput
    short_classification: str
    reference_classification: str
    cap_hit: bool
    stalled: bool
    short_window_seconds: int
    reference_window_seconds: int


@dataclass(frozen=True)
class WindowPairEvidence:
    server: str
    backend: str
    scenario: str
    paired_blocks: int
    interval_low_ratio: DecimalInput
    interval_high_ratio: DecimalInput
    short_log_variance: DecimalInput
    reference_log_variance: DecimalInput
    classifications: tuple[tuple[str, str], ...]
    confidence_level: DecimalInput = "0.90"


@dataclass(frozen=True)
class WindowContrastEvidence:
    backend: str
    scenario: str
    selected_server: str
    baseline_server: str
    paired_blocks: int
    interval_low_ratio: DecimalInput
    interval_high_ratio: DecimalInput
    confidence_level: DecimalInput = "0.90"


def evaluate_window_equivalence(
    *,
    servers: Sequence[str],
    backends: Sequence[str],
    scenarios: Sequence[str],
    baseline_server: str,
    screens: Sequence[WindowScreenEvidence],
    held_out: Sequence[WindowPairEvidence],
    contrasts: Sequence[WindowContrastEvidence],
) -> QualificationDecision:
    if baseline_server not in servers:
        raise QualificationError("window baseline server is not in the frozen server set")
    expected = {
        (server, backend, scenario)
        for server in servers
        for backend in backends
        for scenario in scenarios
    }
    indexed, reasons = _index_exact(
        screens,
        expected,
        lambda item: (item.server, item.backend, item.scenario),
        "window_screen",
    )
    server_rank = {server: ordinal for ordinal, server in enumerate(servers)}
    scored: dict[tuple[str, str], list[tuple[Decimal, int, str]]] = {}
    for key, item in indexed.items():
        try:
            short = _decimal(item.short_rate, "short-window rate")
            reference = _decimal(item.reference_rate, "reference-window rate")
            if short <= 0 or reference <= 0:
                raise ValueError("nonpositive rate")
            if (item.short_window_seconds, item.reference_window_seconds) not in {
                (2, 10),
                (5, 20),
            }:
                reasons.append(f"window_screen_duration:{key!r}")
            if (
                item.short_classification != item.reference_classification
                or item.cap_hit
                or item.stalled
            ):
                reasons.append(f"window_screen_semantics:{key!r}")
            score = (short / reference).ln().copy_abs()
            scored.setdefault((key[1], key[2]), []).append(
                (score, -server_rank[key[0]], key[0])
            )
        except (ValueError, InvalidOperation):
            reasons.append(f"window_screen_nonfinite:{key!r}")
    selected: dict[tuple[str, str], str] = {}
    for stratum in ((backend, scenario) for backend in backends for scenario in scenarios):
        candidates = scored.get(stratum, [])
        if len(candidates) == len(servers):
            selected[stratum] = max(candidates)[2]

    held_expected = {
        (server, backend, scenario)
        for (backend, scenario), selected_server in selected.items()
        for server in {selected_server, baseline_server}
    }
    paired, found = _index_exact(
        held_out,
        held_expected,
        lambda item: (item.server, item.backend, item.scenario),
        "window_held_out",
    )
    reasons.extend(found)
    for key, item in paired.items():
        if item.paired_blocks != 20 or len(item.classifications) != 20:
            reasons.append(f"window_block_count:{key!r}")
        if any(short != reference for short, reference in item.classifications):
            reasons.append(f"window_classification_mismatch:{key!r}")
        try:
            if not _is_ninety_percent(item.confidence_level):
                reasons.append(f"window_confidence:{key!r}")
            if not _inside_ratio(item.interval_low_ratio, item.interval_high_ratio, "0.02"):
                reasons.append(f"window_interval:{key!r}")
            short_variance = _decimal(item.short_log_variance, "short-window variance")
            reference_variance = _decimal(
                item.reference_log_variance, "reference-window variance"
            )
            if min(short_variance, reference_variance) < 0:
                raise ValueError("negative variance")
            if short_variance > Decimal("1.25") * reference_variance:
                reasons.append(f"window_variance_inflation:{key!r}")
        except ValueError:
            reasons.append(f"window_nonfinite:{key!r}")

    contrast_expected = {
        (backend, scenario)
        for (backend, scenario), selected_server in selected.items()
        if selected_server != baseline_server
    }
    contrast_by_key, found = _index_exact(
        contrasts,
        contrast_expected,
        lambda item: (item.backend, item.scenario),
        "window_contrast",
    )
    reasons.extend(found)
    for key, item in contrast_by_key.items():
        if (
            item.selected_server != selected.get(key)
            or item.baseline_server != baseline_server
        ):
            reasons.append(f"window_contrast_cell_mismatch:{key!r}")
        if item.paired_blocks != 20:
            reasons.append(f"window_contrast_block_count:{key!r}")
        try:
            if not _is_ninety_percent(item.confidence_level):
                reasons.append(f"window_contrast_confidence:{key!r}")
            if not _inside_ratio(item.interval_low_ratio, item.interval_high_ratio, "0.02"):
                reasons.append(f"window_contrast_interval:{key!r}")
        except ValueError:
            reasons.append(f"window_contrast_nonfinite:{key!r}")
    return _decision(
        "window-qualification",
        reasons,
        {
            "screen_observations_used_as_qualification": 0,
            "selected_servers": {
                f"{backend}/{scenario}": server
                for (backend, scenario), server in sorted(selected.items())
            },
            "held_out_paired_blocks": 20,
            "enabled_windows_seconds": [2, 5] if not reasons else [10, 20],
        },
    )


def evaluate_tail_window_adequacy(
    *,
    screens: Sequence[TailScreenCell],
    held_out: Sequence[TailHeldOutBlock],
) -> QualificationDecision:
    analysis = analyze_tail_window_qualification(screens, held_out)
    selected = {
        f"{scenario}/{backend}/{client}": list(servers)
        for (scenario, backend, client), servers in sorted(
            analysis.selected_servers_by_stratum.items()
        )
    }
    stratum_durations = {
        f"{scenario}/{backend}/{client}": duration
        for (scenario, backend, client), duration in sorted(
            analysis.stratum_durations.items()
        )
    }
    interval_summary = {
        f"{scenario}/{backend}/{client}": {
            "sign_patterns": result.sign_patterns,
            "critical_value": format(result.critical_value, ".17g"),
            "contrasts": len(result.intervals),
        }
        for (scenario, backend, client), result in sorted(
            analysis.interval_results.items()
        )
    }
    return _decision(
        "tail-window",
        analysis.reasons,
        {
            "screen_observations_used_as_qualification": 0,
            "screening_trials": len(screens),
            "held_out_trials": len(held_out),
            "screening_nominations_seconds": dict(
                sorted(analysis.screening_nominations.items())
            ),
            "selected_servers": selected,
            "stratum_durations_seconds": stratum_durations,
            "scenario_durations_seconds": dict(
                sorted(analysis.scenario_durations.items())
            ),
            "simultaneous_intervals": interval_summary,
            "common_sign_patterns": HELD_OUT_SIGN_PATTERNS,
        },
    )
