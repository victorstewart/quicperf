"""Immutable current-binary native interoperability qualification."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import hmac
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import time
from typing import Any, Callable, Mapping, Sequence

from .canonical import canonical_bytes, loads_strict
from .identity import analysis_plan_hash, domain_hash, spec_hash
from .manifest import manifest_hash
from .model import ExperimentSpecV2, ImmutableIdentityManifest


ARTIFACT_SCHEMA_VERSION = "quicperf.native-interoperability.v2"
CHECKPOINT_SCHEMA_VERSION = "quicperf.native-interoperability-checkpoint.v2"
IDENTITY_SCHEMA_VERSION = "quicperf.native-interoperability-identity.v2"
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
PASS = "PASS"
FAIL = "FAIL"
POST_TRIAL_QUIESCENCE_NS = 250_000_000
POST_TRIAL_QUIESCENCE_SECONDS = POST_TRIAL_QUIESCENCE_NS / 1_000_000_000


class InteroperabilityError(ValueError):
    """The native interoperability plan or artifact is invalid."""


@dataclass(frozen=True, slots=True)
class InteroperabilityTuple:
    tuple_id: str
    execution_order: int
    server: str
    reference_client: str
    server_backend: str
    reference_client_backend: str
    scenario: str


@dataclass(frozen=True, slots=True)
class InteroperabilityRecord:
    tuple_id: str
    execution_order: int
    server: str
    reference_client: str
    server_backend: str
    reference_client_backend: str
    scenario: str
    status: str
    reason: str
    evidence_sha256: str
    evidence: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class InteroperabilityArtifact:
    identity_hash: str
    artifact_hash: str
    plan_hash: str
    status: str
    passed: int
    failed: int
    records: tuple[InteroperabilityRecord, ...]
    path: Path | None = None


def _module_hash() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def build_interoperability_identity(
    spec: ExperimentSpecV2, manifest: ImmutableIdentityManifest
) -> dict[str, Any]:
    binaries = {
        str(binary["name"]): {
            "sha256": str(binary["sha256"]),
            "elf_build_id": str(binary["elf_build_id"]),
            "loaded_libraries_sha256": domain_hash(
                "interoperability-loaded-libraries",
                canonical_bytes(binary["expected_loaded_libraries"]),
            ),
        }
        for binary in manifest.binaries
        if str(binary["name"]) in set(spec.servers) | set(spec.reference_clients)
    }
    identity = {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "profile_sha256": spec_hash(spec.raw),
        "analysis_plan_sha256": analysis_plan_hash(spec.raw["analysis"]),
        "manifest_sha256": manifest_hash(manifest),
        "source_sha256": domain_hash(
            "interoperability-source", canonical_bytes(manifest.source)
        ),
        "dependencies_sha256": domain_hash(
            "interoperability-dependencies", canonical_bytes(manifest.dependencies)
        ),
        "toolchains_sha256": domain_hash(
            "interoperability-toolchains", canonical_bytes(manifest.toolchains)
        ),
        "binaries": binaries,
        "protocols_sha256": domain_hash(
            "interoperability-protocols", canonical_bytes(manifest.protocols)
        ),
        "tls_sha256": domain_hash(
            "interoperability-tls", canonical_bytes(spec.raw["treatment"]["tls"])
        ),
        "workload_policy_sha256": domain_hash(
            "interoperability-workloads", canonical_bytes(spec.raw["workloads"])
        ),
        "host_kernel_policy_sha256": domain_hash(
            "interoperability-host-kernel-policy",
            canonical_bytes(manifest.host_policy),
        ),
        "path_profiles_sha256": domain_hash(
            "interoperability-path-profiles",
            canonical_bytes(manifest.path_profiles),
        ),
        "runner_sha256": _module_hash(),
    }
    expected_binaries = set(spec.servers) | set(spec.reference_clients)
    if set(binaries) != expected_binaries:
        missing = sorted(expected_binaries - set(binaries))
        raise InteroperabilityError(
            "interoperability identity is missing binaries: " + ",".join(missing)
        )
    return identity


def interoperability_identity_hash(identity: Mapping[str, Any]) -> str:
    if identity.get("schema_version") != IDENTITY_SCHEMA_VERSION:
        raise InteroperabilityError("interoperability identity schema is invalid")
    return domain_hash("native-interoperability-identity", canonical_bytes(identity))


def interoperability_plan_cardinality(spec: ExperimentSpecV2) -> int:
    """Cover every server/scenario while balancing the client/backend nuisance axes."""

    nuisance_treatments = len(spec.reference_clients) * len(spec.server_backends)
    return len(spec.servers) * max(len(spec.scenarios), nuisance_treatments)


def _identity_order(
    values: Sequence[Any], key: bytes, label: bytes
) -> tuple[Any, ...]:
    return tuple(
        value
        for _rank, _encoded, value in sorted(
            (
                hmac.new(
                    key,
                    label + canonical_bytes(value),
                    hashlib.sha256,
                ).digest(),
                canonical_bytes(value),
                value,
            )
            for value in values
        )
    )


def plan_interoperability(
    spec: ExperimentSpecV2, identity_hash: str
) -> tuple[InteroperabilityTuple, ...]:
    try:
        key = bytes.fromhex(identity_hash)
    except ValueError as exc:
        raise InteroperabilityError("identity hash must be lowercase hexadecimal") from exc
    if len(key) != 32:
        raise InteroperabilityError("identity hash must contain exactly 256 bits")
    servers = _identity_order(spec.servers, key, b"interop-server")
    scenarios = _identity_order(spec.scenarios, key, b"interop-scenario")
    nuisance = _identity_order(
        tuple(
            (client, backend)
            for client in spec.reference_clients
            for backend in spec.server_backends
        ),
        key,
        b"interop-nuisance",
    )
    positions = max(len(scenarios), len(nuisance))
    unordered = []
    for server_index, server in enumerate(servers):
        for position in range(positions):
            scenario = scenarios[position % len(scenarios)]
            client, backend = nuisance[(server_index + position) % len(nuisance)]
            coordinates = {
                "server": server,
                "reference_client": client,
                "server_backend": backend,
                "reference_client_backend": spec.reference_client_backend,
                "scenario": scenario,
            }
            tuple_id = domain_hash(
                "native-interoperability-tuple",
                key,
                canonical_bytes(coordinates),
            )
            order_key = hmac.new(
                key,
                b"native-interoperability-order" + bytes.fromhex(tuple_id),
                hashlib.sha256,
            ).digest()
            unordered.append((order_key, tuple_id, coordinates))
    ordered = tuple(
        InteroperabilityTuple(
            tuple_id=tuple_id,
            execution_order=index,
            **coordinates,
        )
        for index, (_order, tuple_id, coordinates) in enumerate(sorted(unordered))
    )
    expected = interoperability_plan_cardinality(spec)
    covered = {(item.server, item.scenario) for item in ordered}
    nuisance_covered = {
        (item.server, item.reference_client, item.server_backend)
        for item in ordered
    }
    if (
        len(ordered) != expected
        or len({item.tuple_id for item in ordered}) != expected
        or covered
        != {
            (server, scenario)
            for server in spec.servers
            for scenario in spec.scenarios
        }
        or nuisance_covered
        != {
            (server, client, backend)
            for server in spec.servers
            for client in spec.reference_clients
            for backend in spec.server_backends
        }
    ):
        raise InteroperabilityError("interoperability plan cardinality is not exact")
    return ordered


def interoperability_plan_hash(plan: Sequence[InteroperabilityTuple]) -> str:
    return domain_hash(
        "native-interoperability-plan",
        canonical_bytes([asdict(item) for item in plan]),
    )


def _record(
    planned: InteroperabilityTuple,
    *,
    status: str,
    reason: str,
    evidence: Mapping[str, Any],
) -> InteroperabilityRecord:
    if status not in {PASS, FAIL} or not reason:
        raise InteroperabilityError("interoperability result status or reason is invalid")
    evidence_value = dict(evidence)
    return InteroperabilityRecord(
        **asdict(planned),
        status=status,
        reason=reason,
        evidence_sha256=hashlib.sha256(canonical_bytes(evidence_value)).hexdigest(),
        evidence=evidence_value,
    )


def _payload(
    identity: Mapping[str, Any],
    plan_hash: str,
    records: Sequence[InteroperabilityRecord],
) -> dict[str, Any]:
    passed = sum(record.status == PASS for record in records)
    failed = len(records) - passed
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "identity": identity,
        "identity_hash": interoperability_identity_hash(identity),
        "plan_hash": plan_hash,
        "status": PASS if records and failed == 0 else FAIL,
        "passed": passed,
        "failed": failed,
        "records": [asdict(record) for record in records],
    }


def _decode(
    content: bytes,
    *,
    spec: ExperimentSpecV2,
    identity: Mapping[str, Any],
) -> InteroperabilityArtifact:
    if len(content) > MAX_ARTIFACT_BYTES:
        raise InteroperabilityError("interoperability artifact exceeds 64 MiB")
    try:
        document = loads_strict(content)
    except Exception as exc:
        raise InteroperabilityError(
            f"interoperability artifact is not strict JSON: {exc}"
        ) from exc
    if canonical_bytes(document) + b"\n" != content:
        raise InteroperabilityError("interoperability artifact is not canonical")
    required = {
        "schema_version",
        "identity",
        "identity_hash",
        "plan_hash",
        "status",
        "passed",
        "failed",
        "records",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise InteroperabilityError("interoperability artifact fields are invalid")
    if document["schema_version"] != ARTIFACT_SCHEMA_VERSION:
        raise InteroperabilityError("interoperability artifact schema is invalid")
    if document["identity"] != identity:
        raise InteroperabilityError("interoperability artifact identity differs")
    identity_hash = interoperability_identity_hash(identity)
    if document["identity_hash"] != identity_hash:
        raise InteroperabilityError("interoperability artifact identity hash differs")
    plan = plan_interoperability(spec, identity_hash)
    plan_hash = interoperability_plan_hash(plan)
    if document["plan_hash"] != plan_hash:
        raise InteroperabilityError("interoperability artifact plan hash differs")
    rows = document["records"]
    if not isinstance(rows, list) or len(rows) != len(plan):
        raise InteroperabilityError("interoperability artifact record count differs")
    records = []
    record_fields = {field.name for field in InteroperabilityRecord.__dataclass_fields__.values()}
    for index, (row, planned) in enumerate(zip(rows, plan, strict=True)):
        if not isinstance(row, Mapping) or set(row) != record_fields:
            raise InteroperabilityError(f"interoperability record {index} fields are invalid")
        record = InteroperabilityRecord(**row)
        for field, value in asdict(planned).items():
            if getattr(record, field) != value:
                raise InteroperabilityError(
                    f"interoperability record {index} does not match its plan"
                )
        if record.status not in {PASS, FAIL} or not record.reason:
            raise InteroperabilityError(f"interoperability record {index} status is invalid")
        if hashlib.sha256(canonical_bytes(record.evidence)).hexdigest() != record.evidence_sha256:
            raise InteroperabilityError(f"interoperability record {index} evidence hash differs")
        records.append(record)
    passed = sum(record.status == PASS for record in records)
    failed = len(records) - passed
    if (
        document["passed"] != passed
        or document["failed"] != failed
        or document["status"] != (PASS if failed == 0 else FAIL)
    ):
        raise InteroperabilityError("interoperability artifact summary differs")
    return InteroperabilityArtifact(
        identity_hash=identity_hash,
        artifact_hash=hashlib.sha256(content).hexdigest(),
        plan_hash=plan_hash,
        status=str(document["status"]),
        passed=passed,
        failed=failed,
        records=tuple(records),
    )


def decode_interoperability_artifact(
    content: bytes,
    *,
    spec: ExperimentSpecV2,
    identity: Mapping[str, Any],
) -> InteroperabilityArtifact:
    return _decode(content, spec=spec, identity=identity)


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class InteroperabilityArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _directory(self, identity_hash: str) -> Path:
        return self.root / identity_hash

    def load_optional(
        self,
        spec: ExperimentSpecV2,
        identity: Mapping[str, Any],
    ) -> InteroperabilityArtifact | None:
        identity_hash = interoperability_identity_hash(identity)
        directory = self._directory(identity_hash)
        if not directory.exists():
            return None
        if not directory.is_dir() or directory.is_symlink():
            raise InteroperabilityError("interoperability store identity path is invalid")
        files = sorted(
            path
            for path in directory.iterdir()
            if path.is_file() and not path.is_symlink() and path.suffix == ".json"
        )
        if not files:
            return None
        if len(files) != 1:
            raise InteroperabilityError(
                "interoperability identity directory must contain exactly one artifact"
            )
        content = files[0].read_bytes()
        artifact = _decode(content, spec=spec, identity=identity)
        if files[0].stem != artifact.artifact_hash:
            raise InteroperabilityError("interoperability artifact filename hash differs")
        return replace(artifact, path=files[0])

    def refresh(
        self,
        spec: ExperimentSpecV2,
        identity: Mapping[str, Any],
        execute: Callable[[InteroperabilityTuple], tuple[str, str, Mapping[str, Any]]],
    ) -> InteroperabilityArtifact:
        identity_hash = interoperability_identity_hash(identity)
        plan = plan_interoperability(spec, identity_hash)
        plan_hash = interoperability_plan_hash(plan)
        directory = self._directory(identity_hash)
        if directory.exists() and (not directory.is_dir() or directory.is_symlink()):
            raise InteroperabilityError(
                "interoperability store identity path is invalid"
            )
        checkpoint = directory / "checkpoint.json.partial"
        records: list[InteroperabilityRecord] = []
        if checkpoint.exists():
            if not checkpoint.is_file() or checkpoint.is_symlink():
                raise InteroperabilityError("interoperability checkpoint path is invalid")
            checkpoint_content = checkpoint.read_bytes()
            if len(checkpoint_content) > MAX_ARTIFACT_BYTES:
                raise InteroperabilityError("interoperability checkpoint exceeds 64 MiB")
            try:
                document = loads_strict(checkpoint_content)
            except Exception as exc:
                raise InteroperabilityError(
                    f"interoperability checkpoint is not strict JSON: {exc}"
                ) from exc
            if canonical_bytes(document) + b"\n" != checkpoint_content:
                raise InteroperabilityError(
                    "interoperability checkpoint is not canonical"
                )
            if (
                not isinstance(document, Mapping)
                or document.get("schema_version") != CHECKPOINT_SCHEMA_VERSION
                or document.get("identity_hash") != identity_hash
                or document.get("plan_hash") != plan_hash
                or not isinstance(document.get("records"), list)
            ):
                raise InteroperabilityError("interoperability checkpoint identity differs")
            for index, row in enumerate(document["records"]):
                try:
                    record = InteroperabilityRecord(**row)
                except (TypeError, ValueError) as exc:
                    raise InteroperabilityError(
                        f"interoperability checkpoint record {index} is invalid"
                    ) from exc
                if (
                    record.status not in {PASS, FAIL}
                    or not record.reason
                    or hashlib.sha256(canonical_bytes(record.evidence)).hexdigest()
                    != record.evidence_sha256
                ):
                    raise InteroperabilityError(
                        f"interoperability checkpoint record {index} is invalid"
                    )
                records.append(record)
            prefix = plan[: len(records)]
            if len(records) > len(plan) or any(
                any(getattr(record, field) != value for field, value in asdict(planned).items())
                for record, planned in zip(records, prefix, strict=True)
            ):
                raise InteroperabilityError("interoperability checkpoint is not a plan prefix")
        pending = plan[len(records) :]
        execute_batch = getattr(execute, "execute_batch", None)
        batch_size = int(getattr(execute, "lane_count", 1))
        if batch_size not in {1, 2}:
            raise InteroperabilityError("interoperability executor lane count is invalid")
        for offset in range(0, len(pending), batch_size):
            batch = pending[offset : offset + batch_size]
            try:
                outcomes = (
                    execute_batch(batch)
                    if callable(execute_batch)
                    else [execute(planned) for planned in batch]
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:
                outcomes = [
                    (
                        FAIL,
                        f"executor_error:{type(exc).__name__}",
                        {"error": str(exc)[:512]},
                    )
                    for _planned in batch
                ]
            if not isinstance(outcomes, Sequence) or len(outcomes) != len(batch):
                raise InteroperabilityError(
                    "interoperability executor returned the wrong batch cardinality"
                )
            for planned, outcome in zip(batch, outcomes, strict=True):
                try:
                    status, reason, evidence = outcome
                    record = _record(
                        planned, status=status, reason=reason, evidence=evidence
                    )
                except (KeyboardInterrupt, SystemExit):
                    raise
                except BaseException as exc:
                    record = _record(
                        planned,
                        status=FAIL,
                        reason=f"executor_error:{type(exc).__name__}",
                        evidence={"error": str(exc)[:512]},
                    )
                records.append(record)
                _atomic_write(
                    checkpoint,
                    canonical_bytes(
                        {
                            "schema_version": CHECKPOINT_SCHEMA_VERSION,
                            "identity_hash": identity_hash,
                            "plan_hash": plan_hash,
                            "records": [asdict(item) for item in records],
                        }
                    )
                    + b"\n",
                )
        payload = _payload(identity, plan_hash, records)
        content = canonical_bytes(payload) + b"\n"
        artifact_hash = hashlib.sha256(content).hexdigest()
        final = directory / f"{artifact_hash}.json"
        existing = [
            path
            for path in directory.iterdir()
            if path.suffix == ".json" and path.name != checkpoint.name
        ]
        if any(not path.is_file() or path.is_symlink() for path in existing):
            raise InteroperabilityError("interoperability artifact path is invalid")
        if existing and (len(existing) != 1 or existing[0].read_bytes() != content):
            raise InteroperabilityError(
                "a different interoperability artifact already exists for this identity"
            )
        if not final.exists():
            _atomic_write(final, content)
        checkpoint.unlink(missing_ok=True)
        artifact = _decode(content, spec=spec, identity=identity)
        return replace(artifact, path=final)


def interoperability_check_detail(artifact: InteroperabilityArtifact) -> str:
    return (
        f"{len(artifact.records)} exact current-binary tuples: "
        f"{artifact.passed} PASS, {artifact.failed} FAIL; "
        f"artifact={artifact.artifact_hash}"
    )


class NativeInteroperabilityExecutor:
    """Run planned tuples through the common native trial/supervision path."""

    def __init__(
        self,
        *,
        root: Path,
        run_dir: Path,
        spec: ExperimentSpecV2,
        manifest: ImmutableIdentityManifest,
        identity_hash: str,
    ) -> None:
        self.root = root
        self.run_dir = run_dir
        self.spec = spec
        self.manifest = manifest
        self.identity_hash = identity_hash
        self.source: Any = None
        self.resources: Any = None
        self.resource_context: Any = None
        if not tuple(manifest.host_policy.get("lane_layout", ())):
            raise InteroperabilityError(
                "native interoperability manifest has no frozen lane"
            )
        # This is a semantic gate, not a throughput estimand. Serial execution
        # avoids cross-lane kernel work contaminating strict health evidence.
        self.lane_count = 1

    def __enter__(self) -> "NativeInteroperabilityExecutor":
        from .qualification_runner import NativeSessionObservationSource

        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.source = NativeSessionObservationSource(
            root=self.root,
            run_dir=self.run_dir,
            campaign_id=self.identity_hash,
            spec=self.spec,
            manifest=self.manifest,
        )
        self.resource_context = self.source._lane_resources(self.lane_count)
        self.resources = self.resource_context.__enter__()
        return self

    def __exit__(self, exception_type: Any, exception: Any, traceback: Any) -> bool:
        if self.resource_context is None:
            return False
        return bool(
            self.resource_context.__exit__(exception_type, exception, traceback)
        )

    def __call__(
        self, planned: InteroperabilityTuple
    ) -> tuple[str, str, Mapping[str, Any]]:
        return self._execute(planned, 0)

    def execute_batch(
        self, planned: Sequence[InteroperabilityTuple]
    ) -> list[tuple[str, str, Mapping[str, Any]]]:
        if not planned or len(planned) > self.lane_count:
            raise InteroperabilityError(
                "native interoperability batch exceeds the frozen lane count"
            )
        if len(planned) == 1:
            outcomes = [self._execute(planned[0], 0)]
        else:
            with ThreadPoolExecutor(max_workers=len(planned)) as executor:
                futures = [
                    executor.submit(self._execute, item, lane)
                    for lane, item in enumerate(planned)
                ]
                outcomes = [future.result() for future in futures]
        # Fresh endpoint teardown schedules per-CPU kernel cleanup. Keep that
        # previous-trial work outside the next trial's strict health interval.
        time.sleep(POST_TRIAL_QUIESCENCE_SECONDS)
        return outcomes

    def _execute(
        self, planned: InteroperabilityTuple, lane: int
    ) -> tuple[str, str, Mapping[str, Any]]:
        from .qualification import QualificationError
        from .qualification_runner import PhysicalQualificationUnavailable

        if self.source is None or self.resources is None:
            raise InteroperabilityError("native interoperability executor is not active")
        topologies, lane_cgroups, paths, coordinator_affinity = self.resources
        request = {
            "request_id": planned.tuple_id,
            "phase": "native_interoperability",
            "server": planned.server,
            "backend": planned.server_backend,
            "scenario": planned.scenario,
        }
        try:
            sample = self.source._lane_trial(
                request,
                reference_client=planned.reference_client,
                lane=lane,
                topology=topologies[lane],
                lane_cgroups=lane_cgroups[lane],
                path=paths[lane],
                coordinator_affinity=coordinator_affinity,
                barrier=None,
                shared_epoch=None,
                external_thermal_provider=True,
                construct_sample=True,
                allow_client_headroom_failure=True,
            )
        except PhysicalQualificationUnavailable as exc:
            return FAIL, "physical_resources_unavailable", {"error": str(exc)[:512]}
        except QualificationError as exc:
            return FAIL, "native_semantic_exercise_failed", {"error": str(exc)[:512]}
        if not isinstance(sample, Mapping) or sample.get("completion_status") != "valid":
            return FAIL, "native_result_missing_or_invalid", {
                "sample_type": type(sample).__name__
            }
        treatment = sample.get("treatment")
        roles = sample.get("roles")
        negotiated = sample.get("negotiated")
        units = sample.get("units")
        runtime = sample.get("runtime")
        if not all(
            isinstance(value, Mapping)
            for value in (treatment, roles, negotiated, units, runtime)
        ):
            return FAIL, "native_result_evidence_missing", {
                "sample_sha256": hashlib.sha256(canonical_bytes(sample)).hexdigest()
            }
        if (
            treatment.get("scenario") != planned.scenario
            or treatment.get("server_backend") != planned.server_backend
            or treatment.get("reference_client_backend")
            != planned.reference_client_backend
            or negotiated.get("settings_match") is not True
            or sample.get("termination_reason") != "deadline_reached"
            or int(units.get("completed", 0)) <= 0
        ):
            return FAIL, "native_result_semantic_attestation_failed", {
                "sample_sha256": hashlib.sha256(canonical_bytes(sample)).hexdigest(),
                "treatment": treatment,
                "roles": roles,
                "negotiated": negotiated,
                "units": units,
            }
        evidence = {
            "sample_sha256": hashlib.sha256(canonical_bytes(sample)).hexdigest(),
            "server_binary_sha256": roles["server_binary_sha256"],
            "reference_client_binary_sha256": roles[
                "reference_client_binary_sha256"
            ],
            "server_config_hash": treatment["server_config_hash"],
            "reference_client_config_hash": treatment[
                "reference_client_config_hash"
            ],
            "tls_hash": treatment["tls_hash"],
            "path_hash": treatment["path_hash"],
            "completed": int(units["completed"]),
            "negotiated_settings_match": True,
            "cleanup_attested": True,
            "cgroup_throttled_ns": int(
                sample.get("telemetry", {}).get("cgroup_throttled_ns", 0)
            ),
            "cgroup_nr_throttled": int(
                sample.get("telemetry", {}).get("cgroup_nr_throttled", 0)
            ),
            "measurement_ns": int(runtime["measurement_ns"]),
        }
        return PASS, "native_semantic_exercise_passed", evidence


def refresh_native_interoperability(
    *,
    root: Path,
    store_root: Path,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
) -> InteroperabilityArtifact:
    identity = build_interoperability_identity(spec, manifest)
    identity_hash = interoperability_identity_hash(identity)
    run_dir = store_root / "runs" / identity_hash
    store = InteroperabilityArtifactStore(store_root / "artifacts")
    with NativeInteroperabilityExecutor(
        root=root,
        run_dir=run_dir,
        spec=spec,
        manifest=manifest,
        identity_hash=identity_hash,
    ) as execute:
        return store.refresh(spec, identity, execute)


def load_native_interoperability(
    *,
    store_root: Path,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
) -> InteroperabilityArtifact | None:
    identity = build_interoperability_identity(spec, manifest)
    return InteroperabilityArtifactStore(store_root / "artifacts").load_optional(
        spec, identity
    )
