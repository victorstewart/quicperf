"""Qualification evidence evaluation and exact-identity artifact acquisition."""

from __future__ import annotations

from dataclasses import fields, replace
from decimal import Decimal, InvalidOperation
import hashlib
from pathlib import Path
import stat
from typing import Any, Callable, Mapping, Sequence, TypeVar

from .canonical import canonical_bytes, loads_strict, normalize_decimal
from .errors import IdentityMismatchError
from .journal import Journal
from .qualification import (
    ARTIFACT_KINDS,
    EnduranceCheckpointEvidence,
    HeadroomPairEvidence,
    HeadroomScreenEvidence,
    LanePairEvidence,
    LaneScreenEvidence,
    LeakSlopeEvidence,
    QualificationArtifactStore,
    QualificationDecision,
    QualificationError,
    ResetCycleEvidence,
    ReuseParityEvidence,
    WindowContrastEvidence,
    WindowPairEvidence,
    WindowScreenEvidence,
    build_qualification_identity,
    decode_qualification_artifact,
    encode_qualification_artifact,
    evaluate_client_headroom,
    evaluate_lane_interference,
    evaluate_tail_window_adequacy,
    evaluate_window_equivalence,
    evaluate_worker_reuse,
    qualification_identity_hash,
    worker_reuse_eligible_scenario,
)
from .tail_window import TailHeldOutBlock, TailPrefixObservation, TailScreenCell
from .runner import _persisted_run_identity


EVIDENCE_SCHEMA_VERSION = "quicperf.qualification-evidence.v1"
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_T = TypeVar("_T")


def _object(
    value: Any,
    *,
    required: set[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise QualificationError(f"{label} must be an object")
    if set(value) != required:
        missing = sorted(required - set(value))
        unknown = sorted(set(value) - required)
        detail = []
        if missing:
            detail.append("missing " + ",".join(missing))
        if unknown:
            detail.append("unknown " + ",".join(unknown))
        raise QualificationError(f"{label} fields are invalid: {'; '.join(detail)}")
    return value


def _array(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise QualificationError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 256:
        raise QualificationError(f"{label} must be a nonempty string of at most 256 bytes")
    return value


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise QualificationError(f"{label} must be an integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{label} must be boolean")
    return value


def _decimal(value: Any, label: str) -> str | int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise QualificationError(f"{label} must be an integer or canonical decimal string")
    if isinstance(value, int):
        return value
    try:
        normalize_decimal(value)
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise QualificationError(f"{label} must be a finite canonical decimal") from exc
    if not parsed.is_finite():
        raise QualificationError(f"{label} must be finite")
    return value


def _decimals(value: Any, label: str) -> tuple[str | int, ...]:
    return tuple(_decimal(item, f"{label}[]") for item in _array(value, label))


def _classifications(value: Any, label: str) -> tuple[tuple[str, str], ...]:
    result = []
    for index, item in enumerate(_array(value, label)):
        pair = _array(item, f"{label}[{index}]")
        if len(pair) != 2:
            raise QualificationError(f"{label}[{index}] must contain exactly two values")
        result.append(
            (
                _string(pair[0], f"{label}[{index}][0]"),
                _string(pair[1], f"{label}[{index}][1]"),
            )
        )
    return tuple(result)


def _tail_prefixes(value: Any, label: str) -> tuple[TailPrefixObservation, ...]:
    required = {
        "duration_seconds",
        "eligible_operations",
        "failed_or_censored_operations",
        "p99_ns",
        "validity_classification",
        "capped_or_stalled",
    }
    result = []
    for index, item in enumerate(_array(value, label)):
        item_label = f"{label}[{index}]"
        document = _object(item, required=required, label=item_label)
        result.append(
            TailPrefixObservation(
                duration_seconds=_integer(
                    document["duration_seconds"], f"{item_label}.duration_seconds"
                ),
                eligible_operations=_integer(
                    document["eligible_operations"],
                    f"{item_label}.eligible_operations",
                ),
                failed_or_censored_operations=_integer(
                    document["failed_or_censored_operations"],
                    f"{item_label}.failed_or_censored_operations",
                ),
                p99_ns=_integer(document["p99_ns"], f"{item_label}.p99_ns"),
                validity_classification=_string(
                    document["validity_classification"],
                    f"{item_label}.validity_classification",
                ),
                capped_or_stalled=_boolean(
                    document["capped_or_stalled"],
                    f"{item_label}.capped_or_stalled",
                ),
            )
        )
    return tuple(result)


def _records(
    value: Any,
    record_type: type[_T],
    converters: Mapping[str, Callable[[Any, str], Any]],
    label: str,
) -> tuple[_T, ...]:
    expected = {field.name for field in fields(record_type)}
    if set(converters) != expected:
        raise AssertionError(f"internal converter mismatch for {record_type.__name__}")
    result = []
    for index, item in enumerate(_array(value, label)):
        record_label = f"{label}[{index}]"
        document = _object(item, required=expected, label=record_label)
        result.append(
            record_type(
                **{
                    name: converter(document[name], f"{record_label}.{name}")
                    for name, converter in converters.items()
                }
            )
        )
    return tuple(result)


def _record(
    value: Any,
    record_type: type[_T],
    converters: Mapping[str, Callable[[Any, str], Any]],
    label: str,
) -> _T:
    records = _records([value], record_type, converters, label)
    return records[0]


_RESET_CONVERTERS = {
    "adapter": _string,
    "backend": _string,
    "scenario": _string,
    "cycle": _integer,
    "live_connections": _integer,
    "live_streams": _integer,
    "live_tickets": _integer,
    "work_inventory": _integer,
}
_ENDURANCE_CONVERTERS = {
    "adapter": _string,
    "backend": _string,
    "cycle": _integer,
    "baseline_fd_count": _integer,
    "fd_count": _integer,
    "live_connections": _integer,
    "live_streams": _integer,
    "live_tickets": _integer,
    "baseline_memory_bytes": _integer,
    "reset_memory_bytes": _integer,
}
_PARITY_CONVERTERS = {
    "adapter": _string,
    "backend": _string,
    "sentinel": _string,
    "paired_blocks": _integer,
    "interval_low_ratio": _decimal,
    "interval_high_ratio": _decimal,
    "reordered_ratio": _decimal,
    "confidence_level": _decimal,
}
_LEAK_CONVERTERS = {
    "adapter": _string,
    "backend": _string,
    "baseline_memory_bytes": _integer,
    "interval_low_bytes_per_cycle": _decimal,
    "interval_high_bytes_per_cycle": _decimal,
    "confidence_level": _decimal,
}
_HEADROOM_SCREEN_CONVERTERS = {
    "server": _string,
    "backend": _string,
    "scenario": _string,
    "client_cpu_ns_per_wall_ns": _decimal,
}
_HEADROOM_PAIR_CONVERTERS = {
    "server": _string,
    "backend": _string,
    "scenario": _string,
    "blocks": _integer,
    "treatment_client_cores": _integer,
    "treatment_p95_cpu": _decimals,
}
_LANE_SCREEN_CONVERTERS = {
    "server": _string,
    "backend": _string,
    "scenario": _string,
    "pressure": _decimal,
}
_LANE_PAIR_CONVERTERS = {
    "dimension": _string,
    "server": _string,
    "backend": _string,
    "scenario": _string,
    "paired_blocks": _integer,
    "rate_interval_low_ratio": _decimal,
    "rate_interval_high_ratio": _decimal,
    "memory_interval_low_ratio": _decimal,
    "memory_interval_high_ratio": _decimal,
    "one_lane_variance": _decimal,
    "two_lane_variance": _decimal,
    "one_lane_ci_width": _decimal,
    "two_lane_ci_width": _decimal,
    "confidence_level": _decimal,
}
_WINDOW_SCREEN_CONVERTERS = {
    "server": _string,
    "backend": _string,
    "scenario": _string,
    "short_rate": _decimal,
    "reference_rate": _decimal,
    "short_classification": _string,
    "reference_classification": _string,
    "cap_hit": _boolean,
    "stalled": _boolean,
    "short_window_seconds": _integer,
    "reference_window_seconds": _integer,
}
_WINDOW_PAIR_CONVERTERS = {
    "server": _string,
    "backend": _string,
    "scenario": _string,
    "paired_blocks": _integer,
    "interval_low_ratio": _decimal,
    "interval_high_ratio": _decimal,
    "short_log_variance": _decimal,
    "reference_log_variance": _decimal,
    "classifications": _classifications,
    "confidence_level": _decimal,
}
_WINDOW_CONTRAST_CONVERTERS = {
    "backend": _string,
    "scenario": _string,
    "selected_server": _string,
    "baseline_server": _string,
    "paired_blocks": _integer,
    "interval_low_ratio": _decimal,
    "interval_high_ratio": _decimal,
    "confidence_level": _decimal,
}
_TAIL_SCREEN_CONVERTERS = {
    "scenario": _string,
    "server": _string,
    "server_backend": _string,
    "reference_client": _string,
    "prefixes": _tail_prefixes,
}
_TAIL_HELD_CONVERTERS = {
    **_TAIL_SCREEN_CONVERTERS,
    "block": _integer,
}


def _read_evidence(path: Path, kind: str, expected_identity_hash: str) -> tuple[Mapping[str, Any], bytes]:
    if kind not in ARTIFACT_KINDS:
        raise QualificationError(f"unknown qualification kind {kind!r}")
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise QualificationError("qualification evidence must be a regular non-symlink file")
        if metadata.st_size > MAX_EVIDENCE_BYTES:
            raise QualificationError("qualification evidence exceeds the 8 MiB bound")
        content = path.read_bytes()
    except QualificationError:
        raise
    except OSError as exc:
        raise QualificationError(f"cannot read qualification evidence: {exc}") from exc
    try:
        document = loads_strict(content)
    except Exception as exc:
        raise QualificationError(f"qualification evidence is not strict JSON: {exc}") from exc
    document = _object(
        document,
        required={"schema_version", "artifact_kind", "identity_hash", "inputs"},
        label="qualification evidence",
    )
    if canonical_bytes(document) + b"\n" != content:
        raise QualificationError("qualification evidence is not canonical")
    if document["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise QualificationError("qualification evidence schema version is not supported")
    if document["artifact_kind"] != kind:
        raise QualificationError("qualification evidence kind mismatch")
    if document["identity_hash"] != expected_identity_hash:
        raise QualificationError("qualification evidence identity mismatch")
    return document, content


def _evaluate(kind: str, inputs: Any, spec: Any) -> QualificationDecision:
    servers = tuple(spec.servers)
    backends = tuple(spec.server_backends)
    if kind == "worker-reuse":
        value = _object(
            inputs,
            required={"reset_cycles", "endurance_checkpoints", "parity", "leak_slopes"},
            label="worker-reuse inputs",
        )
        return evaluate_worker_reuse(
            expected_reset_cells=tuple(
                (adapter, backend, scenario)
                for adapter in servers
                for backend in backends
                for scenario in filter(worker_reuse_eligible_scenario, spec.scenarios)
            ),
            expected_adapter_backends=tuple(
                (adapter, backend) for adapter in servers for backend in backends
            ),
            reset_cycles=_records(
                value["reset_cycles"], ResetCycleEvidence, _RESET_CONVERTERS, "reset_cycles"
            ),
            endurance_checkpoints=_records(
                value["endurance_checkpoints"],
                EnduranceCheckpointEvidence,
                _ENDURANCE_CONVERTERS,
                "endurance_checkpoints",
            ),
            parity=_records(value["parity"], ReuseParityEvidence, _PARITY_CONVERTERS, "parity"),
            leak_slopes=_records(
                value["leak_slopes"], LeakSlopeEvidence, _LEAK_CONVERTERS, "leak_slopes"
            ),
        )
    if kind == "client-headroom":
        value = _object(
            inputs,
            required={"screens", "held_out"},
            label="client-headroom inputs",
        )
        return evaluate_client_headroom(
            servers=servers,
            backends=backends,
            treatment_client_cores=int(
                spec.raw["treatment"]["resources"]["client_physical_cores"]
            ),
            screens=_records(
                value["screens"],
                HeadroomScreenEvidence,
                _HEADROOM_SCREEN_CONVERTERS,
                "screens",
            ),
            held_out=_record(
                value["held_out"],
                HeadroomPairEvidence,
                _HEADROOM_PAIR_CONVERTERS,
                "held_out",
            ),
        )
    if kind == "lane-interference":
        value = _object(
            inputs,
            required={"screens", "held_out"},
            label="lane-interference inputs",
        )
        return evaluate_lane_interference(
            servers=servers,
            backends=backends,
            screens=_records(
                value["screens"], LaneScreenEvidence, _LANE_SCREEN_CONVERTERS, "screens"
            ),
            held_out=_records(
                value["held_out"], LanePairEvidence, _LANE_PAIR_CONVERTERS, "held_out"
            ),
        )
    if kind == "window-qualification":
        value = _object(
            inputs,
            required={"screens", "held_out", "contrasts"},
            label="window-qualification inputs",
        )
        return evaluate_window_equivalence(
            servers=servers,
            backends=backends,
            scenarios=tuple(spec.scenarios),
            baseline_server="ngtcp2perf",
            screens=_records(
                value["screens"], WindowScreenEvidence, _WINDOW_SCREEN_CONVERTERS, "screens"
            ),
            held_out=_records(
                value["held_out"], WindowPairEvidence, _WINDOW_PAIR_CONVERTERS, "held_out"
            ),
            contrasts=_records(
                value["contrasts"],
                WindowContrastEvidence,
                _WINDOW_CONTRAST_CONVERTERS,
                "contrasts",
            ),
        )
    if kind == "tail-window":
        value = _object(
            inputs,
            required={"screens", "held_out"},
            label="tail-window inputs",
        )
        return evaluate_tail_window_adequacy(
            screens=_records(
                value["screens"],
                TailScreenCell,
                _TAIL_SCREEN_CONVERTERS,
                "screens",
            ),
            held_out=_records(
                value["held_out"],
                TailHeldOutBlock,
                _TAIL_HELD_CONVERTERS,
                "held_out",
            ),
        )
    raise QualificationError(f"unknown qualification kind {kind!r}")


def evaluate_qualification_inputs(
    kind: str, inputs: Any, spec: Any
) -> QualificationDecision:
    """Evaluate coordinator-derived inputs through the strict public gate."""

    return _evaluate(kind, inputs, spec)


def _journal_artifact(
    journal: Journal,
    campaign_id: str,
    kind: str,
    identity: Mapping[str, Any],
) -> tuple[QualificationDecision, str, bytes] | None:
    row = journal.connection.execute(
        "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
        (campaign_id, f"qualification/{kind}.json"),
    ).fetchone()
    if row is None:
        return None
    content = bytes(row["content"])
    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        raise IdentityMismatchError(f"stored {kind} qualification artifact checksum mismatch")
    decision, artifact_hash, _identity_hash = decode_qualification_artifact(
        content,
        expected_kind=kind,
        expected_identity=identity,
    )
    return decision, artifact_hash, content


def store_qualification_evidence(
    *,
    run_dir: Path,
    kind: str,
    evidence_path: Path,
    artifact_store: Path,
) -> dict[str, Any]:
    if kind == "host-stability":
        raise QualificationError(
            "host-stability is live-only; use qualification run so raw AMD "
            "calibration and negative-control evidence is collected on this boot"
        )
    with Journal(run_dir) as journal:
        spec, manifest, _schedule = _persisted_run_identity(journal, run_dir)
        identity = build_qualification_identity(kind, spec, manifest)
        identity_hash = qualification_identity_hash(kind, identity)
        document, content = _read_evidence(evidence_path, kind, identity_hash)
        decision = _evaluate(kind, document["inputs"], spec)
        decision = replace(
            decision,
            evidence={
                "evaluation": decision.evidence,
                "input_sha256": hashlib.sha256(content).hexdigest(),
                "inputs": document["inputs"],
            },
        )
        stored = QualificationArtifactStore(artifact_store).store(kind, identity, decision)
    return {
        "schema_version": "quicperf.qualification-command.v1",
        "operation": "store",
        "artifact_kind": kind,
        "status": decision.status,
        "qualified": decision.qualified,
        "reasons": list(decision.reasons),
        "identity_hash": stored.identity_hash,
        "artifact_hash": stored.artifact_hash,
        "artifact_path": str(stored.path),
    }


def acquire_qualification_artifact(
    *,
    run_dir: Path,
    kind: str,
    artifact_store: Path,
) -> dict[str, Any]:
    with Journal(run_dir) as journal:
        spec, manifest, _schedule = _persisted_run_identity(journal, run_dir)
        campaign = journal.connection.execute("SELECT campaign_id FROM campaign").fetchone()
        if campaign is None:
            raise IdentityMismatchError("run journal has no campaign")
        campaign_id = str(campaign["campaign_id"])
        identity = build_qualification_identity(kind, spec, manifest)
        stored = QualificationArtifactStore(artifact_store).load(kind, identity)
        content, artifact_hash, identity_hash = encode_qualification_artifact(
            kind,
            identity,
            stored.decision,
        )
        decision = stored.decision
        if (artifact_hash, identity_hash) != (stored.artifact_hash, stored.identity_hash):
            raise QualificationError("qualification artifact changed during acquisition")
        existing = _journal_artifact(journal, campaign_id, kind, identity)
        if existing is not None and existing[2] != content:
            raise IdentityMismatchError(
                f"journal {kind} qualification is already bound to different artifact bytes"
            )
        if existing is None:
            journal.store_artifact(
                campaign_id,
                f"qualification/{kind}.json",
                content,
                media_type="application/json",
            )
        journal.integrity_check()
    return {
        "schema_version": "quicperf.qualification-command.v1",
        "operation": "acquire",
        "artifact_kind": kind,
        "status": decision.status,
        "qualified": decision.qualified,
        "reasons": list(decision.reasons),
        "identity_hash": identity_hash,
        "artifact_hash": artifact_hash,
        "journal_path": f"qualification/{kind}.json",
        "acquired": True,
    }


def qualification_status(
    *,
    run_dir: Path,
    kind: str,
    artifact_store: Path,
) -> dict[str, Any]:
    with Journal(run_dir) as journal:
        spec, manifest, _schedule = _persisted_run_identity(journal, run_dir)
        campaign = journal.connection.execute("SELECT campaign_id FROM campaign").fetchone()
        if campaign is None:
            raise IdentityMismatchError("run journal has no campaign")
        campaign_id = str(campaign["campaign_id"])
        identity = build_qualification_identity(kind, spec, manifest)
        identity_hash = qualification_identity_hash(kind, identity)
        acquired = _journal_artifact(journal, campaign_id, kind, identity)
        available = QualificationArtifactStore(artifact_store).load_optional(kind, identity)
        if acquired is not None and available is not None:
            if acquired[1] != available.artifact_hash:
                raise IdentityMismatchError(
                    f"journal and content store disagree for {kind} qualification"
                )
        source = acquired if acquired is not None else (
            (available.decision, available.artifact_hash, b"")
            if available is not None
            else None
        )
    if source is None:
        return {
            "schema_version": "quicperf.qualification-command.v1",
            "operation": "status",
            "artifact_kind": kind,
            "status": "not_run",
            "qualified": False,
            "reasons": ["physical qualification has not produced an exact-identity artifact"],
            "identity_hash": identity_hash,
            "artifact_hash": None,
            "stored": False,
            "acquired": False,
        }
    decision, artifact_hash, _content = source
    return {
        "schema_version": "quicperf.qualification-command.v1",
        "operation": "status",
        "artifact_kind": kind,
        "status": decision.status,
        "qualified": decision.qualified,
        "reasons": list(decision.reasons),
        "identity_hash": identity_hash,
        "artifact_hash": artifact_hash,
        "stored": available is not None,
        "acquired": acquired is not None,
    }
