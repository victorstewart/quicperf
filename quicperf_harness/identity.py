"""Domain-separated v2 content identities."""

from __future__ import annotations

import hashlib
import struct
from typing import Any

from .canonical import canonical_bytes
from .errors import CanonicalizationError


PREFIX = b"quicperf-v2\0"


def domain_digest(tag: str, *fields: bytes) -> bytes:
    """Implement the length-delimited H(tag, fields...) construction."""

    if not isinstance(tag, str) or not tag:
        raise CanonicalizationError("identity tag must be a non-empty string")
    try:
        tag_bytes = tag.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("identity tag is not valid UTF-8") from exc
    digest = hashlib.sha256()
    digest.update(PREFIX)
    digest.update(struct.pack(">I", len(tag_bytes)))
    digest.update(tag_bytes)
    for field in fields:
        if not isinstance(field, bytes):
            raise CanonicalizationError("identity fields must be bytes")
        digest.update(struct.pack(">Q", len(field)))
        digest.update(field)
    return digest.digest()


def domain_hash(tag: str, *fields: bytes) -> str:
    return domain_digest(tag, *fields).hex()


def _digest_bytes(value: str, name: str) -> bytes:
    if len(value) != 64:
        raise CanonicalizationError(f"{name} must be a full SHA-256 hex digest")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise CanonicalizationError(f"{name} must be hexadecimal") from exc


def spec_hash(canonical_spec: Any) -> str:
    return domain_hash("spec", canonical_bytes(canonical_spec))


def identity_manifest_hash(canonical_manifest: Any) -> str:
    return domain_hash("identity-manifest", canonical_bytes(canonical_manifest))


def analysis_plan_hash(canonical_analysis_plan: Any) -> str:
    return domain_hash("analysis-plan", canonical_bytes(canonical_analysis_plan))


def schedule_basis_hash(
    spec_hash_hex: str,
    manifest_hash_hex: str,
    analysis_hash_hex: str,
    campaign_seed: bytes,
) -> str:
    return domain_hash(
        "schedule-basis",
        _digest_bytes(spec_hash_hex, "spec_hash"),
        _digest_bytes(manifest_hash_hex, "identity_manifest_hash"),
        _digest_bytes(analysis_hash_hex, "analysis_plan_hash"),
        campaign_seed,
    )


def cell_id(treatment: Any) -> str:
    return domain_hash("cell", canonical_bytes(treatment))


def microblock_id(
    schedule_basis_hash_hex: str,
    coordinates: Any,
    slot: str,
) -> str:
    if slot not in {"primary", "retry"}:
        raise CanonicalizationError("microblock slot must be primary or retry")
    return domain_hash(
        "microblock",
        _digest_bytes(schedule_basis_hash_hex, "schedule_basis_hash"),
        canonical_bytes(coordinates),
        slot.encode("ascii"),
    )


def trial_id(
    schedule_basis_hash_hex: str,
    session: int,
    microblock_id_hex: str,
    cell_id_hex: str,
    warmup: bool,
) -> str:
    if isinstance(session, bool) or not 0 <= session <= 0xFFFFFFFF:
        raise CanonicalizationError("session must fit an unsigned 32-bit integer")
    return domain_hash(
        "trial",
        _digest_bytes(schedule_basis_hash_hex, "schedule_basis_hash"),
        struct.pack(">I", session),
        _digest_bytes(microblock_id_hex, "microblock_id"),
        _digest_bytes(cell_id_hex, "cell_id"),
        bytes((int(warmup),)),
    )


def schedule_hash(schedule: Any) -> str:
    return domain_hash("schedule", canonical_bytes(schedule))


def campaign_id(
    spec_hash_hex: str,
    manifest_hash_hex: str,
    analysis_hash_hex: str,
    schedule_hash_hex: str,
) -> str:
    return domain_hash(
        "campaign",
        _digest_bytes(spec_hash_hex, "spec_hash"),
        _digest_bytes(manifest_hash_hex, "identity_manifest_hash"),
        _digest_bytes(analysis_hash_hex, "analysis_plan_hash"),
        _digest_bytes(schedule_hash_hex, "schedule_hash"),
    )


def attempt_id(trial_id_hex: str, attempt_number: int) -> str:
    if isinstance(attempt_number, bool) or not 0 <= attempt_number <= 0xFFFFFFFF:
        raise CanonicalizationError("attempt number must fit an unsigned 32-bit integer")
    return domain_hash(
        "attempt",
        _digest_bytes(trial_id_hex, "trial_id"),
        struct.pack(">I", attempt_number),
    )
