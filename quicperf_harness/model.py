"""Immutable value models shared by v2 planning and persistence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


JsonScalar = None | bool | int | str
FrozenJson = JsonScalar | tuple["FrozenJson", ...] | Mapping[str, "FrozenJson"]


def freeze_json(value: Any) -> FrozenJson:
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class PathProfile:
    name: str
    content_hash: str
    trace_policy: str
    trace_seed_derivation: str
    one_way_delay_ns: int
    loss_percent: str
    dynamic: bool


@dataclass(frozen=True, slots=True)
class ExpectedCardinality:
    planned_trials: int
    maximum_trial_ids: int
    committed_samples: int
    sessions: int
    williams_rows: int


@dataclass(frozen=True, slots=True)
class ExperimentSpecV2:
    schema_version: str
    control_protocol_version: str
    name: str
    campaign_kind: str
    estimand: str
    servers: tuple[str, ...]
    reference_clients: tuple[str, ...]
    scenarios: tuple[str, ...]
    server_backends: tuple[str, ...]
    reference_client_backend: str
    paths: tuple[PathProfile, ...]
    expected_cardinality: ExpectedCardinality
    raw: Mapping[str, FrozenJson]


@dataclass(frozen=True, slots=True)
class ImmutableIdentityManifest:
    schema_version: str
    source: Mapping[str, FrozenJson]
    binaries: tuple[Mapping[str, FrozenJson], ...]
    dependencies: tuple[Mapping[str, FrozenJson], ...]
    toolchains: tuple[Mapping[str, FrozenJson], ...]
    protocols: Mapping[str, FrozenJson]
    host_policy: Mapping[str, FrozenJson]
    path_profiles: tuple[Mapping[str, FrozenJson], ...]
    raw: Mapping[str, FrozenJson]
