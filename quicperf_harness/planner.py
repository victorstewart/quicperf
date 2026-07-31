"""Deterministic v2 publication planning.

The planner is outcome-free: every primary and dormant retry coordinate is
materialized from immutable inputs before a benchmark result exists.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from typing import Iterable, Mapping, Sequence

from .canonical import canonical_bytes
from .identity import domain_digest
from .scheduler import LaneItem, ScheduleError, balanced_lane_assignments


CANONICAL_SERVERS = (
    "ngtcp2perf",
    "lsperf",
    "tquicperf",
    "quicheperf",
    "picoperf",
    "xquicperf",
    "quinnperf",
    "s2nperf",
    "neqoperf",
    "noqperf",
    "quiczigperf",
    "mvfstperf",
)
REFERENCE_CLIENTS = ("ngtcp2perf", "picoperf")
SERVER_BACKENDS = ("syscall", "iouring")
ONE_BACKEND_SERVER_BACKENDS = ("iouring",)
PUBLICATION_SCENARIOS = (
    "download",
    "upload",
    "multistream_download",
    "multistream_upload",
    "bidi",
    "loss_recovery",
    "flow_control",
    "small_payload_pps",
    "datagram",
    "reqresp",
    "stream_churn",
    "close_reset_cleanup",
    "connect",
    "resumed_connect",
    "zero_rtt_reqresp",
)
PUBLICATION_ESTIMAND = "fixed_treatment_server"
BALANCE_CONTROL_ESTIMAND = "parallel_balance_control"
PUBLICATION_BALANCE_CONTROL_TRIALS = 576
FIXED_CONCURRENCY = 16
CANONICAL_PATH_HASHES = {
    "loopback": bytes.fromhex(
        "d0f5773c884ea4961eccf552169eccefd110a890093237b14fa9b7a08e200668"
    ),
    "loss_recovery_v1": bytes.fromhex(
        "b9256fd84288033f77b70da4e89b057c6836c713671a8fe5b4f54a658949e4f9"
    ),
}


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def tagged_hash(tag: str, *fields: bytes) -> bytes:
    """The length-prefixed H primitive prescribed by the v2 identity policy."""

    return domain_digest(tag, *fields)


def _json_bytes(value: object) -> bytes:
    return canonical_bytes(value)


def _hmac(seed: bytes, label: bytes, suffix: bytes = b"") -> bytes:
    return hmac.new(seed, label + suffix, hashlib.sha256).digest()


def williams_base(n: int) -> tuple[int, ...]:
    if n <= 0 or n % 2:
        raise ScheduleError("Williams base requires a positive even treatment count")
    result = [0]
    low, high = 1, n - 1
    take_low = True
    while len(result) < n:
        if take_low:
            result.append(low)
            low += 1
        else:
            result.append(high)
            high -= 1
        take_low = not take_low
    return tuple(result)


def williams_rows(treatments: Sequence[str]) -> tuple[tuple[str, ...], ...]:
    n = len(treatments)
    base = williams_base(n)
    return tuple(
        tuple(treatments[(index + row) % n] for index in base)
        for row in range(n)
    )


def diagnostic_cyclic_rows(treatments: Sequence[str]) -> tuple[tuple[str, ...], ...]:
    """Position-balanced rows for noncanonical odd/subset diagnostics."""

    if not treatments:
        raise ScheduleError("at least one treatment is required")
    n = len(treatments)
    return tuple(
        tuple(treatments[(position + row) % n] for position in range(n))
        for row in range(n)
    )


@dataclass(frozen=True)
class WilliamsAssignment:
    row_index: int
    sort_key: str
    session: int
    session_position: int
    reference_client: str
    server_order: tuple[str, ...]


def assign_williams_rows(
    servers: Sequence[str], campaign_seed: bytes
) -> tuple[WilliamsAssignment, ...]:
    if not campaign_seed:
        raise ScheduleError("campaign_seed must not be empty")
    rows = williams_rows(servers) if len(servers) % 2 == 0 else diagnostic_cyclic_rows(servers)
    keyed = sorted(
        (
            _hmac(campaign_seed, b"williams-row", _u32(row_index)),
            row_index,
            row,
        )
        for row_index, row in enumerate(rows)
    )
    assignments: list[WilliamsAssignment] = []
    session_one_clients = {
        row_index: REFERENCE_CLIENTS[sorted_index % len(REFERENCE_CLIENTS)]
        for sorted_index, (_, row_index, _) in enumerate(keyed)
    }
    for session, ordered in ((1, keyed), (2, tuple(reversed(keyed)))):
        for session_position, (sort_key, row_index, row) in enumerate(ordered):
            reference_client = session_one_clients[row_index]
            if session == 2:
                reference_client = REFERENCE_CLIENTS[
                    1 - REFERENCE_CLIENTS.index(reference_client)
                ]
            assignments.append(
                WilliamsAssignment(
                    row_index=row_index,
                    sort_key=sort_key.hex(),
                    session=session,
                    session_position=session_position,
                    reference_client=reference_client,
                    server_order=row,
                )
            )
    return tuple(assignments)


def assign_noninferential_williams_rows(
    servers: Sequence[str], campaign_seed: bytes
) -> tuple[WilliamsAssignment, ...]:
    """Retain the bounded 12-row split used by noninferential qualifications."""

    if not campaign_seed:
        raise ScheduleError("campaign_seed must not be empty")
    rows = (
        williams_rows(servers)
        if len(servers) % 2 == 0
        else diagnostic_cyclic_rows(servers)
    )
    keyed = sorted(
        (
            _hmac(campaign_seed, b"williams-row", _u32(row_index)),
            row_index,
            row,
        )
        for row_index, row in enumerate(rows)
    )
    split = len(keyed) // 2
    assignments = []
    for sorted_index, (sort_key, row_index, row) in enumerate(keyed):
        session = 1 if sorted_index < split else 2
        session_position = sorted_index if session == 1 else sorted_index - split
        client_index = session_position % 2
        if session == 2:
            client_index = 1 - client_index
        assignments.append(
            WilliamsAssignment(
                row_index=row_index,
                sort_key=sort_key.hex(),
                session=session,
                session_position=session_position,
                reference_client=REFERENCE_CLIENTS[client_index],
                server_order=row,
            )
        )
    return tuple(assignments)


@dataclass(frozen=True)
class TrialCoordinate:
    trial_id: str
    cell_id: str
    microblock_id: str
    logical_microblock_id: str
    superblock_id: str
    slot: str
    estimand: str
    scenario: str
    path_profile: str
    fixed_concurrency: int
    reference_client: str
    reference_client_backend: str
    session: int
    williams_row: int
    server_position: int
    server: str
    server_backend: str
    backend_order: int


@dataclass(frozen=True)
class PublicationMicroblock:
    microblock_id: str
    logical_id: str
    superblock_id: str
    slot: str
    estimand: str
    scenario: str
    path_profile: str
    fixed_concurrency: int
    reference_client: str
    session: int
    session_position: int
    williams_row: int
    server_order: tuple[str, ...]
    lane: int
    parallel_epoch_id: str | None
    parallel_epoch_ordinal: int | None
    parallel_lane_ordinal: int | None
    trace_seed: str
    trials: tuple[TrialCoordinate, ...]


@dataclass(frozen=True)
class PublicationSchedule:
    campaign_seed: str
    schedule_basis_hash: str
    servers: tuple[str, ...]
    scenarios: tuple[str, ...]
    server_backends: tuple[str, ...]
    reference_clients: tuple[str, ...]
    qualified_lane_count: int
    publication_eligible: bool
    microblocks: tuple[PublicationMicroblock, ...]

    @property
    def primary_microblocks(self) -> tuple[PublicationMicroblock, ...]:
        return tuple(
            block
            for block in self.microblocks
            if block.slot == "primary" and block.estimand == PUBLICATION_ESTIMAND
        )

    @property
    def retry_microblocks(self) -> tuple[PublicationMicroblock, ...]:
        return tuple(
            block
            for block in self.microblocks
            if block.slot == "retry" and block.estimand == PUBLICATION_ESTIMAND
        )

    @property
    def balance_control_microblocks(self) -> tuple[PublicationMicroblock, ...]:
        return tuple(
            block
            for block in self.microblocks
            if block.estimand == BALANCE_CONTROL_ESTIMAND
        )

    @property
    def primary_trials(self) -> tuple[TrialCoordinate, ...]:
        return tuple(trial for block in self.primary_microblocks for trial in block.trials)

    @property
    def retry_trials(self) -> tuple[TrialCoordinate, ...]:
        return tuple(trial for block in self.retry_microblocks for trial in block.trials)

    def canonical_bytes(self) -> bytes:
        payload = {
            "campaign_seed": self.campaign_seed,
            "schedule_basis_hash": self.schedule_basis_hash,
            "servers": self.servers,
            "scenarios": self.scenarios,
            "server_backends": self.server_backends,
            "reference_clients": self.reference_clients,
            "qualified_lane_count": self.qualified_lane_count,
            "publication_eligible": self.publication_eligible,
            "microblocks": [asdict(block) for block in self.microblocks],
        }
        return canonical_bytes(payload)

    @property
    def schedule_hash(self) -> str:
        return tagged_hash("schedule", self.canonical_bytes()).hex()


def publication_design_eligible(
    servers: Sequence[str],
    scenarios: Sequence[str],
    server_backends: Sequence[str],
    reference_clients: Sequence[str],
) -> bool:
    return (
        tuple(servers) == CANONICAL_SERVERS
        and tuple(scenarios) == PUBLICATION_SCENARIOS
        and tuple(server_backends) in {
            SERVER_BACKENDS,
            ONE_BACKEND_SERVER_BACKENDS,
        }
        and tuple(reference_clients) == REFERENCE_CLIENTS
    )


def _backend_order(
    row_index: int, position: int, backends: Sequence[str], session: int
) -> tuple[str, ...]:
    if tuple(backends) != SERVER_BACKENDS:
        return tuple(backends)
    order = (
        SERVER_BACKENDS
        if (row_index + position) % 2 == 0
        else tuple(reversed(SERVER_BACKENDS))
    )
    return order if session == 1 else tuple(reversed(order))


def _path_for_scenario(scenario: str) -> str:
    return "loss_recovery_v1" if scenario == "loss_recovery" else "loopback"


def _publication_arm(scenario: str) -> tuple[int, int]:
    if scenario == "loss_recovery":
        return 500_000_000, 5_000_000_000
    if scenario in {"connect", "resumed_connect", "zero_rtt_reqresp"}:
        return 0, 2_000_000_000
    return 250_000_000, 2_000_000_000


_MAIN_ROW_PERMUTATION = (0, 1, 3, 7, 6, 10, 4, 2, 11, 5, 9, 8)

def _peer_balanced_layout(
    campaign_seed: bytes,
) -> tuple[
    tuple[
        tuple[tuple[str, str], tuple[str, str]],
        ...,
    ],
    tuple[int, ...],
]:
    regular = tuple(
        scenario
        for scenario in PUBLICATION_SCENARIOS
        if _publication_arm(scenario) == (250_000_000, 2_000_000_000)
    )
    lifecycle = tuple(
        scenario
        for scenario in PUBLICATION_SCENARIOS
        if _publication_arm(scenario) == (0, 2_000_000_000)
    )
    main_scenarios = ("loss_recovery",) + tuple(
        sorted(
            regular,
            key=lambda scenario: _hmac(
                campaign_seed,
                b"publication-main-template-scenario",
                scenario.encode("ascii"),
            ),
        )
    )
    lifecycle_scenarios = tuple(
        sorted(
            lifecycle,
            key=lambda scenario: _hmac(
                campaign_seed,
                b"publication-lifecycle-template-scenario",
                scenario.encode("ascii"),
            ),
        )
    )
    row_key = _hmac(campaign_seed, b"publication-template-row-transform")
    row_shift = int.from_bytes(row_key[:4], "big") % 12
    row_sign = -1 if row_key[4] & 1 else 1
    row_transform = tuple(
        (row_sign * row + row_shift) % 12 for row in range(12)
    )
    main_families = tuple(
        (PUBLICATION_ESTIMAND, scenario) for scenario in main_scenarios
    )
    lifecycle_families = tuple(
        (PUBLICATION_ESTIMAND, scenario) for scenario in lifecycle_scenarios
    )
    balance_control = (
        BALANCE_CONTROL_ESTIMAND,
        lifecycle_scenarios[-1],
    )
    family_pairs = tuple(
        zip(main_families[::2], main_families[1::2], strict=True)
    ) + (
        (lifecycle_families[0], lifecycle_families[1]),
        (lifecycle_families[2], balance_control),
    )
    return family_pairs, row_transform


def _peer_balanced_epoch_coordinates(
    campaign_seed: bytes,
    session: int,
) -> tuple[
    tuple[tuple[str, str, int], tuple[str, str, int]],
    ...,
]:
    family_pairs, row_transform = _peer_balanced_layout(campaign_seed)

    if session not in (1, 2):
        raise ScheduleError(f"unsupported publication session {session}")
    main_permutation = tuple(
        (peer_row + (6 if session == 2 else 0)) % 12
        for peer_row in _MAIN_ROW_PERMUTATION
    )
    return tuple(
        (
            (left[0], left[1], row_transform[row]),
            (
                right[0],
                right[1],
                row_transform[main_permutation[row]],
            ),
        )
        for left, right in family_pairs
        for row in range(12)
    )


def _peer_balanced_backend_phases(
    campaign_seed: bytes,
) -> frozenset[tuple[str, str, int]]:
    family_pairs, row_transform = _peer_balanced_layout(campaign_seed)
    return frozenset(
        (left[0], left[1], row_transform[row])
        for left, _right in family_pairs
        for row in (0, 2, 3, 4, 5, 8)
    )


def _balanced_epoch_orientations(
    campaign_seed: bytes,
    session: int,
    epoch_pairs: Sequence[
        tuple[PublicationMicroblock, PublicationMicroblock]
    ],
) -> tuple[bool, ...]:
    """Orient an even-degree category graph to split every client 3/3."""

    adjacency: dict[
        tuple[str, str, str],
        list[tuple[bytes, int, tuple[str, str, str]]],
    ] = defaultdict(list)
    endpoints = []
    for index, (left, right) in enumerate(epoch_pairs):
        left_category = (
            left.estimand,
            left.scenario,
            left.reference_client,
        )
        right_category = (
            right.estimand,
            right.scenario,
            right.reference_client,
        )
        if left_category == right_category:
            raise ScheduleError("publication epoch category contains a loop")
        endpoints.append((left_category, right_category))
        rank = _hmac(
            campaign_seed,
            b"publication-epoch-orientation-edge",
            _json_bytes(
                {
                    "session": session,
                    "left": left.logical_id,
                    "right": right.logical_id,
                }
            ),
        )
        adjacency[left_category].append((rank, index, right_category))
        adjacency[right_category].append((rank, index, left_category))
    if any(len(edges) % 2 for edges in adjacency.values()):
        raise ScheduleError("publication epoch category degree is odd")

    unused = set(range(len(epoch_pairs)))
    directions: dict[int, bool] = {}
    while unused:
        start = min(
            (
                category
                for category, edges in adjacency.items()
                if any(index in unused for _rank, index, _other in edges)
            ),
            key=lambda category: _hmac(
                campaign_seed,
                b"publication-epoch-orientation-start",
                _json_bytes({"session": session, "category": category}),
            ),
        )
        vertex_stack = [start]
        edge_stack: list[
            tuple[int, tuple[str, str, str], tuple[str, str, str]]
        ] = []
        while vertex_stack:
            vertex = vertex_stack[-1]
            candidates = [
                edge
                for edge in adjacency[vertex]
                if edge[1] in unused
            ]
            if candidates:
                _rank, edge_index, other = min(candidates)
                unused.remove(edge_index)
                vertex_stack.append(other)
                edge_stack.append((edge_index, vertex, other))
                continue
            vertex_stack.pop()
            if edge_stack:
                edge_index, source, _target = edge_stack.pop()
                directions[edge_index] = source == endpoints[edge_index][0]
    if len(directions) != len(epoch_pairs):
        raise ScheduleError("publication epoch orientation is incomplete")
    lane_zero = Counter()
    for index, (left, right) in enumerate(epoch_pairs):
        selected = left if directions[index] else right
        lane_zero[
            (selected.estimand, selected.scenario, selected.reference_client)
        ] += 1
    inferential_lane_zero = {
        category: count
        for category, count in lane_zero.items()
        if category[0] == PUBLICATION_ESTIMAND
    }
    if set(inferential_lane_zero.values()) != {3}:
        raise ScheduleError("publication epoch orientation is not 3/3 balanced")
    return tuple(directions[index] for index in range(len(epoch_pairs)))


def _reverse_microblock_backend_order(
    block: PublicationMicroblock,
) -> PublicationMicroblock:
    if len(block.trials) % 2:
        raise ScheduleError("publication block backend cardinality is odd")
    trials = []
    for index in range(0, len(block.trials), 2):
        pair = tuple(reversed(block.trials[index : index + 2]))
        if (
            len(pair) != 2
            or pair[0].server != pair[1].server
            or pair[0].server_position != pair[1].server_position
        ):
            raise ScheduleError("publication block backend pair is malformed")
        trials.extend(
            replace(trial, backend_order=backend_order)
            for backend_order, trial in enumerate(pair)
        )
    return replace(block, trials=tuple(trials))


def _two_lane_publication_epochs(
    blocks: Sequence[PublicationMicroblock],
    campaign_seed: bytes,
) -> list[PublicationMicroblock]:
    """Pack frozen blocks into globally interleaved, family-disjoint epochs."""

    backend_phases = _peer_balanced_backend_phases(campaign_seed)
    blocks = tuple(
        _reverse_microblock_backend_order(block)
        if (block.estimand, block.scenario, block.williams_row)
        in backend_phases
        else block
        for block in blocks
    )
    by_coordinate = {
        (
            block.session,
            block.slot,
            block.williams_row,
            block.estimand,
            block.scenario,
        ): block
        for block in blocks
    }
    if len(by_coordinate) != len(blocks):
        raise ScheduleError("duplicate publication block coordinate")

    result: list[PublicationMicroblock] = []
    for session in (1, 2):
        coordinates = _peer_balanced_epoch_coordinates(
            campaign_seed, session
        )
        primary_pairs = tuple(
            (
                by_coordinate[
                    (
                        session,
                        "primary",
                        left_row,
                        left_estimand,
                        left_scenario,
                    )
                ],
                by_coordinate[
                    (
                        session,
                        "primary",
                        right_row,
                        right_estimand,
                        right_scenario,
                    )
                ],
            )
            for (
                (left_estimand, left_scenario, left_row),
                (right_estimand, right_scenario, right_row),
            ) in coordinates
        )
        if (
            len(primary_pairs) != 96
            or len(
                {
                    block.microblock_id
                    for pair in primary_pairs
                    for block in pair
                }
            )
            != 192
        ):
            raise ScheduleError(
                "canonical publication epoch template is not a partition"
            )
        orientations = _balanced_epoch_orientations(
            campaign_seed, session, primary_pairs
        )
        epoch_specs = [
            (
                _hmac(
                    campaign_seed,
                    b"publication-epoch-order",
                    _json_bytes(
                        {
                            "session": session,
                            "left": left.logical_id,
                            "right": right.logical_id,
                        }
                    ),
                ),
                pair_index,
            )
            for pair_index, (left, right) in enumerate(primary_pairs)
        ]
        epoch_specs.sort(key=lambda item: item[0])
        if len(epoch_specs) != 96:
            raise ScheduleError("canonical publication needs 96 parallel epochs")

        for slot in ("primary", "retry"):
            for epoch_ordinal, (_key, pair_index) in enumerate(epoch_specs):
                (
                    (left_estimand, left_scenario, left_row),
                    (right_estimand, right_scenario, right_row),
                ) = coordinates[pair_index]
                left = by_coordinate[
                    (
                        session,
                        slot,
                        left_row,
                        left_estimand,
                        left_scenario,
                    )
                ]
                right = by_coordinate[
                    (
                        session,
                        slot,
                        right_row,
                        right_estimand,
                        right_scenario,
                    )
                ]
                epoch_id = tagged_hash(
                    "parallel-epoch",
                    bytes.fromhex(left.logical_id),
                    bytes.fromhex(right.logical_id),
                ).hex()
                left_on_zero = orientations[pair_index]
                for lane, block in (
                    ((0, left), (1, right))
                    if left_on_zero
                    else ((0, right), (1, left))
                ):
                    result.append(
                        replace(
                            block,
                            lane=lane,
                            parallel_epoch_id=epoch_id,
                            parallel_epoch_ordinal=epoch_ordinal,
                            parallel_lane_ordinal=0,
                        )
                    )
    if len(result) != len(blocks) or {
        block.microblock_id for block in result
    } != {block.microblock_id for block in blocks}:
        raise ScheduleError("publication parallel epochs changed block cardinality")
    return result


def _coordinate_bytes(
    estimand: str,
    scenario: str,
    path_profile: str,
    assignment: WilliamsAssignment,
) -> bytes:
    return _json_bytes(
        {
            "estimand": estimand,
            "scenario": scenario,
            "path_profile": path_profile,
            "fixed_concurrency": FIXED_CONCURRENCY,
            "reference_client": assignment.reference_client,
            "session": assignment.session,
            "williams_row": assignment.row_index,
        }
    )


def _make_microblock(
    *,
    schedule_basis_hash: bytes,
    campaign_seed: bytes,
    assignment: WilliamsAssignment,
    estimand: str,
    scenario: str,
    backends: Sequence[str],
    path_profile_hash: bytes,
    slot: str,
) -> PublicationMicroblock:
    path_profile = _path_for_scenario(scenario)
    coordinate = _coordinate_bytes(
        estimand, scenario, path_profile, assignment
    )
    logical_id = tagged_hash("logical-microblock", schedule_basis_hash, coordinate).hex()
    superblock_coordinate = _json_bytes(
        {
            "estimand": estimand,
            "scenario": scenario,
            "path_profile": path_profile,
            "fixed_concurrency": FIXED_CONCURRENCY,
            "williams_row": assignment.row_index,
        }
    )
    superblock_id = tagged_hash(
        "session-paired-superblock", schedule_basis_hash, superblock_coordinate
    ).hex()
    slot_field = slot.encode("ascii")
    microblock = tagged_hash("microblock", schedule_basis_hash, coordinate, slot_field)
    trials: list[TrialCoordinate] = []
    for position, server in enumerate(assignment.server_order):
        order = _backend_order(
            assignment.row_index, position, backends, assignment.session
        )
        for backend_order, backend in enumerate(order):
            treatment = _json_bytes(
                {
                    "estimand": estimand,
                    "scenario": scenario,
                    "path_profile": path_profile,
                    "concurrency": FIXED_CONCURRENCY,
                    "server": server,
                    "server_backend": backend,
                    "reference_client": assignment.reference_client,
                    "reference_client_backend": "iouring",
                }
            )
            cell_id = tagged_hash("cell", treatment)
            trial_id = tagged_hash(
                "trial",
                schedule_basis_hash,
                _u32(assignment.session),
                microblock,
                cell_id,
                b"\x00",
            )
            trials.append(
                TrialCoordinate(
                    trial_id=trial_id.hex(),
                    cell_id=cell_id.hex(),
                    microblock_id=microblock.hex(),
                    logical_microblock_id=logical_id,
                    superblock_id=superblock_id,
                    slot=slot,
                    estimand=estimand,
                    scenario=scenario,
                    path_profile=path_profile,
                    fixed_concurrency=FIXED_CONCURRENCY,
                    reference_client=assignment.reference_client,
                    reference_client_backend="iouring",
                    session=assignment.session,
                    williams_row=assignment.row_index,
                    server_position=position,
                    server=server,
                    server_backend=backend,
                    backend_order=backend_order,
                )
            )
    if len(path_profile_hash) != 32:
        raise ScheduleError("path profile hash must be exactly 256 bits")
    trace_seed = hmac.new(
        campaign_seed, microblock + path_profile_hash, hashlib.sha256
    ).hexdigest()
    return PublicationMicroblock(
        microblock_id=microblock.hex(),
        logical_id=logical_id,
        superblock_id=superblock_id,
        slot=slot,
        estimand=estimand,
        scenario=scenario,
        path_profile=path_profile,
        fixed_concurrency=FIXED_CONCURRENCY,
        reference_client=assignment.reference_client,
        session=assignment.session,
        session_position=assignment.session_position,
        williams_row=assignment.row_index,
        server_order=assignment.server_order,
        lane=-1,
        parallel_epoch_id=None,
        parallel_epoch_ordinal=None,
        parallel_lane_ordinal=None,
        trace_seed=trace_seed,
        trials=tuple(trials),
    )


def plan_publication(
    *,
    campaign_seed: bytes,
    schedule_basis_hash: bytes,
    qualified_lane_count: int = 1,
    servers: Sequence[str] = CANONICAL_SERVERS,
    scenarios: Sequence[str] = PUBLICATION_SCENARIOS,
    server_backends: Sequence[str] = SERVER_BACKENDS,
    reference_clients: Sequence[str] = REFERENCE_CLIENTS,
    path_profile_hashes: Mapping[str, bytes] = CANONICAL_PATH_HASHES,
) -> PublicationSchedule:
    if len(schedule_basis_hash) != hashlib.sha256().digest_size:
        raise ScheduleError("schedule_basis_hash must be 32 bytes")
    if tuple(reference_clients) != REFERENCE_CLIENTS:
        # The exact assignment rule has two frozen reference levels.  Alternate
        # reference sets are diagnostic but must still contain two roles.
        if len(reference_clients) != 2:
            raise ScheduleError("publication planning requires exactly two reference clients")
    eligible = publication_design_eligible(
        servers, scenarios, server_backends, reference_clients
    )
    assignments = assign_williams_rows(tuple(servers), campaign_seed)
    family_pairs, _row_transform = _peer_balanced_layout(campaign_seed)
    balance_scenario = next(
        scenario
        for pair in family_pairs
        for estimand, scenario in pair
        if estimand == BALANCE_CONTROL_ESTIMAND
    )
    blocks: list[PublicationMicroblock] = []
    for assignment in assignments:
        # Rebind diagnostic reference labels without changing parity.
        if tuple(reference_clients) != REFERENCE_CLIENTS:
            ref_index = REFERENCE_CLIENTS.index(assignment.reference_client)
            assignment = replace(assignment, reference_client=reference_clients[ref_index])
        for scenario in scenarios:
            path_profile = _path_for_scenario(scenario)
            try:
                path_profile_hash = path_profile_hashes[path_profile]
            except KeyError as exc:
                raise ScheduleError(
                    f"missing content hash for path profile {path_profile!r}"
                ) from exc
            blocks.append(
                _make_microblock(
                    schedule_basis_hash=schedule_basis_hash,
                    campaign_seed=campaign_seed,
                    assignment=assignment,
                    estimand=PUBLICATION_ESTIMAND,
                    scenario=scenario,
                    backends=server_backends,
                    path_profile_hash=path_profile_hash,
                    slot="primary",
                )
            )
            blocks.append(
                _make_microblock(
                    schedule_basis_hash=schedule_basis_hash,
                    campaign_seed=campaign_seed,
                    assignment=assignment,
                    estimand=PUBLICATION_ESTIMAND,
                    scenario=scenario,
                    backends=server_backends,
                    path_profile_hash=path_profile_hash,
                    slot="retry",
                )
            )
        if eligible and qualified_lane_count == 2:
            path_profile = _path_for_scenario(balance_scenario)
            try:
                path_profile_hash = path_profile_hashes[path_profile]
            except KeyError as exc:
                raise ScheduleError(
                    f"missing content hash for path profile {path_profile!r}"
                ) from exc
            for slot in ("primary", "retry"):
                blocks.append(
                    _make_microblock(
                        schedule_basis_hash=schedule_basis_hash,
                        campaign_seed=campaign_seed,
                        assignment=assignment,
                        estimand=BALANCE_CONTROL_ESTIMAND,
                        scenario=balance_scenario,
                        backends=server_backends,
                        path_profile_hash=path_profile_hash,
                        slot=slot,
                    )
                )
    if eligible and qualified_lane_count == 2:
        blocks = _two_lane_publication_epochs(blocks, campaign_seed)
    else:
        lane_items = [
            LaneItem(
                block.microblock_id,
                (
                    block.session,
                    block.slot,
                    block.scenario,
                    block.reference_client,
                ),
            )
            for block in blocks
        ]
        lane_assignments = balanced_lane_assignments(
            lane_items, campaign_seed, qualified_lane_count
        )
        blocks = [
            replace(block, lane=lane_assignments[block.microblock_id])
            for block in blocks
        ]
        scenario_rank = {
            scenario: index for index, scenario in enumerate(PUBLICATION_SCENARIOS)
        }
        blocks.sort(
            key=lambda block: (
                block.session,
                0 if block.slot == "primary" else 1,
                (0, scenario_rank[block.scenario])
                if block.scenario in scenario_rank
                else (1, block.scenario),
                block.session_position,
            )
        )
    schedule = PublicationSchedule(
        campaign_seed=campaign_seed.hex(),
        schedule_basis_hash=schedule_basis_hash.hex(),
        servers=tuple(servers),
        scenarios=tuple(scenarios),
        server_backends=tuple(server_backends),
        reference_clients=tuple(reference_clients),
        qualified_lane_count=qualified_lane_count,
        publication_eligible=eligible,
        microblocks=tuple(blocks),
    )
    audit = audit_publication_schedule(schedule)
    if not audit.valid:
        raise ScheduleError(
            "publication schedule audit failed: " + ",".join(audit.reasons)
        )
    return schedule


@dataclass(frozen=True)
class ScheduleAudit:
    valid: bool
    reasons: tuple[str, ...]
    primary_trials: int
    retry_trials: int
    primary_per_session: tuple[int, int]


def audit_publication_schedule(schedule: PublicationSchedule) -> ScheduleAudit:
    reasons: list[str] = []
    primary = schedule.primary_trials
    retry = schedule.retry_trials
    if schedule.publication_eligible:
        expected_trials = (
            2
            * 12
            * len(schedule.scenarios)
            * len(schedule.servers)
            * len(schedule.server_backends)
        )
        if len(primary) != expected_trials:
            reasons.append(
                f"primary_cardinality_{len(primary)}_ne_{expected_trials}"
            )
        if len(retry) != expected_trials:
            reasons.append(
                f"retry_cardinality_{len(retry)}_ne_{expected_trials}"
            )
        if schedule.qualified_lane_count == 2:
            control_counts = Counter(
                block.slot
                for block in schedule.balance_control_microblocks
                for _trial in block.trials
            )
            if control_counts != Counter(
                {
                    "primary": PUBLICATION_BALANCE_CONTROL_TRIALS,
                    "retry": PUBLICATION_BALANCE_CONTROL_TRIALS,
                }
            ):
                reasons.append("parallel_balance_control_cardinality")
    trial_ids = [
        trial.trial_id
        for block in schedule.microblocks
        for trial in block.trials
    ]
    if len(trial_ids) != len(set(trial_ids)):
        reasons.append("duplicate_trial_id")
    microblock_ids = [block.microblock_id for block in schedule.microblocks]
    if len(microblock_ids) != len(set(microblock_ids)):
        reasons.append("duplicate_microblock_id")

    session_counts = tuple(
        sum(1 for trial in primary if trial.session == session) for session in (1, 2)
    )
    expected_session_trials = (
        12
        * len(schedule.scenarios)
        * len(schedule.servers)
        * len(schedule.server_backends)
    )
    if schedule.publication_eligible and session_counts != (
        expected_session_trials,
        expected_session_trials,
    ):
        reasons.append(f"session_cardinality_{session_counts!r}")

    position_counts = Counter((trial.server, trial.server_position) for trial in primary)
    expected_position = 2 * len(schedule.scenarios) * len(schedule.server_backends)
    if schedule.publication_eligible and set(position_counts.values()) != {expected_position}:
        reasons.append("server_position_unbalanced")

    stratum_counts = Counter(
        (trial.server, trial.scenario, trial.server_backend, trial.reference_client)
        for trial in primary
    )
    if schedule.publication_eligible and set(stratum_counts.values()) != {12}:
        reasons.append("reference_backend_strata_unbalanced")

    backend_first = Counter(
        (trial.server, trial.scenario, trial.server_backend)
        for trial in primary
        if trial.backend_order == 0
    )
    expected_backend_first = 12 if len(schedule.server_backends) == 2 else 24
    if (
        schedule.publication_eligible
        and set(backend_first.values()) != {expected_backend_first}
    ):
        reasons.append("backend_order_unbalanced")

    superblocks: dict[tuple[str, str], list[PublicationMicroblock]] = {}
    for block in schedule.microblocks:
        superblocks.setdefault((block.superblock_id, block.slot), []).append(block)
    if schedule.publication_eligible:
        for pair in superblocks.values():
            if len(pair) != 2 or {block.session for block in pair} != {1, 2}:
                reasons.append("session_pair_incomplete")
                break
            first, second = sorted(pair, key=lambda block: block.session)
            if (
                first.server_order != second.server_order
                or first.reference_client == second.reference_client
                or first.trace_seed == second.trace_seed
            ):
                reasons.append("session_pair_treatment_mismatch")
                break
            first_orders = {
                (trial.server, trial.server_backend): trial.backend_order
                for trial in first.trials
            }
            second_orders = {
                (trial.server, trial.server_backend): trial.backend_order
                for trial in second.trials
            }
            backend_orders_match = (
                all(second_orders[key] == order for key, order in first_orders.items())
                if len(schedule.server_backends) == 1
                else all(
                    second_orders[key] == 1 - order
                    for key, order in first_orders.items()
                )
            )
            if not backend_orders_match:
                reasons.append("session_pair_backend_order_not_complemented")
                break

    paired = Counter((block.logical_id, block.slot) for block in schedule.microblocks)
    if any(count != 1 for count in paired.values()):
        reasons.append("duplicate_logical_slot")
    logical_slots: dict[str, set[str]] = {}
    for block in schedule.microblocks:
        logical_slots.setdefault(block.logical_id, set()).add(block.slot)
    if any(slots != {"primary", "retry"} for slots in logical_slots.values()):
        reasons.append("missing_primary_or_retry")
    if schedule.publication_eligible and schedule.qualified_lane_count == 2:
        placements: dict[str, dict[str, tuple[object, ...]]] = {}
        for block in schedule.microblocks:
            placements.setdefault(block.logical_id, {})[block.slot] = (
                block.lane,
                block.parallel_epoch_id,
                block.parallel_epoch_ordinal,
                block.parallel_lane_ordinal,
            )
        if any(
            members.get("primary") != members.get("retry")
            for members in placements.values()
        ):
            reasons.append("parallel_retry_placement_mismatch")

    for session in (1, 2):
        for slot in ("primary", "retry"):
            counts = Counter(
                block.lane
                for block in schedule.microblocks
                if block.session == session and block.slot == slot
            )
            if counts and max(counts.values()) - min(counts.values()) > 1:
                reasons.append(f"lane_unbalanced_session_{session}_{slot}")
            if (
                schedule.publication_eligible
                and schedule.qualified_lane_count == 2
            ):
                members = [
                    block
                    for block in schedule.microblocks
                    if block.session == session and block.slot == slot
                ]
                epochs: dict[int, list[PublicationMicroblock]] = {}
                for block in members:
                    if (
                        type(block.parallel_epoch_ordinal) is not int
                        or not isinstance(block.parallel_epoch_id, str)
                        or len(block.parallel_epoch_id) != 64
                        or block.parallel_lane_ordinal != 0
                    ):
                        reasons.append(
                            f"parallel_epoch_identity_invalid_session_{session}_{slot}"
                        )
                        break
                    epochs.setdefault(block.parallel_epoch_ordinal, []).append(block)
                if set(epochs) != set(range(96)):
                    reasons.append(
                        f"parallel_epoch_cardinality_session_{session}_{slot}"
                    )
                mismatched_arms = 0
                for epoch in epochs.values():
                    if (
                        len(epoch) != 2
                        or {block.lane for block in epoch} != {0, 1}
                        or len({block.parallel_epoch_id for block in epoch}) != 1
                        or len(
                            {
                                (block.estimand, block.scenario)
                                for block in epoch
                            }
                        )
                        != 2
                    ):
                        reasons.append(
                            f"parallel_epoch_membership_session_{session}_{slot}"
                        )
                        break
                    arms = [_publication_arm(block.scenario) for block in epoch]
                    if arms[0] != arms[1]:
                        mismatched_arms += 1
                        scenarios = {block.scenario for block in epoch}
                        if (
                            "loss_recovery" not in scenarios
                            or any(
                                _publication_arm(scenario)
                                != (250_000_000, 2_000_000_000)
                                for scenario in scenarios - {"loss_recovery"}
                            )
                        ):
                            reasons.append(
                                f"parallel_epoch_arm_invalid_session_{session}_{slot}"
                            )
                            break
                if mismatched_arms != 12:
                    reasons.append(
                        f"parallel_loss_bridge_count_session_{session}_{slot}"
                    )
                strata = Counter(
                    (block.scenario, block.reference_client, block.lane)
                    for block in members
                    if block.estimand == PUBLICATION_ESTIMAND
                )
                if set(strata.values()) != {3}:
                    reasons.append(
                        f"parallel_client_strata_unbalanced_session_{session}_{slot}"
                    )
    if schedule.publication_eligible and schedule.qualified_lane_count == 2:
        expected_offsets = Counter({offset: 2 for offset in range(12)})
        expected_peer_servers = Counter(
            {server: 2 for server in schedule.servers}
        )
        expected_peer_backends = Counter(
            {backend: 12 for backend in schedule.server_backends}
        )
        expected_peer_clients = Counter(
            {client: 12 for client in schedule.reference_clients}
        )
        expected_peer_treatments = Counter(
            {
                (server, backend): 1
                for server in schedule.servers
                for backend in schedule.server_backends
            }
        )
        for slot in ("primary", "retry"):
            offsets: dict[str, Counter[int]] = defaultdict(Counter)
            peer_servers: dict[
                tuple[str, str, str], Counter[str]
            ] = defaultdict(Counter)
            peer_backends: dict[
                tuple[str, str, str], Counter[str]
            ] = defaultdict(Counter)
            peer_clients: dict[
                tuple[str, str, str], Counter[str]
            ] = defaultdict(Counter)
            peer_treatments: dict[
                tuple[str, str, str], Counter[tuple[str, str]]
            ] = defaultdict(Counter)
            malformed = False
            for session in (1, 2):
                epochs: dict[int, list[PublicationMicroblock]] = defaultdict(
                    list
                )
                for block in schedule.microblocks:
                    if block.session == session and block.slot == slot:
                        if type(block.parallel_epoch_ordinal) is not int:
                            malformed = True
                            break
                        epochs[block.parallel_epoch_ordinal].append(block)
                if malformed:
                    break
                for epoch in epochs.values():
                    if len(epoch) != 2:
                        malformed = True
                        break
                    left, right = epoch
                    for block, peer in ((left, right), (right, left)):
                        if block.estimand != PUBLICATION_ESTIMAND:
                            continue
                        offsets[block.scenario][
                            (peer.williams_row - block.williams_row) % 12
                        ] += 1
                        if len(block.trials) != len(peer.trials):
                            malformed = True
                            break
                        for trial, peer_trial in zip(
                            block.trials, peer.trials, strict=True
                        ):
                            key = (
                                trial.scenario,
                                trial.server,
                                trial.server_backend,
                            )
                            peer_servers[key][peer_trial.server] += 1
                            peer_backends[key][peer_trial.server_backend] += 1
                            peer_clients[key][peer_trial.reference_client] += 1
                            peer_treatments[key][
                                (
                                    peer_trial.server,
                                    peer_trial.server_backend,
                                )
                            ] += 1
                    if malformed:
                        break
                if malformed:
                    break
            if malformed:
                reasons.append(f"parallel_peer_exposure_malformed_{slot}")
                continue
            if (
                set(offsets) != set(schedule.scenarios)
                or any(
                    counts != expected_offsets
                    for counts in offsets.values()
                )
            ):
                reasons.append(f"parallel_peer_row_offsets_unbalanced_{slot}")
            expected_keys = {
                (scenario, server, backend)
                for scenario in schedule.scenarios
                for server in schedule.servers
                for backend in schedule.server_backends
            }
            if (
                set(peer_servers) != expected_keys
                or any(
                    counts != expected_peer_servers
                    for counts in peer_servers.values()
                )
            ):
                reasons.append(f"parallel_peer_servers_unbalanced_{slot}")
            if (
                set(peer_backends) != expected_keys
                or any(
                    counts != expected_peer_backends
                    for counts in peer_backends.values()
                )
            ):
                reasons.append(f"parallel_peer_backends_unbalanced_{slot}")
            if (
                set(peer_clients) != expected_keys
                or any(
                    counts != expected_peer_clients
                    for counts in peer_clients.values()
                )
            ):
                reasons.append(f"parallel_peer_clients_unbalanced_{slot}")
            if (
                set(peer_treatments) != expected_keys
                or any(
                    counts != expected_peer_treatments
                    for counts in peer_treatments.values()
                )
            ):
                reasons.append(
                    f"parallel_peer_treatments_unbalanced_{slot}"
                )
    return ScheduleAudit(not reasons, tuple(reasons), len(primary), len(retry), session_counts)


def ordered_predecessor_counts(rows: Iterable[Sequence[str]]) -> Counter[tuple[str, str]]:
    counts: Counter[tuple[str, str]] = Counter()
    for row in rows:
        counts.update(zip(row, row[1:]))
    return counts
