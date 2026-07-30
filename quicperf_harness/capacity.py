"""Frozen exploratory and held-out capacity-frontier design helpers."""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass, replace
from typing import Mapping, Sequence

from .canonical import canonical_bytes
from .planner import (
    CANONICAL_SERVERS,
    REFERENCE_CLIENTS,
    SERVER_BACKENDS,
    assign_williams_rows,
    tagged_hash,
    williams_rows,
)
from .scheduler import LaneItem, ScheduleError, balanced_lane_assignments


CAPACITY_ESTIMAND = "capacity_frontier"
CAPACITY_SCENARIOS = (
    "download",
    "upload",
    "bidi",
    "small_payload_pps",
    "datagram",
    "reqresp",
    "connect",
)
CAPACITY_GRID = (1, 2, 4, 8, 16)


def _stable_permutation(values: Sequence[int], seed: bytes, label: bytes) -> tuple[int, ...]:
    return tuple(
        sorted(
            values,
            key=lambda value: (
                hmac.new(seed, label + int(value).to_bytes(4, "big"), hashlib.sha256).digest(),
                value,
            ),
        )
    )


def latin_square(
    values: Sequence[int], seed: bytes, *, label: bytes = b"latin-square"
) -> tuple[tuple[int, ...], ...]:
    if not values or len(set(values)) != len(values):
        raise ScheduleError("Latin square values must be nonempty and unique")
    base = _stable_permutation(values, seed, label)
    return tuple(base[offset:] + base[:offset] for offset in range(len(base)))


@dataclass(frozen=True)
class CapacitySearchTrial:
    trial_id: str
    server: str
    server_backend: str
    scenario: str
    reference_client: str
    concurrency: int
    search_round: int
    server_position: int
    backend_order: int
    trace_seed: str
    phase: str = "exploratory"


@dataclass(frozen=True)
class CapacitySearchPlan:
    trials: tuple[CapacitySearchTrial, ...]
    server_orders: tuple[tuple[str, ...], ...]
    grid_square: tuple[tuple[int, ...], ...]


def plan_capacity_search(
    *,
    campaign_seed: bytes,
    schedule_basis_hash: bytes,
    servers: Sequence[str] = CANONICAL_SERVERS,
    backends: Sequence[str] = SERVER_BACKENDS,
    scenarios: Sequence[str] = CAPACITY_SCENARIOS,
) -> CapacitySearchPlan:
    """Freeze all five loads once per reference client for every stratum."""

    if len(schedule_basis_hash) != 32:
        raise ScheduleError("schedule_basis_hash must be 32 bytes")
    rows = williams_rows(servers)
    ordered_row_indices = sorted(
        range(len(rows)),
        key=lambda row: hmac.new(
            campaign_seed, b"capacity-williams-row" + row.to_bytes(4, "big"), hashlib.sha256
        ).digest(),
    )
    selected_rows = tuple(rows[index] for index in ordered_row_indices[:10])
    square = latin_square(CAPACITY_GRID, campaign_seed, label=b"capacity-grid")
    server_index = {server: index for index, server in enumerate(servers)}
    trials: list[CapacitySearchTrial] = []
    for search_round, server_order in enumerate(selected_rows):
        reference_client = REFERENCE_CLIENTS[search_round % len(REFERENCE_CLIENTS)]
        grid_row = square[search_round // len(REFERENCE_CLIENTS)]
        trace_seed = hmac.new(
            campaign_seed,
            b"capacity-search-trace" + search_round.to_bytes(4, "big"),
            hashlib.sha256,
        ).hexdigest()
        for scenario in scenarios:
            for position, server in enumerate(server_order):
                backend_order = (
                    tuple(backends)
                    if (search_round + position) % 2 == 0
                    else tuple(reversed(backends))
                )
                for order_index, backend in enumerate(backend_order):
                    concurrency = grid_row[server_index[server] % len(CAPACITY_GRID)]
                    coordinates = canonical_bytes(
                        {
                            "server": server,
                            "server_backend": backend,
                            "scenario": scenario,
                            "reference_client": reference_client,
                            "concurrency": concurrency,
                            "search_round": search_round,
                        }
                    )
                    trial_id = tagged_hash(
                        "capacity-search-trial", schedule_basis_hash, coordinates
                    ).hex()
                    trials.append(
                        CapacitySearchTrial(
                            trial_id=trial_id,
                            server=server,
                            server_backend=backend,
                            scenario=scenario,
                            reference_client=reference_client,
                            concurrency=concurrency,
                            search_round=search_round,
                            server_position=position,
                            backend_order=order_index,
                            trace_seed=trace_seed,
                        )
                    )
    return CapacitySearchPlan(tuple(trials), selected_rows, square)


@dataclass(frozen=True)
class CapacityPoint:
    concurrency: int
    reference_client: str
    rate: float | None
    valid: bool
    client_headroom_valid: bool = True


@dataclass(frozen=True)
class CapacityNomination:
    candidate: int | None
    scores: tuple[tuple[int, float], ...]
    status: str
    reason: str = ""


def nominate_capacity(
    observations: Sequence[CapacityPoint], threshold: float = 0.97
) -> CapacityNomination:
    if not 0.0 < threshold <= 1.0:
        raise ValueError("threshold must be in (0, 1]")
    by_grid: dict[int, dict[str, CapacityPoint]] = {value: {} for value in CAPACITY_GRID}
    for observation in observations:
        if observation.concurrency not in by_grid:
            raise ValueError(f"unexpected capacity grid point {observation.concurrency}")
        if observation.reference_client not in REFERENCE_CLIENTS:
            raise ValueError(f"unexpected reference client {observation.reference_client!r}")
        clients = by_grid[observation.concurrency]
        if observation.reference_client in clients:
            raise ValueError("duplicate capacity search observation")
        clients[observation.reference_client] = observation

    scores: list[tuple[int, float]] = []
    for concurrency in CAPACITY_GRID:
        clients = by_grid[concurrency]
        if set(clients) != set(REFERENCE_CLIENTS):
            continue
        points = [clients[client] for client in REFERENCE_CLIENTS]
        if not all(
            point.valid
            and point.client_headroom_valid
            and point.rate is not None
            and math.isfinite(point.rate)
            and point.rate > 0.0
            for point in points
        ):
            continue
        scores.append((concurrency, math.sqrt(float(points[0].rate) * float(points[1].rate))))
    if not scores:
        return CapacityNomination(None, (), "inconclusive", "no_valid_complete_grid_point")
    best = max(score for _, score in scores)
    candidate = min(concurrency for concurrency, score in scores if score >= threshold * best)
    return CapacityNomination(candidate, tuple(scores), "nominated")


def neighbor_loads(candidate: int) -> tuple[int, ...]:
    if candidate not in CAPACITY_GRID:
        raise ValueError(f"candidate {candidate} is not in the frozen grid")
    index = CAPACITY_GRID.index(candidate)
    low = max(0, index - 1)
    high = min(len(CAPACITY_GRID), index + 2)
    return CAPACITY_GRID[low:high]


@dataclass(frozen=True)
class CapacityConfirmationTrial:
    trial_id: str
    branch_candidate: int
    server: str
    server_backend: str
    scenario: str
    confirmation_round: int
    reference_client: str
    session: int
    williams_row: int
    concurrency: int
    order: int
    slot: str
    microblock_id: str
    lane: int
    trace_seed: str


@dataclass(frozen=True)
class CapacityBranch:
    branch_id: str
    candidate: int
    status: str
    trials: tuple[CapacityConfirmationTrial, ...]


def freeze_confirmation_branches(
    *,
    campaign_seed: bytes,
    schedule_basis_hash: bytes,
    server: str,
    server_backend: str,
    scenario: str,
    qualified_lane_count: int = 1,
) -> tuple[CapacityBranch, ...]:
    """Preallocate all five possible held-out branches and their retries."""

    if server not in CANONICAL_SERVERS:
        raise ValueError(f"unknown canonical server {server!r}")
    if server_backend not in SERVER_BACKENDS:
        raise ValueError(f"unknown canonical backend {server_backend!r}")
    assignments = assign_williams_rows(CANONICAL_SERVERS, campaign_seed)
    branches: list[CapacityBranch] = []
    for candidate in CAPACITY_GRID:
        loads = neighbor_loads(candidate)
        square = latin_square(loads, campaign_seed, label=f"capacity-confirm-{candidate}".encode())
        branch_coordinates = canonical_bytes(
            {
                "server": server,
                "server_backend": server_backend,
                "scenario": scenario,
                "candidate": candidate,
            }
        )
        branch_id = tagged_hash(
            "capacity-confirmation-branch", schedule_basis_hash, branch_coordinates
        ).hex()
        trials: list[CapacityConfirmationTrial] = []
        for round_index, assignment in enumerate(assignments):
            client = assignment.reference_client
            order = square[round_index % len(square)]
            for order_index, concurrency in enumerate(order):
                for slot in ("primary", "retry"):
                    slot_field = slot.encode("ascii")
                    microblock = tagged_hash(
                        "capacity-confirmation-microblock",
                        schedule_basis_hash,
                        branch_coordinates,
                        round_index.to_bytes(4, "big"),
                        slot_field,
                    )
                    trials.append(
                        CapacityConfirmationTrial(
                            trial_id=tagged_hash(
                                "capacity-confirmation-trial",
                                schedule_basis_hash,
                                branch_coordinates,
                                round_index.to_bytes(4, "big"),
                                concurrency.to_bytes(4, "big"),
                                slot_field,
                            ).hex(),
                            branch_candidate=candidate,
                            server=server,
                            server_backend=server_backend,
                            scenario=scenario,
                            confirmation_round=round_index,
                            reference_client=client,
                            session=assignment.session,
                            williams_row=assignment.row_index,
                            concurrency=concurrency,
                            order=order_index,
                            slot=slot,
                            microblock_id=microblock.hex(),
                            lane=-1,
                            trace_seed=hmac.new(
                                campaign_seed,
                                b"capacity-confirmation-trace" + microblock,
                                hashlib.sha256,
                            ).hexdigest(),
                        )
                    )
        branches.append(CapacityBranch(branch_id, candidate, "dormant", tuple(trials)))

    microblock_groups = {
        (trial.microblock_id, trial.branch_candidate, trial.slot)
        for branch in branches
        for trial in branch.trials
    }
    lanes = balanced_lane_assignments(
        (
            LaneItem(microblock_id, (candidate, slot))
            for microblock_id, candidate, slot in microblock_groups
        ),
        campaign_seed,
        qualified_lane_count,
    )
    return tuple(
        replace(
            branch,
            trials=tuple(
                replace(trial, lane=lanes[trial.microblock_id])
                for trial in branch.trials
            ),
        )
        for branch in branches
    )


def activate_confirmation_branch(
    branches: Sequence[CapacityBranch], candidate: int
) -> tuple[CapacityBranch, ...]:
    if len(branches) != len(CAPACITY_GRID) or {
        branch.candidate for branch in branches
    } != set(CAPACITY_GRID):
        raise ValueError("confirmation branch set is not the frozen five-point domain")
    if candidate not in CAPACITY_GRID:
        raise ValueError("candidate is not in the frozen grid")
    return tuple(
        replace(branch, status="active" if branch.candidate == candidate else "not_selected")
        for branch in branches
    )


@dataclass(frozen=True)
class NeighborInterval:
    neighbor: int
    low_log_ratio: float
    high_log_ratio: float


@dataclass(frozen=True)
class CapacityConfirmation:
    status: str
    reason: str


def confirm_nomination(
    candidate: int,
    intervals: Mapping[int, NeighborInterval],
    *,
    practical_margin: float = math.log(1.03),
    candidate_valid: bool = True,
) -> CapacityConfirmation:
    if not candidate_valid:
        return CapacityConfirmation("inconclusive", "selection_not_confirmed")
    expected = set(neighbor_loads(candidate)) - {candidate}
    if set(intervals) != expected:
        return CapacityConfirmation("inconclusive", "selection_not_confirmed")
    for neighbor in sorted(expected):
        interval = intervals[neighbor]
        if interval.neighbor != neighbor or interval.low_log_ratio > interval.high_log_ratio:
            raise ValueError("malformed neighbor interval")
        # Ratios are candidate / neighbor, oriented so positive favors the
        # candidate.  Equivalence or a wholly favorable interval confirms it.
        equivalent = (
            interval.low_log_ratio >= -practical_margin
            and interval.high_log_ratio <= practical_margin
        )
        favors_candidate = interval.low_log_ratio > practical_margin
        if neighbor > candidate and interval.high_log_ratio < -practical_margin:
            return CapacityConfirmation("inconclusive", "under_bracketed")
        if not equivalent and not favors_candidate:
            return CapacityConfirmation("inconclusive", "selection_not_confirmed")
    if candidate == CAPACITY_GRID[-1]:
        lower = intervals[CAPACITY_GRID[-2]]
        if lower.low_log_ratio > practical_margin:
            return CapacityConfirmation("right_censored", "right_censored")
    return CapacityConfirmation("confirmed", "")
