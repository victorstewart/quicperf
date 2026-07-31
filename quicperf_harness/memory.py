"""Fresh-process memory-curve planning and block-level fitting."""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Sequence

from .canonical import canonical_bytes
from .capacity import latin_square
from .planner import CANONICAL_SERVERS, SERVER_BACKENDS, assign_williams_rows, tagged_hash


MEMORY_ESTIMAND = "memory_curve"
MEMORY_N_VALUES = (0, 64, 256, 1024)


def memory_orders(campaign_seed: bytes, blocks: int = 12) -> tuple[tuple[int, ...], ...]:
    if blocks <= 0:
        raise ValueError("blocks must be positive")
    square = latin_square(MEMORY_N_VALUES, campaign_seed, label=b"memory-n")
    return tuple(square[index % len(square)] for index in range(blocks))


@dataclass(frozen=True)
class MemoryTrial:
    trial_id: str
    server: str
    server_backend: str
    session: int
    williams_row: int
    server_position: int
    block_position: int
    connections: int
    n_order: int


def plan_memory_campaign(
    *,
    campaign_seed: bytes,
    schedule_basis_hash: bytes,
    servers: Sequence[str] = CANONICAL_SERVERS,
    backends: Sequence[str] = SERVER_BACKENDS,
) -> tuple[MemoryTrial, ...]:
    """Freeze the exact 24-raw-row, four-point fresh-process memory campaign."""

    if len(schedule_basis_hash) != 32:
        raise ValueError("schedule_basis_hash must be 32 bytes")
    assignments = assign_williams_rows(servers, campaign_seed)
    orders = memory_orders(campaign_seed, len(assignments))
    trials: list[MemoryTrial] = []
    for block_position, (assignment, n_order) in enumerate(zip(assignments, orders, strict=True)):
        for server_position, server in enumerate(assignment.server_order):
            for backend in backends:
                for order_index, connections in enumerate(n_order):
                    coordinates = canonical_bytes(
                        {
                            "server": server,
                            "server_backend": backend,
                            "session": assignment.session,
                            "williams_row": assignment.row_index,
                            "connections": connections,
                        }
                    )
                    trials.append(
                        MemoryTrial(
                            trial_id=tagged_hash(
                                "memory-trial", schedule_basis_hash, coordinates
                            ).hex(),
                            server=server,
                            server_backend=backend,
                            session=assignment.session,
                            williams_row=assignment.row_index,
                            server_position=server_position,
                            block_position=block_position,
                            connections=connections,
                            n_order=order_index,
                        )
                    )
    return tuple(trials)


@dataclass(frozen=True)
class MemoryPoll:
    elapsed_seconds: float
    bytes_used: int


def memory_settling_time(
    polls: Sequence[MemoryPoll],
    *,
    minimum_seconds: float = 5.0,
    maximum_seconds: float = 15.0,
    interval_seconds: float = 0.1,
    max_change_per_second: float = 0.005,
) -> float | None:
    """Return the first end of two consecutive stable one-second windows."""

    if interval_seconds <= 0.0:
        raise ValueError("interval_seconds must be positive")
    ordered = sorted(polls, key=lambda poll: poll.elapsed_seconds)
    if any(
        not math.isfinite(poll.elapsed_seconds)
        or poll.elapsed_seconds < 0.0
        or poll.bytes_used < 0
        for poll in ordered
    ):
        raise ValueError("memory polls must have finite time and nonnegative bytes")
    if any(
        not math.isclose(
            current.elapsed_seconds - previous.elapsed_seconds,
            interval_seconds,
            rel_tol=0.0,
            abs_tol=1e-9,
        )
        for previous, current in zip(ordered, ordered[1:])
    ):
        raise ValueError("memory polls do not match the frozen cadence")
    per_second = int(round(1.0 / interval_seconds))
    if per_second <= 0:
        raise ValueError("invalid polling interval")
    stable = 0
    first_checkpoint = per_second
    last_checkpoint = min(
        len(ordered) - 1, int(math.floor(maximum_seconds / interval_seconds))
    )
    for end in range(first_checkpoint, last_checkpoint + 1, per_second):
        start = end - per_second
        if start < 0:
            continue
        before = ordered[start].bytes_used
        after = ordered[end].bytes_used
        if before <= 0 or after < 0:
            stable = 0
            continue
        relative_change = abs(after - before) / before
        stable = stable + 1 if relative_change < max_change_per_second else 0
        if stable >= 2 and ordered[end].elapsed_seconds >= minimum_seconds:
            return ordered[end].elapsed_seconds
    return None


def final_observation_median(
    polls: Sequence[MemoryPoll], settled_at: float, *, interval_seconds: float = 0.1
) -> float:
    if (
        interval_seconds <= 0.0
        or not math.isfinite(settled_at)
        or settled_at < 0.0
    ):
        raise ValueError("invalid final-observation interval")
    selected = sorted(
        (
            poll
            for poll in polls
            if settled_at < poll.elapsed_seconds <= settled_at + 2.0 + 1e-9
        ),
        key=lambda poll: poll.elapsed_seconds,
    )
    expected = int(round(2.0 / interval_seconds))
    if len(selected) != expected:
        raise ValueError(f"expected {expected} post-settle polls, got {len(selected)}")
    if any(poll.bytes_used < 0 for poll in selected):
        raise ValueError("memory polls must have nonnegative bytes")
    if any(
        not math.isclose(
            current.elapsed_seconds - previous.elapsed_seconds,
            interval_seconds,
            rel_tol=0.0,
            abs_tol=1e-9,
        )
        for previous, current in zip(selected, selected[1:])
    ):
        raise ValueError("post-settle polls do not match the frozen cadence")
    return float(statistics.median(poll.bytes_used for poll in selected))


@dataclass(frozen=True)
class MemoryPoint:
    connections: int
    bytes_used: float


@dataclass(frozen=True)
class MemoryFit:
    intercept: float
    bytes_per_connection: float
    fitted: tuple[float, ...]
    residuals: tuple[float, ...]
    max_absolute_residual: float
    observed_range: float
    status: str
    reason: str


def fit_memory_curve(points: Sequence[MemoryPoint]) -> MemoryFit:
    if tuple(point.connections for point in points) != MEMORY_N_VALUES:
        raise ValueError(f"memory curve must use exact N values {MEMORY_N_VALUES}")
    values = [float(point.bytes_used) for point in points]
    if any(not math.isfinite(value) or value < 0.0 for value in values):
        raise ValueError("memory values must be finite and nonnegative")
    xs = [float(point.connections) for point in points]
    x_mean = sum(xs) / len(xs)
    y_mean = sum(values) / len(values)
    denominator = sum((value - x_mean) ** 2 for value in xs)
    slope = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, values, strict=True)) / denominator
    intercept = y_mean - slope * x_mean
    fitted = tuple(intercept + slope * x for x in xs)
    residuals = tuple(y - prediction for y, prediction in zip(values, fitted, strict=True))
    maximum = max(abs(value) for value in residuals)
    observed_range = max(values) - min(values)

    reasons: list[str] = []
    if intercept <= 0.0 or slope <= 0.0:
        reasons.append("inconclusive_nonpositive_estimate")
    if observed_range == 0.0:
        reasons.append("model_misfit")
    elif maximum > 0.05 * observed_range:
        reasons.append("model_misfit")
    if any(next_value < value * 0.95 for value, next_value in zip(values, values[1:])):
        if "model_misfit" not in reasons:
            reasons.append("model_misfit")
    status = "claimable" if not reasons else "inconclusive"
    return MemoryFit(
        intercept=intercept,
        bytes_per_connection=slope,
        fitted=fitted,
        residuals=residuals,
        max_absolute_residual=maximum,
        observed_range=observed_range,
        status=status,
        reason=";".join(reasons),
    )
