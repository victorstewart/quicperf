"""Frozen nonpublication tail-window screening and held-out selection design."""

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
    tagged_hash,
    williams_rows,
)
from .statistics import wilson_upper_bound


TAIL_SCENARIOS = (
    "small_payload_pps",
    "datagram",
    "reqresp",
    "stream_churn",
    "close_reset_cleanup",
    "connect",
    "resumed_connect",
    "zero_rtt_reqresp",
)
DURATION_LADDER_SECONDS = (2, 5, 10, 20)
HELD_OUT_BLOCKS = 20
HELD_OUT_SIGN_PATTERNS = 1 << HELD_OUT_BLOCKS


@dataclass(frozen=True)
class TailWindowTrial:
    trial_id: str
    scenario: str
    server: str
    server_backend: str
    reference_client: str
    block: int
    phase: str
    slot: str
    status: str
    execution_order: int
    williams_row: int | None = None
    server_position: int | None = None
    duration_prefixes_seconds: tuple[int, ...] = DURATION_LADDER_SECONDS


@dataclass(frozen=True)
class TailWindowPlan:
    screening: tuple[TailWindowTrial, ...]
    held_out: tuple[TailWindowTrial, ...]


def _trial(
    basis: bytes,
    coordinates: Mapping[str, object],
    *,
    slot: str,
    status: str,
    execution_order: int,
) -> TailWindowTrial:
    identity = tagged_hash(
        "tail-window-trial", basis, canonical_bytes(coordinates), slot.encode("ascii")
    ).hex()
    return TailWindowTrial(
        trial_id=identity,
        scenario=str(coordinates["scenario"]),
        server=str(coordinates["server"]),
        server_backend=str(coordinates["server_backend"]),
        reference_client=str(coordinates["reference_client"]),
        block=int(coordinates["block"]),
        phase=str(coordinates["phase"]),
        slot=slot,
        status=status,
        execution_order=execution_order,
        williams_row=(
            int(coordinates["williams_row"])
            if "williams_row" in coordinates
            else None
        ),
        server_position=(
            int(coordinates["server_position"])
            if "server_position" in coordinates
            else None
        ),
    )


def plan_tail_window_qualification(
    *, campaign_seed: bytes, schedule_basis_hash: bytes
) -> TailWindowPlan:
    """Freeze all 384 screens and all 7,680 possible held-out primary IDs."""

    if not campaign_seed or len(schedule_basis_hash) != 32:
        raise ValueError("tail-window planning requires a seed and 256-bit basis")
    screening_unordered: list[tuple[bytes, Mapping[str, object]]] = []
    screening: list[TailWindowTrial] = []
    held_out: list[TailWindowTrial] = []
    for scenario in TAIL_SCENARIOS:
        for server in CANONICAL_SERVERS:
            for backend in SERVER_BACKENDS:
                for client in REFERENCE_CLIENTS:
                    coordinates = {
                        "phase": "screening",
                        "scenario": scenario,
                        "server": server,
                        "server_backend": backend,
                        "reference_client": client,
                        "block": 0,
                    }
                    screening_unordered.append(
                        (
                            hmac.new(
                                campaign_seed,
                                b"tail-window-screen-order"
                                + canonical_bytes(coordinates),
                                hashlib.sha256,
                            ).digest(),
                            coordinates,
                        )
                    )
    for execution_order, (_key, coordinates) in enumerate(
        sorted(screening_unordered, key=lambda item: item[0])
    ):
        for slot in ("primary", "retry"):
            screening.append(
                _trial(
                    schedule_basis_hash,
                    coordinates,
                    slot=slot,
                    status="active" if slot == "primary" else "dormant",
                    execution_order=execution_order,
                )
            )

    execution_order = 0
    rows = williams_rows(CANONICAL_SERVERS)
    for scenario in TAIL_SCENARIOS:
        for backend in SERVER_BACKENDS:
            for client in REFERENCE_CLIENTS:
                stratum = {
                    "scenario": scenario,
                    "server_backend": backend,
                    "reference_client": client,
                }
                ranked_blocks = sorted(
                    range(1, HELD_OUT_BLOCKS + 1),
                    key=lambda block: hmac.new(
                        campaign_seed,
                        canonical_bytes(
                            {
                                "label": "tail-window-held-out-block-order",
                                **stratum,
                                "block": block,
                            }
                        ),
                        hashlib.sha256,
                    ).digest(),
                )
                for row_ordinal, block in enumerate(ranked_blocks):
                    williams_row = row_ordinal % len(rows)
                    for server_position, server in enumerate(rows[williams_row]):
                        coordinates = {
                            "phase": "held_out",
                            "scenario": scenario,
                            "server": server,
                            "server_backend": backend,
                            "reference_client": client,
                            "block": block,
                            "williams_row": williams_row,
                            "server_position": server_position,
                        }
                        for slot in ("primary", "retry"):
                            held_out.append(
                                _trial(
                                    schedule_basis_hash,
                                    coordinates,
                                    slot=slot,
                                    status="dormant",
                                    execution_order=execution_order,
                                )
                            )
                        execution_order += 1
    trial_ids = [trial.trial_id for trial in (*screening, *held_out)]
    if len(trial_ids) != len(set(trial_ids)):
        raise ValueError("tail-window plan produced duplicate trial IDs")
    return TailWindowPlan(tuple(screening), tuple(held_out))


@dataclass(frozen=True)
class PrefixEvidence:
    eligible: int
    wilson_failure_upper: float
    valid: bool
    capped_or_stalled: bool = False
    p99_log_ratio_to_twenty_seconds: float = 0.0
    interval_low: float = 0.0
    interval_high: float = 0.0


@dataclass(frozen=True)
class TailWindowInterval:
    contrast: str
    mean_log_ratio: float
    standard_error: float
    low_log_ratio: float
    high_log_ratio: float


@dataclass(frozen=True)
class TailWindowMaxTResult:
    alpha: float
    sign_patterns: int
    critical_value: float
    intervals: tuple[TailWindowInterval, ...]


@dataclass(frozen=True)
class TailPrefixObservation:
    duration_seconds: int
    eligible_operations: int
    failed_or_censored_operations: int
    p99_ns: int
    validity_classification: str
    capped_or_stalled: bool = False


@dataclass(frozen=True)
class TailScreenCell:
    scenario: str
    server: str
    server_backend: str
    reference_client: str
    prefixes: tuple[TailPrefixObservation, ...]


@dataclass(frozen=True)
class TailHeldOutBlock:
    scenario: str
    server: str
    server_backend: str
    reference_client: str
    block: int
    prefixes: tuple[TailPrefixObservation, ...]


@dataclass(frozen=True)
class TailWindowAnalysis:
    screening_nominations: Mapping[str, int | None]
    selected_servers_by_stratum: Mapping[tuple[str, str, str], tuple[str, ...]]
    stratum_durations: Mapping[tuple[str, str, str], int | None]
    scenario_durations: Mapping[str, int | None]
    interval_results: Mapping[tuple[str, str, str], TailWindowMaxTResult]
    passed: bool
    reasons: tuple[str, ...]


def _sample_standard_error(values: Sequence[float]) -> float:
    center = sum(values) / len(values)
    return math.sqrt(
        sum((value - center) ** 2 for value in values)
        / (len(values) - 1)
        / len(values)
    )


def exact_twenty_block_simultaneous_intervals(
    contrasts: Mapping[str, Sequence[float]], *, alpha: float = 0.10
) -> TailWindowMaxTResult:
    """Enumerate all common 20-block signs with a Gray-code max-|t| kernel."""

    if not contrasts or not 0.0 < alpha < 1.0:
        raise ValueError("tail-window inference requires contrasts and alpha in (0,1)")
    names = tuple(sorted(contrasts))
    vectors = {name: tuple(float(value) for value in contrasts[name]) for name in names}
    if any(len(vector) != HELD_OUT_BLOCKS for vector in vectors.values()):
        raise ValueError("every tail-window contrast requires exactly 20 blocks")
    if any(not math.isfinite(value) for vector in vectors.values() for value in vector):
        raise ValueError("tail-window contrasts must be finite")
    means = {name: sum(vectors[name]) / HELD_OUT_BLOCKS for name in names}
    centered = {
        name: tuple(value - means[name] for value in vectors[name]) for name in names
    }
    sums_of_squares = {
        name: sum(value * value for value in centered[name]) for name in names
    }
    if all(value == 0.0 for value in sums_of_squares.values()):
        return TailWindowMaxTResult(
            alpha,
            HELD_OUT_SIGN_PATTERNS,
            0.0,
            tuple(
                TailWindowInterval(name, means[name], 0.0, means[name], means[name])
                for name in names
            ),
        )
    signed_sums = {name: -sum(centered[name]) for name in names}
    maxima: list[float] = []
    previous_gray = 0
    for pattern in range(HELD_OUT_SIGN_PATTERNS):
        gray = pattern ^ (pattern >> 1)
        if pattern:
            changed = gray ^ previous_gray
            bit = changed.bit_length() - 1
            sign = 1.0 if gray & changed else -1.0
            for name in names:
                signed_sums[name] += 2.0 * sign * centered[name][bit]
        previous_gray = gray
        maximum = 0.0
        for name in names:
            mean = signed_sums[name] / HELD_OUT_BLOCKS
            variance_numerator = max(
                0.0,
                sums_of_squares[name] - HELD_OUT_BLOCKS * mean * mean,
            )
            standard_error = math.sqrt(
                variance_numerator
                / (HELD_OUT_BLOCKS - 1)
                / HELD_OUT_BLOCKS
            )
            statistic = (
                0.0
                if standard_error == 0.0 and mean == 0.0
                else math.inf
                if standard_error == 0.0
                else abs(mean / standard_error)
            )
            maximum = max(maximum, statistic)
        maxima.append(maximum)
    maxima.sort()
    critical = maxima[math.ceil((1.0 - alpha) * len(maxima)) - 1]
    intervals = []
    for name in names:
        standard_error = _sample_standard_error(vectors[name])
        half_width = critical * standard_error
        intervals.append(
            TailWindowInterval(
                contrast=name,
                mean_log_ratio=means[name],
                standard_error=standard_error,
                low_log_ratio=means[name] - half_width,
                high_log_ratio=means[name] + half_width,
            )
        )
    return TailWindowMaxTResult(alpha, HELD_OUT_SIGN_PATTERNS, critical, tuple(intervals))


def _prefix_index(
    prefixes: Sequence[TailPrefixObservation], label: str
) -> dict[int, TailPrefixObservation]:
    indexed = {prefix.duration_seconds: prefix for prefix in prefixes}
    if len(indexed) != len(prefixes) or set(indexed) != set(DURATION_LADDER_SECONDS):
        raise ValueError(f"{label} requires exactly the 2/5/10/20-second prefixes")
    for duration, prefix in indexed.items():
        if (
            isinstance(prefix.eligible_operations, bool)
            or prefix.eligible_operations < 0
            or isinstance(prefix.failed_or_censored_operations, bool)
            or prefix.failed_or_censored_operations < 0
            or isinstance(prefix.p99_ns, bool)
            or prefix.p99_ns <= 0
            or not prefix.validity_classification
        ):
            raise ValueError(f"{label}/{duration}s prefix evidence is malformed")
    return indexed


def _prefix_evidence(prefix: TailPrefixObservation) -> PrefixEvidence:
    trials = prefix.eligible_operations + prefix.failed_or_censored_operations
    upper = (
        wilson_upper_bound(prefix.failed_or_censored_operations, trials)
        if trials
        else 1.0
    )
    return PrefixEvidence(
        eligible=prefix.eligible_operations,
        wilson_failure_upper=upper,
        valid=prefix.validity_classification == "valid",
        capped_or_stalled=prefix.capped_or_stalled,
    )


def screen_tail_window_qualification(
    screens: Sequence[TailScreenCell],
) -> tuple[
    dict[str, int | None],
    dict[tuple[str, str, str], tuple[str, ...]],
    tuple[str, ...],
]:
    """Validate the 384 screens and mechanically nominate durations/servers."""

    screen_expected = {
        (scenario, server, backend, client)
        for scenario in TAIL_SCENARIOS
        for server in CANONICAL_SERVERS
        for backend in SERVER_BACKENDS
        for client in REFERENCE_CLIENTS
    }
    screen_index = {
        (cell.scenario, cell.server, cell.server_backend, cell.reference_client): cell
        for cell in screens
    }
    if len(screen_index) != len(screens) or set(screen_index) != screen_expected:
        raise ValueError("tail-window screening evidence is not the exact 384-cell matrix")
    screen_prefixes = {
        key: _prefix_index(cell.prefixes, f"screen/{key!r}")
        for key, cell in screen_index.items()
    }
    nominations: dict[str, int | None] = {}
    selections: dict[tuple[str, str, str], tuple[str, ...]] = {}
    reasons: list[str] = []
    for scenario in TAIL_SCENARIOS:
        scenario_cells = [
            {
                duration: _prefix_evidence(screen_prefixes[key][duration])
                for duration in DURATION_LADDER_SECONDS
            }
            for key in screen_expected
            if key[0] == scenario
        ]
        nomination = nominate_screening_duration(scenario_cells)
        nominations[scenario] = nomination
        if nomination is None:
            reasons.append(f"screening_nomination_failed:{scenario}")
            continue
        for backend in SERVER_BACKENDS:
            for client in REFERENCE_CLIENTS:
                server_evidence: dict[str, PrefixEvidence] = {}
                for server in CANONICAL_SERVERS:
                    prefixes = screen_prefixes[(scenario, server, backend, client)]
                    selected_prefix = prefixes[nomination]
                    reference_prefix = prefixes[20]
                    evidence = _prefix_evidence(selected_prefix)
                    server_evidence[server] = replace(
                        evidence,
                        p99_log_ratio_to_twenty_seconds=math.log(
                            selected_prefix.p99_ns / reference_prefix.p99_ns
                        ),
                    )
                selections[(scenario, backend, client)] = selected_servers(server_evidence)
    return nominations, selections, tuple(reasons)


def analyze_tail_window_qualification(
    screens: Sequence[TailScreenCell],
    held_out: Sequence[TailHeldOutBlock],
) -> TailWindowAnalysis:
    """Apply screening, frozen selection, exact held-out inference, and global duration."""

    nominations, selections, screen_reasons = screen_tail_window_qualification(screens)
    reasons = list(screen_reasons)

    held_index = {
        (
            cell.scenario,
            cell.server,
            cell.server_backend,
            cell.reference_client,
            cell.block,
        ): cell
        for cell in held_out
    }
    if len(held_index) != len(held_out):
        raise ValueError("tail-window held-out evidence contains duplicate blocks")
    expected_held = {
        (scenario, server, backend, client, block)
        for (scenario, backend, client), servers in selections.items()
        for server in servers
        for block in range(1, HELD_OUT_BLOCKS + 1)
    }
    if set(held_index) != expected_held:
        raise ValueError("tail-window held-out evidence is not the exact activated matrix")
    held_prefixes = {
        key: _prefix_index(cell.prefixes, f"held/{key!r}")
        for key, cell in held_index.items()
    }
    stratum_durations: dict[tuple[str, str, str], int | None] = {}
    interval_results: dict[tuple[str, str, str], TailWindowMaxTResult] = {}
    for stratum, servers in sorted(selections.items()):
        scenario, backend, client = stratum
        contrasts: dict[str, tuple[float, ...]] = {}
        for server in servers:
            for duration in DURATION_LADDER_SECONDS[:-1]:
                contrasts[f"{server}/{duration}s"] = tuple(
                    math.log(
                        held_prefixes[(scenario, server, backend, client, block)][duration].p99_ns
                        / held_prefixes[(scenario, server, backend, client, block)][20].p99_ns
                    )
                    for block in range(1, HELD_OUT_BLOCKS + 1)
                )
        result = exact_twenty_block_simultaneous_intervals(contrasts)
        interval_results[stratum] = result
        intervals = {interval.contrast: interval for interval in result.intervals}
        activated_cells: list[dict[int, PrefixEvidence]] = []
        for server in servers:
            by_duration: dict[int, PrefixEvidence] = {}
            for duration in DURATION_LADDER_SECONDS:
                prefixes = [
                    held_prefixes[(scenario, server, backend, client, block)][duration]
                    for block in range(1, HELD_OUT_BLOCKS + 1)
                ]
                references = [
                    held_prefixes[(scenario, server, backend, client, block)][20]
                    for block in range(1, HELD_OUT_BLOCKS + 1)
                ]
                prefix_evidence = tuple(_prefix_evidence(prefix) for prefix in prefixes)
                if duration == 20:
                    low = high = 0.0
                else:
                    interval = intervals[f"{server}/{duration}s"]
                    low, high = interval.low_log_ratio, interval.high_log_ratio
                by_duration[duration] = PrefixEvidence(
                    eligible=min(item.eligible for item in prefix_evidence),
                    wilson_failure_upper=max(
                        item.wilson_failure_upper for item in prefix_evidence
                    ),
                    valid=all(
                        item.valid
                        and prefix.validity_classification
                        == reference.validity_classification
                        for item, prefix, reference in zip(
                            prefix_evidence, prefixes, references, strict=True
                        )
                    ),
                    capped_or_stalled=any(
                        item.capped_or_stalled for item in prefix_evidence
                    ),
                    interval_low=low,
                    interval_high=high,
                )
            activated_cells.append(by_duration)
        duration = qualify_stratum_duration(
            int(nominations[scenario]), activated_cells
        )
        stratum_durations[stratum] = duration
        if duration is None:
            reasons.append(
                f"held_out_duration_failed:{scenario}/{backend}/{client}"
            )

    scenario_durations: dict[str, int | None] = {}
    for scenario in TAIL_SCENARIOS:
        if nominations[scenario] is None:
            scenario_durations[scenario] = None
            continue
        duration = scenario_duration(
            {
                (backend, client): stratum_durations.get(
                    (scenario, backend, client)
                )
                for backend in SERVER_BACKENDS
                for client in REFERENCE_CLIENTS
            }
        )
        scenario_durations[scenario] = duration
        if duration is None:
            reasons.append(f"scenario_duration_failed:{scenario}")
    unique_reasons = tuple(dict.fromkeys(reasons))
    return TailWindowAnalysis(
        screening_nominations=nominations,
        selected_servers_by_stratum=selections,
        stratum_durations=stratum_durations,
        scenario_durations=scenario_durations,
        interval_results=interval_results,
        passed=not unique_reasons,
        reasons=unique_reasons,
    )


def nominate_screening_duration(
    cells: Sequence[Mapping[int, PrefixEvidence]],
) -> int | None:
    """Choose the shortest prefix whose screening facts pass for every cell."""

    if not cells:
        raise ValueError("tail-window screening requires cells")
    for duration in DURATION_LADDER_SECONDS:
        evidence = [cell.get(duration) for cell in cells]
        if all(
            item is not None
            and item.valid
            and not item.capped_or_stalled
            and item.eligible >= 1_280
            and item.wilson_failure_upper < 0.01
            for item in evidence
        ):
            return duration
    return None


def selected_servers(
    evidence: Mapping[str, PrefixEvidence],
) -> tuple[str, ...]:
    """Return count-worst, discrepancy-worst, and baseline union with fixed ties."""

    if set(evidence) != set(CANONICAL_SERVERS):
        raise ValueError("screening selection requires every canonical server")
    rank = {server: index for index, server in enumerate(CANONICAL_SERVERS)}
    count_worst = min(
        CANONICAL_SERVERS,
        key=lambda server: (evidence[server].eligible, rank[server]),
    )
    discrepancy_worst = max(
        CANONICAL_SERVERS,
        key=lambda server: (
            abs(evidence[server].p99_log_ratio_to_twenty_seconds),
            -rank[server],
        ),
    )
    selected = {"ngtcp2perf", count_worst, discrepancy_worst}
    return tuple(server for server in CANONICAL_SERVERS if server in selected)


def activate_held_out(
    plan: TailWindowPlan,
    selected: Mapping[tuple[str, str, str], Sequence[str]],
) -> TailWindowPlan:
    allowed = {
        (scenario, backend, client)
        for scenario in TAIL_SCENARIOS
        for backend in SERVER_BACKENDS
        for client in REFERENCE_CLIENTS
    }
    if set(selected) != allowed:
        raise ValueError("held-out activation requires every frozen stratum")
    activated = []
    for trial in plan.held_out:
        key = (trial.scenario, trial.server_backend, trial.reference_client)
        chosen = set(selected[key])
        if not chosen <= set(CANONICAL_SERVERS) or "ngtcp2perf" not in chosen:
            raise ValueError("held-out activation names an invalid server set")
        status = (
            "active"
            if trial.slot == "primary" and trial.server in chosen
            else "dormant"
            if trial.slot == "retry" and trial.server in chosen
            else "not_selected"
        )
        activated.append(replace(trial, status=status))
    return TailWindowPlan(plan.screening, tuple(activated))


def qualify_stratum_duration(
    nominated_seconds: int,
    activated_cells: Sequence[Mapping[int, PrefixEvidence]],
) -> int | None:
    if nominated_seconds not in DURATION_LADDER_SECONDS or not activated_cells:
        raise ValueError("invalid tail-window held-out inputs")
    margin = math.log(1.02)
    for duration in DURATION_LADDER_SECONDS:
        if duration < nominated_seconds:
            continue
        evidence = [cell.get(duration) for cell in activated_cells]
        if all(
            item is not None
            and item.valid
            and not item.capped_or_stalled
            and item.eligible >= 1_024
            and item.wilson_failure_upper < 0.01
            and (
                duration == 20
                or item.interval_low >= -margin
                and item.interval_high <= margin
            )
            for item in evidence
        ):
            return duration
    return None


def scenario_duration(
    stratum_durations: Mapping[tuple[str, str], int | None],
) -> int | None:
    expected = {
        (backend, client)
        for backend in SERVER_BACKENDS
        for client in REFERENCE_CLIENTS
    }
    if set(stratum_durations) != expected:
        raise ValueError("tail-window scenario duration requires all four strata")
    if any(duration is None for duration in stratum_durations.values()):
        return None
    values = tuple(int(duration) for duration in stratum_durations.values())
    if any(duration not in DURATION_LADDER_SECONDS for duration in values):
        raise ValueError("tail-window stratum duration is outside the frozen ladder")
    return max(values)
