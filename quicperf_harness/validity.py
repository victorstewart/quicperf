"""Causal sample validity, censoring, resolution, and retry policy."""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from functools import reduce
from math import gcd
from typing import Sequence


INFRASTRUCTURE_TRANSIENT_REASONS = frozenset(
    {
        "external_cpu_or_irq_noise",
        "host_stability_monitor_transient",
        "host_stability_interval_transient",
        "coordinator_interruption",
        "journal_busy_timeout",
        "path_control_failure_before_endpoint_start",
    }
)


@dataclass(frozen=True)
class ProgressBucket:
    completed_units: int
    blocked_reason: str = ""


@dataclass(frozen=True)
class DurationSampleFacts:
    scenario: str
    termination_reason: str
    numerator: int
    denominator_raw_ns: int
    integer_operation_rate: bool
    useful_work_available_full_interval: bool = True
    work_cap_hits: int = 0
    byte_cap_hits: int = 0
    stream_cap_hits: int = 0
    stream_id_cap_hits: int = 0
    generator_starvation_events: int = 0
    counters_reconciled: bool = True
    endpoint_config_hashes_match: bool = True
    timing_gate_passed: bool = True
    trace_gate_passed: bool = True
    completion_gate_passed: bool = True
    progress_buckets: tuple[ProgressBucket, ...] = ()
    client_cpu_fraction_of_quota_p95: float = 0.0
    socket_drops: int = 0
    missed_offered_work_deadlines: int = 0
    negotiated_settings_match: bool = True
    data_blocked_frames: int = 0
    stream_data_blocked_frames: int = 0
    flow_control_write_blocked_events: int = 0
    flow_control_blocked_raw_ns: int = 0
    flow_control_block_evidence: bool = False
    flow_control_recovery_evidence: bool = False
    thermal_throttle_delta: int = 0
    swap_activity: bool = False
    governor_violation: bool = False
    irq_policy_violation: bool = False
    cgroup_policy_violation: bool = False
    backend_policy_violation: bool = False
    path_policy_violation: bool = False
    right_censored: bool = False


@dataclass(frozen=True)
class ValidityResult:
    valid: bool
    publication_valid: bool
    reasons: tuple[str, ...]
    censoring: tuple[str, ...]


def _positive_counter_reason(value: int, reason: str, reasons: list[str]) -> None:
    if value < 0:
        reasons.append(f"negative_{reason}")
    elif value:
        reasons.append(reason)


def validate_duration_sample(facts: DurationSampleFacts) -> ValidityResult:
    """Apply only predeclared causal gates; metric magnitude is never inspected."""

    reasons: list[str] = []
    censoring: list[str] = []
    if facts.termination_reason != "deadline_reached":
        reasons.append("termination_not_deadline_reached")
        censoring.append("right_censored")
    if facts.numerator < 0:
        reasons.append("negative_numerator")
    if facts.denominator_raw_ns <= 0:
        reasons.append("invalid_denominator")
    if not facts.useful_work_available_full_interval:
        reasons.append("useful_work_exhausted")
        censoring.append("finite_work_cap")
    for value, reason in (
        (facts.work_cap_hits, "work_cap_hit"),
        (facts.byte_cap_hits, "byte_cap_hit"),
        (facts.stream_cap_hits, "stream_cap_hit"),
        (facts.stream_id_cap_hits, "stream_id_cap_hit"),
    ):
        before = len(reasons)
        _positive_counter_reason(value, reason, reasons)
        if len(reasons) != before and value > 0:
            censoring.append("finite_work_cap")
    _positive_counter_reason(
        facts.generator_starvation_events, "generator_starvation", reasons
    )
    if not facts.counters_reconciled:
        reasons.append("counter_reconciliation_failed")
    if not facts.endpoint_config_hashes_match:
        reasons.append("endpoint_config_mismatch")
    if not facts.timing_gate_passed:
        reasons.append("timing_gate_failed")
    if not facts.trace_gate_passed:
        reasons.append("trace_gate_failed")
    if not facts.completion_gate_passed:
        reasons.append("completion_gate_failed")
    if not facts.progress_buckets:
        reasons.append("missing_progress_buckets")
    elif any(
        bucket.completed_units <= 0 and not bucket.blocked_reason
        for bucket in facts.progress_buckets
    ):
        reasons.append("progress_stall_without_cause")
        censoring.append("stalled")
    if (
        not math.isfinite(facts.client_cpu_fraction_of_quota_p95)
        or facts.client_cpu_fraction_of_quota_p95 < 0.0
        or facts.client_cpu_fraction_of_quota_p95 >= 0.80
    ):
        reasons.append("reference_client_headroom_failed")
    _positive_counter_reason(facts.socket_drops, "socket_drop", reasons)
    _positive_counter_reason(
        facts.missed_offered_work_deadlines, "missed_offered_work_deadline", reasons
    )
    if not facts.negotiated_settings_match:
        reasons.append("negotiated_setting_mismatch")

    blocked = (
        facts.data_blocked_frames
        or facts.stream_data_blocked_frames
        or facts.flow_control_write_blocked_events
        or facts.flow_control_blocked_raw_ns
    )
    if facts.scenario == "flow_control":
        if not blocked or not facts.flow_control_block_evidence:
            reasons.append("missing_flow_control_block_evidence")
        if not facts.flow_control_recovery_evidence:
            reasons.append("missing_flow_control_recovery_evidence")
    elif blocked:
        reasons.append("unexpected_flow_control_blocking")

    for violated, reason in (
        (facts.thermal_throttle_delta != 0, "thermal_throttle"),
        (facts.swap_activity, "swap_activity"),
        (facts.governor_violation, "governor_policy_violation"),
        (facts.irq_policy_violation, "irq_policy_violation"),
        (facts.cgroup_policy_violation, "cgroup_policy_violation"),
        (facts.backend_policy_violation, "backend_policy_violation"),
        (facts.path_policy_violation, "path_policy_violation"),
    ):
        if violated:
            reasons.append(reason)
    if facts.right_censored:
        censoring.append("right_censored")
    if facts.integer_operation_rate and facts.numerator < 400:
        censoring.append("resolution_limited")

    reasons = list(dict.fromkeys(reasons))
    censoring = list(dict.fromkeys(censoring))
    valid = not reasons
    return ValidityResult(valid, valid and not censoring, tuple(reasons), tuple(censoring))


@dataclass(frozen=True)
class RowResolution:
    distinct_numerators: int
    gcd_quantum: int
    median_numerator: float
    quantum_fraction: float
    labels: tuple[str, ...]
    publication_valid: bool


def assess_row_resolution(
    numerators: Sequence[int],
    *,
    interval_low: float,
    interval_high: float,
    verified_external_rate_limit: bool = False,
) -> RowResolution:
    if not numerators:
        raise ValueError("row resolution requires numerators")
    if any(not isinstance(value, int) or value < 0 for value in numerators):
        raise ValueError("numerators must be nonnegative integers")
    if not math.isfinite(interval_low) or not math.isfinite(interval_high):
        raise ValueError("interval bounds must be finite")
    if interval_low > interval_high:
        raise ValueError("interval bounds are reversed")
    positive = [value for value in numerators if value > 0]
    quantum = reduce(gcd, positive) if positive else 0
    median_numerator = float(statistics.median(numerators))
    fraction = quantum / median_numerator if median_numerator > 0.0 else math.inf
    labels: list[str] = []
    if fraction >= 0.0025:
        labels.append("resolution_limited")
    if interval_low == interval_high and not verified_external_rate_limit:
        labels.append("unexplained_zero_variance")
    return RowResolution(
        distinct_numerators=len(set(numerators)),
        gcd_quantum=quantum,
        median_numerator=median_numerator,
        quantum_fraction=fraction,
        labels=tuple(labels),
        publication_valid=not labels,
    )


def classify_failure(reason: str) -> str:
    if reason in INFRASTRUCTURE_TRANSIENT_REASONS:
        return "infrastructure_transient"
    if reason == "unsupported":
        return "unsupported"
    return "terminal"


def retry_allowed(reason: str, prior_infrastructure_retries: int) -> bool:
    if prior_infrastructure_retries < 0:
        raise ValueError("prior retry count must be nonnegative")
    return reason in INFRASTRUCTURE_TRANSIENT_REASONS and prior_infrastructure_retries == 0
