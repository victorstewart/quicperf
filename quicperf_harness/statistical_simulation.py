"""Deterministic calibration for the v2 exact paired-inference policy.

The production interval enumerates every common sign vector.  Calibration uses
the same statistic, with the global-sign symmetry removed, and checks that
accelerated kernel against :func:`paired_max_t_intervals` before emitting an
artifact.  All artifact rates retain integer numerators so policy decisions do
not depend on rounded display values.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .statistics import (
    MEMORY_MARGIN,
    MEMORY_SD_ENVELOPE,
    RATE_MARGIN,
    RATE_SD_ENVELOPE,
    SUPERBLOCKS,
    pair_session_superblocks,
    paired_log_differences,
    paired_max_t_intervals,
)


SCHEMA_VERSION = "quicperf.statistical-simulation.v3"
ALGORITHM_VERSION = "paired-session-superblock-max-t-calibration-v3"
DEFAULT_SEED = "quicperf-v2-superblock-calibration-2026-07-18"
MINIMUM_CAMPAIGNS = 25_000
BLOCKS = SUPERBLOCKS
RAW_ROWS = 2 * BLOCKS
SIGN_PATTERNS = 1 << BLOCKS
PRIMARY_CONTRASTS = 11
ALL_PAIRS_CONTRASTS = math.comb(PRIMARY_CONTRASTS + 1, 2)
ALPHA = 0.05
IID_COVERAGE_LOW = 0.935
IID_COVERAGE_HIGH = 0.965
STRESS_COVERAGE_LOW = 0.935
MAX_ERROR_RATE = 0.055
MINIMUM_PLANNING_PROBABILITY = 0.80


@dataclass(frozen=True, slots=True)
class TrialObservation:
    """One simulation input row after validity and finite-work evaluation."""

    trial_id: str
    log_effect: float
    status: str = "valid"
    capped: bool = False


@dataclass(frozen=True, slots=True)
class ConditionSpec:
    name: str
    generator: str
    family_size: int = 1
    iid_nominal: bool = False


CONDITIONS = (
    ConditionSpec("iid_lognormal", "iid_lognormal", iid_nominal=True),
    ConditionSpec(
        "iid_familywise_null", "iid_family", PRIMARY_CONTRASTS, iid_nominal=True
    ),
    ConditionSpec(
        "iid_all_pairs_familywise_null",
        "iid_all_pairs",
        ALL_PAIRS_CONTRASTS,
        iid_nominal=True,
    ),
    ConditionSpec(
        "heteroskedastic_implementations",
        "heteroskedastic",
        PRIMARY_CONTRASTS,
    ),
    ConditionSpec("block_and_session_drift", "drift"),
    ConditionSpec("ar1_time_effects", "ar1"),
    ConditionSpec("order_effects", "order"),
    ConditionSpec("predecessor_effects", "predecessor"),
    ConditionSpec("skewed_log_effects", "skew"),
    ConditionSpec("heavy_tailed_log_effects", "heavy_tail"),
    ConditionSpec("lower_is_better_metrics", "lower_is_better"),
    ConditionSpec("invalid_failed_censored_rows", "invalid_rows"),
    ConditionSpec("caps_and_quantization", "caps_quantization"),
    ConditionSpec("reference_client_and_session_interactions", "interactions"),
    ConditionSpec("cross_session_rho_0_coverage", "session_pair_rho_0"),
    ConditionSpec("cross_session_rho_0_25_coverage", "session_pair_rho_0_25"),
    ConditionSpec("cross_session_rho_0_50_stress", "session_pair_rho_0_50"),
)
CONDITION_NAMES = tuple(condition.name for condition in CONDITIONS)


def _derived_seed(seed: str, label: str) -> int:
    digest = hashlib.sha256(
        ALGORITHM_VERSION.encode("ascii")
        + b"\0"
        + seed.encode("utf-8")
        + b"\0"
        + label.encode("ascii")
    ).digest()
    return int.from_bytes(digest, "big")


def _ratio(numerator: int, denominator: int) -> str:
    return format(numerator / denominator, ".17g")


def _float(value: float) -> str:
    return format(value, ".17g")


def _beta_continued_fraction(a: float, b: float, x: float) -> float:
    """Evaluate the incomplete-beta continued fraction deterministically."""

    maximum_iterations = 400
    epsilon = 3.0e-14
    floor = 1.0e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    d = floor if abs(d) < floor else d
    d = 1.0 / d
    result = d
    for iteration in range(1, maximum_iterations + 1):
        even = 2 * iteration
        numerator = iteration * (b - iteration) * x / (
            (qam + even) * (a + even)
        )
        d = 1.0 + numerator * d
        d = floor if abs(d) < floor else d
        c = 1.0 + numerator / c
        c = floor if abs(c) < floor else c
        d = 1.0 / d
        result *= d * c
        numerator = -(
            (a + iteration)
            * (qab + iteration)
            * x
            / ((a + even) * (qap + even))
        )
        d = 1.0 + numerator * d
        d = floor if abs(d) < floor else d
        c = 1.0 + numerator / c
        c = floor if abs(c) < floor else c
        d = 1.0 / d
        delta = d * c
        result *= delta
        if abs(delta - 1.0) <= epsilon:
            return result
    raise ArithmeticError("incomplete-beta continued fraction did not converge")


def _regularized_beta(x: float, a: float, b: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_factor = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    factor = math.exp(log_factor)
    if x < (a + 1.0) / (a + b + 2.0):
        return factor * _beta_continued_fraction(a, b, x) / a
    return 1.0 - factor * _beta_continued_fraction(b, a, 1.0 - x) / b


def exact_binomial_lower_bound(
    successes: int, trials: int, *, alpha: float = 0.05
) -> float:
    """One-sided Clopper-Pearson lower confidence bound."""

    if (
        not isinstance(successes, int)
        or isinstance(successes, bool)
        or not isinstance(trials, int)
        or isinstance(trials, bool)
        or trials <= 0
        or not 0 <= successes <= trials
        or not 0.0 < alpha < 1.0
    ):
        raise ValueError("invalid exact-binomial confidence inputs")
    if successes == 0:
        return 0.0
    low, high = 0.0, 1.0
    a = float(successes)
    b = float(trials - successes + 1)
    for _ in range(80):
        midpoint = (low + high) / 2.0
        if _regularized_beta(midpoint, a, b) < alpha:
            low = midpoint
        else:
            high = midpoint
    return (low + high) / 2.0


def deduplicated_complete_mean(
    rows: Sequence[TrialObservation],
) -> float | None:
    """Return a complete 12-superblock mean, rejecting invalid/conflicting input.

    Identical replay rows are idempotent.  A reused trial identifier with
    different content is an integrity failure rather than another sample.
    """

    unique: dict[str, TrialObservation] = {}
    for row in rows:
        previous = unique.setdefault(row.trial_id, row)
        if previous != row:
            raise ValueError(f"conflicting replay for trial {row.trial_id!r}")
    if len(unique) != BLOCKS:
        return None
    ordered = tuple(unique[key] for key in sorted(unique))
    if any(
        row.status != "valid"
        or row.capped
        or not math.isfinite(row.log_effect)
        for row in ordered
    ):
        return None
    return sum(row.log_effect for row in ordered) / BLOCKS


def _sample_standard_error(values: Sequence[float]) -> float:
    mean = sum(values) / len(values)
    return math.sqrt(
        sum((value - mean) ** 2 for value in values)
        / (len(values) - 1)
        / len(values)
    )


def _exact_max_t_critical(vectors: Sequence[Sequence[float]]) -> float:
    """Exact common-sign max-|t| critical value with sign symmetry removed.

    For a centered vector, the signed sum determines its studentized mean
    because sign changes preserve the uncentered sum of squares.  Enumerating
    the first eleven signs with the final sign fixed therefore represents each
    of the 4,096 absolute statistics exactly twice.
    """

    if not vectors or any(len(vector) != BLOCKS for vector in vectors):
        raise ValueError("calibration requires one or more 12-row contrasts")
    maxima = [0.0] * (SIGN_PATTERNS // 2)
    scale = math.sqrt((BLOCKS - 1) / BLOCKS)
    for vector in vectors:
        if any(not math.isfinite(value) for value in vector):
            raise ValueError("calibration contrasts must be finite")
        mean = sum(vector) / BLOCKS
        centered = tuple(value - mean for value in vector)
        squared_sum = sum(value * value for value in centered)
        if squared_sum == 0.0:
            continue
        subset_sums = [0.0]
        for value in centered[:-1]:
            subset_sums += [partial + value for partial in subset_sums]
        centered_sum = sum(centered)
        for index, partial in enumerate(subset_sums):
            signed_sum = abs(2.0 * partial - centered_sum)
            denominator_squared = (
                squared_sum - signed_sum * signed_sum / BLOCKS
            )
            if denominator_squared <= 0.0:
                statistic = math.inf if signed_sum else 0.0
            else:
                statistic = signed_sum * scale / math.sqrt(denominator_squared)
            if statistic > maxima[index]:
                maxima[index] = statistic
    maxima.sort()
    full_order_index = math.ceil((1.0 - ALPHA) * SIGN_PATTERNS) - 1
    return maxima[full_order_index // 2]


def _intervals(
    vectors: Sequence[Sequence[float]],
) -> tuple[float, tuple[tuple[float, float, float], ...]]:
    critical = _exact_max_t_critical(vectors)
    intervals = []
    for vector in vectors:
        estimate = sum(vector) / BLOCKS
        half_width = critical * _sample_standard_error(vector)
        intervals.append((estimate, estimate - half_width, estimate + half_width))
    return critical, tuple(intervals)


def _normal(rng: random.Random, standard_deviation: float) -> float:
    return rng.gauss(0.0, standard_deviation)


def _centered(values: Sequence[float]) -> tuple[float, ...]:
    mean = sum(values) / len(values)
    return tuple(value - mean for value in values)


def _normalized_rms(values: Sequence[float]) -> tuple[float, ...]:
    centered = _centered(values)
    rms = math.sqrt(sum(value * value for value in centered) / len(centered))
    return tuple(value / rms for value in centered)


_LINEAR = _normalized_rms(tuple(float(index) for index in range(BLOCKS)))
_SESSION = (-1.0,) * 6 + (1.0,) * 6
_ORDER = (-1.0, 1.0) * 6
_PREDECESSOR = _normalized_rms((-1.0, 0.0, 1.0) * 4)
_CLIENT = tuple(value / 2.0 for value in _ORDER)
_SESSION_CODE = tuple(value / 2.0 for value in _SESSION)
_INTERACTION = tuple(
    client * session
    for client, session in zip(_CLIENT, _SESSION_CODE, strict=True)
)
_IMPLEMENTATION_SD_SCALES = tuple(0.5 + index / 10.0 for index in range(11))


def _single_condition_vector(generator: str, rng: random.Random) -> tuple[float, ...]:
    sd = RATE_SD_ENVELOPE
    if generator == "iid_lognormal":
        implementation_sd = sd / math.sqrt(2.0)
        baseline = tuple(math.exp(_normal(rng, implementation_sd)) for _ in range(BLOCKS))
        candidate = tuple(math.exp(_normal(rng, implementation_sd)) for _ in range(BLOCKS))
        return paired_log_differences(candidate, baseline, higher_is_better=True)
    if generator == "drift":
        random_sd = 0.021
        return tuple(
            _normal(rng, random_sd) + 0.005 * linear + 0.004 * session
            for linear, session in zip(_LINEAR, _SESSION, strict=True)
        )
    if generator == "ar1":
        # Strong common observation-time correlation cancels under pairing;
        # retain a predeclared 0.02 differential AR component as the stress.
        common_rho = 0.60
        common_sd = 0.040
        common = [_normal(rng, common_sd)]
        for _ in range(1, BLOCKS):
            common.append(
                common_rho * common[-1]
                + _normal(rng, common_sd * math.sqrt(1.0 - common_rho * common_rho))
            )
        differential_rho = 0.02
        innovation_sd = sd * math.sqrt(1.0 - differential_rho * differential_rho)
        differential = [_normal(rng, sd)]
        for _ in range(1, BLOCKS):
            differential.append(
                differential_rho * differential[-1] + _normal(rng, innovation_sd)
            )
        baseline = tuple(
            math.exp(shared - delta / 2.0)
            for shared, delta in zip(common, differential, strict=True)
        )
        candidate = tuple(
            math.exp(shared + delta / 2.0)
            for shared, delta in zip(common, differential, strict=True)
        )
        return paired_log_differences(candidate, baseline, higher_is_better=True)
    if generator == "order":
        return tuple(
            _normal(rng, 0.024) + 0.006 * order
            for order in _ORDER
        )
    if generator == "predecessor":
        return tuple(
            _normal(rng, 0.024) + 0.006 * predecessor
            for predecessor in _PREDECESSOR
        )
    if generator == "skew":
        shape = 0.12
        mean = math.exp(shape * shape / 2.0)
        variance = (math.exp(shape * shape) - 1.0) * math.exp(shape * shape)
        return tuple(
            sd * (math.exp(_normal(rng, shape)) - mean) / math.sqrt(variance)
            for _ in range(BLOCKS)
        )
    if generator == "heavy_tail":
        degrees_of_freedom = 5.0
        scale = sd * math.sqrt((degrees_of_freedom - 2.0) / degrees_of_freedom)
        return tuple(
            scale
            * rng.gauss(0.0, 1.0)
            / math.sqrt(rng.gammavariate(degrees_of_freedom / 2.0, 2.0) / degrees_of_freedom)
            for _ in range(BLOCKS)
        )
    if generator == "lower_is_better":
        implementation_sd = sd / math.sqrt(2.0)
        first = tuple(math.exp(_normal(rng, implementation_sd)) for _ in range(BLOCKS))
        second = tuple(math.exp(_normal(rng, implementation_sd)) for _ in range(BLOCKS))
        return paired_log_differences(first, second, higher_is_better=False)
    if generator == "caps_quantization":
        baseline_logs = tuple(_normal(rng, sd / math.sqrt(2.0)) for _ in range(BLOCKS))
        candidate_logs = tuple(_normal(rng, sd / math.sqrt(2.0)) for _ in range(BLOCKS))
        quantum = 0.001
        baseline = tuple(round(math.exp(value) / quantum) * quantum for value in baseline_logs)
        candidate = tuple(round(math.exp(value) / quantum) * quantum for value in candidate_logs)
        return paired_log_differences(candidate, baseline, higher_is_better=True)
    if generator == "interactions":
        return tuple(
            _normal(rng, 0.021)
            + 0.010 * client
            + 0.008 * session
            + 0.006 * interaction
            for client, session, interaction in zip(
                _CLIENT, _SESSION_CODE, _INTERACTION, strict=True
            )
        )
    session_correlations = {
        "session_pair_rho_0": 0.0,
        "session_pair_rho_0_25": 0.25,
        "session_pair_rho_0_50": 0.50,
    }
    if generator in session_correlations:
        return _correlated_superblock_vectors(
            rng, RATE_SD_ENVELOPE, session_correlations[generator], family_size=1
        )[0]
    raise ValueError(f"unknown simulation generator {generator!r}")


def _family_vectors(
    rng: random.Random, paired_log_ratio_sd: float = RATE_SD_ENVELOPE
) -> tuple[tuple[float, ...], ...]:
    implementation_sd = paired_log_ratio_sd / math.sqrt(2.0)
    implementations = tuple(
        tuple(_normal(rng, implementation_sd) for _ in range(BLOCKS))
        for _ in range(PRIMARY_CONTRASTS + 1)
    )
    baseline = implementations[0]
    return tuple(
        tuple(
            candidate - base
            for candidate, base in zip(implementation, baseline, strict=True)
        )
        for implementation in implementations[1:]
    )


def _correlated_superblock_vectors(
    rng: random.Random,
    raw_contrast_sd: float,
    correlation: float,
    *,
    family_size: int = PRIMARY_CONTRASTS,
) -> tuple[tuple[float, ...], ...]:
    """Generate two correlated raw sessions, then pair their matching rows."""

    if not -1.0 <= correlation <= 1.0:
        raise ValueError("cross-session correlation must be in [-1, 1]")
    implementation_sd = raw_contrast_sd / math.sqrt(2.0)
    innovation_scale = math.sqrt(max(0.0, 1.0 - correlation * correlation))
    implementations: list[tuple[tuple[float, ...], tuple[float, ...]]] = []
    for _ in range(family_size + 1):
        session_one = tuple(
            _normal(rng, implementation_sd) for _ in range(BLOCKS)
        )
        session_two = tuple(
            correlation * first
            + innovation_scale * _normal(rng, implementation_sd)
            for first in session_one
        )
        implementations.append((session_one, session_two))
    baseline_one, baseline_two = implementations[0]
    vectors = []
    for candidate_one, candidate_two in implementations[1:]:
        raw_one = tuple(
            candidate - baseline
            for candidate, baseline in zip(
                candidate_one, baseline_one, strict=True
            )
        )
        raw_two = tuple(
            candidate - baseline
            for candidate, baseline in zip(
                candidate_two, baseline_two, strict=True
            )
        )
        vectors.append(
            pair_session_superblocks(
                raw_one + raw_two,
                (1,) * BLOCKS + (2,) * BLOCKS,
                tuple(range(BLOCKS)) * 2,
            )
        )
    return tuple(vectors)


def _all_pairs_vectors(rng: random.Random) -> tuple[tuple[float, ...], ...]:
    implementation_sd = RATE_SD_ENVELOPE / math.sqrt(2.0)
    implementations = tuple(
        tuple(_normal(rng, implementation_sd) for _ in range(BLOCKS))
        for _ in range(PRIMARY_CONTRASTS + 1)
    )
    return tuple(
        tuple(
            first_value - second_value
            for first_value, second_value in zip(first, second, strict=True)
        )
        for first, second in itertools.combinations(implementations, 2)
    )


def _heteroskedastic_vectors(rng: random.Random) -> tuple[tuple[float, ...], ...]:
    implementation_sd = RATE_SD_ENVELOPE / math.sqrt(2.0)
    baseline = tuple(_normal(rng, implementation_sd) for _ in range(BLOCKS))
    return tuple(
        tuple(
            _normal(rng, implementation_sd * scale) - base
            for base in baseline
        )
        for scale in _IMPLEMENTATION_SD_SCALES
    )


def _invalid_rows(campaign: int) -> tuple[TrialObservation, ...]:
    statuses = ("invalid", "failed", "censored")
    invalid_index = campaign % BLOCKS
    return tuple(
        TrialObservation(
            f"trial-{index:02d}",
            0.001 * index,
            statuses[campaign % len(statuses)] if index == invalid_index else "valid",
        )
        for index in range(BLOCKS)
    )


def _capped_rows() -> tuple[TrialObservation, ...]:
    return tuple(
        TrialObservation(f"trial-{index:02d}", 0.001 * index, capped=index == 0)
        for index in range(BLOCKS)
    )


def _condition_parameters(generator: str) -> Mapping[str, str]:
    parameters = {
        "iid_lognormal": {"paired_log_ratio_sd": _float(RATE_SD_ENVELOPE)},
        "iid_family": {
            "paired_log_ratio_sd": _float(RATE_SD_ENVELOPE),
            "shared_baseline": "true",
        },
        "iid_all_pairs": {
            "paired_log_ratio_sd": _float(RATE_SD_ENVELOPE),
            "implementation_count": "12",
        },
        "heteroskedastic": {
            "candidate_implementation_sd_scale_range": "0.5..1.5",
            "shared_baseline_sd_scale": "1",
        },
        "drift": {"block_drift_sd": "0.005", "session_step": "0.004"},
        "ar1": {
            "common_observation_rho": "0.6",
            "differential_log_effect_rho": "0.02",
        },
        "order": {"balanced_order_effect": "0.006"},
        "predecessor": {"balanced_predecessor_effect": "0.006"},
        "skew": {"centered_lognormal_shape": "0.12"},
        "heavy_tail": {"student_t_degrees_of_freedom": "5"},
        "lower_is_better": {"orientation": "positive_is_better"},
        "invalid_rows": {"statuses": "invalid,failed,censored"},
        "caps_quantization": {"relative_quantum": "0.001"},
        "interactions": {
            "reference_client_effect": "0.01",
            "session_effect": "0.008",
            "interaction_effect": "0.006",
        },
        "session_pair_rho_0": {
            "raw_session_paired_log_ratio_sd": _float(RATE_SD_ENVELOPE),
            "cross_session_correlation": "0",
            "superblock_construction": "mean_of_matching_session_rows",
        },
        "session_pair_rho_0_25": {
            "raw_session_paired_log_ratio_sd": _float(RATE_SD_ENVELOPE),
            "cross_session_correlation": "0.25",
            "superblock_construction": "mean_of_matching_session_rows",
        },
        "session_pair_rho_0_50": {
            "raw_session_paired_log_ratio_sd": _float(RATE_SD_ENVELOPE),
            "cross_session_correlation": "0.5",
            "superblock_construction": "mean_of_matching_session_rows",
        },
    }
    return parameters[generator]


def simulate_condition(
    spec: ConditionSpec, *, campaigns: int, seed: str = DEFAULT_SEED
) -> dict[str, Any]:
    """Simulate one named condition; the publication gate enforces 10,000."""

    if campaigns <= 0:
        raise ValueError("campaign count must be positive")
    rng = random.Random(_derived_seed(seed, spec.name))
    if spec.generator == "invalid_rows":
        rejected = 0
        for campaign in range(campaigns):
            rejected += deduplicated_complete_mean(_invalid_rows(campaign)) is None
        return {
            "name": spec.name,
            "generator": spec.generator,
            "campaigns": campaigns,
            "family_size": spec.family_size,
            "parameters": dict(_condition_parameters(spec.generator)),
            "invalid_campaigns_rejected": rejected,
            "passed": rejected == campaigns,
        }

    coverage = 0
    type_i_errors = 0
    false_equivalence = 0
    estimate_sums = [0.0] * spec.family_size
    interaction_sums = {"client": 0.0, "session": 0.0, "client_session": 0.0}
    capped_rejected = 0
    resume_unchanged = 0
    critical_sum = 0.0
    critical_min = math.inf
    critical_max = 0.0
    for _ in range(campaigns):
        if spec.generator == "iid_family":
            vectors = _family_vectors(rng)
        elif spec.generator == "iid_all_pairs":
            vectors = _all_pairs_vectors(rng)
        elif spec.generator == "heteroskedastic":
            vectors = _heteroskedastic_vectors(rng)
        else:
            vectors = (_single_condition_vector(spec.generator, rng),)
        critical, null_intervals = _intervals(vectors)
        critical_sum += critical
        critical_min = min(critical_min, critical)
        critical_max = max(critical_max, critical)
        covered = all(low <= 0.0 <= high for _, low, high in null_intervals)
        coverage += covered
        type_i_errors += not covered
        boundary_intervals = tuple(
            (estimate + RATE_MARGIN, low + RATE_MARGIN, high + RATE_MARGIN)
            for estimate, low, high in null_intervals
        )
        false_equivalence += any(
            low >= -RATE_MARGIN and high <= RATE_MARGIN
            for _, low, high in boundary_intervals
        )
        for index, (estimate, _, _) in enumerate(null_intervals):
            estimate_sums[index] += estimate
        if spec.generator == "interactions":
            response = vectors[0]
            for name, codes in (
                ("client", _CLIENT),
                ("session", _SESSION_CODE),
                ("client_session", _INTERACTION),
            ):
                interaction_sums[name] += sum(
                    code * value
                    for code, value in zip(codes, response, strict=True)
                ) / sum(code * code for code in codes)

        if spec.generator == "caps_quantization":
            capped_rejected += deduplicated_complete_mean(_capped_rows()) is None

        rows = tuple(
            TrialObservation(f"trial-{index:02d}", vectors[0][index])
            for index in range(BLOCKS)
        )
        original = deduplicated_complete_mean(rows)
        replayed = deduplicated_complete_mean(rows + rows)
        resume_unchanged += original == replayed

    coverage_rate = coverage / campaigns
    coverage_low = IID_COVERAGE_LOW if spec.iid_nominal else STRESS_COVERAGE_LOW
    coverage_ok = (
        coverage_low <= coverage_rate <= IID_COVERAGE_HIGH
        if spec.iid_nominal
        else coverage_rate >= coverage_low
    )
    bias = max(abs(total / campaigns) for total in estimate_sums)
    interaction_biases: dict[str, str] = {}
    if spec.generator == "interactions":
        expected = {"client": 0.010, "session": 0.008, "client_session": 0.006}
        numeric_biases = {
            name: interaction_sums[name] / campaigns - coefficient
            for name, coefficient in expected.items()
        }
        bias = max(bias, *(abs(value) for value in numeric_biases.values()))
        interaction_biases = {
            name: _float(value) for name, value in numeric_biases.items()
        }
    passed = (
        coverage_ok
        and type_i_errors / campaigns <= MAX_ERROR_RATE
        and false_equivalence / campaigns <= MAX_ERROR_RATE
        and bias < RATE_MARGIN / 4.0
        and resume_unchanged == campaigns
        and (spec.generator != "caps_quantization" or capped_rejected == campaigns)
    )
    return {
        "name": spec.name,
        "generator": spec.generator,
        "campaigns": campaigns,
        "family_size": spec.family_size,
        "parameters": dict(_condition_parameters(spec.generator)),
        "coverage": {"count": coverage, "rate": _ratio(coverage, campaigns)},
        "familywise_type_i_error": {
            "count": type_i_errors,
            "rate": _ratio(type_i_errors, campaigns),
        },
        "false_equivalence_at_margin": {
            "count": false_equivalence,
            "rate": _ratio(false_equivalence, campaigns),
        },
        "maximum_absolute_bias": _float(bias),
        "interaction_coefficient_biases": interaction_biases,
        "bias_limit": _float(RATE_MARGIN / 4.0),
        "critical_value": {
            "mean": _float(critical_sum / campaigns),
            "minimum": _float(critical_min),
            "maximum": _float(critical_max),
        },
        "capped_campaigns_rejected": capped_rejected,
        "resume_replays_unchanged": resume_unchanged,
        "passed": passed,
    }


def _planning_gate(
    *,
    name: str,
    campaigns: int,
    seed: str,
    margin: float,
    standard_deviation: float,
    declared_effect: float,
    cross_session_correlation: float,
) -> dict[str, Any]:
    gate_label = f"{name}-rho-{format(cross_session_correlation, '.17g')}"
    rng = random.Random(_derived_seed(seed, gate_label))
    equivalence = 0
    declared_power = 0
    doubled_margin_power = 0
    critical_values = []
    for _ in range(campaigns):
        vectors = _correlated_superblock_vectors(
            rng, standard_deviation, cross_session_correlation
        )
        critical = _exact_max_t_critical(vectors)
        critical_values.append(critical)
        estimate_error = sum(vectors[0]) / BLOCKS
        half_width = critical * _sample_standard_error(vectors[0])
        equivalence += (
            estimate_error - half_width >= -margin
            and estimate_error + half_width <= margin
        )
        declared_power += declared_effect + estimate_error - half_width > margin
        doubled_margin_power += 2.0 * margin + estimate_error - half_width > margin
    critical_values.sort()
    exact_95 = critical_values[math.ceil(0.95 * campaigns) - 1]
    result_counts = (equivalence, declared_power, doubled_margin_power)
    lower_bounds = tuple(
        exact_binomial_lower_bound(count, campaigns) for count in result_counts
    )
    passed = all(
        count / campaigns >= MINIMUM_PLANNING_PROBABILITY
        and lower >= MINIMUM_PLANNING_PROBABILITY
        for count, lower in zip(result_counts, lower_bounds, strict=True)
    )
    return {
        "name": name,
        "campaigns": campaigns,
        "blocks": BLOCKS,
        "family_size": PRIMARY_CONTRASTS,
        "raw_rows": RAW_ROWS,
        "margin": _float(margin),
        "raw_session_paired_log_ratio_sd": _float(standard_deviation),
        "cross_session_correlation": _float(cross_session_correlation),
        "superblock_variance_formula": "sigma_squared_times_one_plus_rho_over_two",
        "standard_error": "ordinary_sample_standard_error_across_superblocks",
        "declared_effect": _float(declared_effect),
        "twice_margin_effect": _float(2.0 * margin),
        "equivalence": {
            "count": equivalence,
            "probability": _ratio(equivalence, campaigns),
            "one_sided_95_exact_binomial_lower": _float(lower_bounds[0]),
        },
        "declared_effect_power": {
            "count": declared_power,
            "probability": _ratio(declared_power, campaigns),
            "one_sided_95_exact_binomial_lower": _float(lower_bounds[1]),
        },
        "twice_margin_power": {
            "count": doubled_margin_power,
            "probability": _ratio(doubled_margin_power, campaigns),
            "one_sided_95_exact_binomial_lower": _float(lower_bounds[2]),
        },
        "critical_value_simulation": {
            "minimum": _float(critical_values[0]),
            "mean": _float(sum(critical_values) / campaigns),
            "empirical_95th": _float(exact_95),
            "maximum": _float(critical_values[-1]),
        },
        "passed": passed,
    }


def _legacy_twelve_row_planning_reference(
    *, campaigns: int, seed: str, margin: float, standard_deviation: float,
    declared_effect: float, name: str
) -> dict[str, Any]:
    """Reproduce the superseded single-session design as failure evidence only."""

    rng = random.Random(_derived_seed(seed, f"legacy-12-row-{name}"))
    equivalence = declared_power = 0
    for _ in range(campaigns):
        vectors = _family_vectors(rng, standard_deviation)
        critical = _exact_max_t_critical(vectors)
        error = sum(vectors[0]) / BLOCKS
        half_width = critical * _sample_standard_error(vectors[0])
        equivalence += error - half_width >= -margin and error + half_width <= margin
        declared_power += declared_effect + error - half_width > margin
    return {
        "name": name,
        "raw_rows": BLOCKS,
        "equivalence": {
            "count": equivalence,
            "probability": _ratio(equivalence, campaigns),
        },
        "declared_effect_power": {
            "count": declared_power,
            "probability": _ratio(declared_power, campaigns),
        },
        "expected_to_fail_0_80_gate": True,
        "failure_reproduced": (
            equivalence / campaigns < MINIMUM_PLANNING_PROBABILITY
            and declared_power / campaigns < MINIMUM_PLANNING_PROBABILITY
        ),
    }


def _reference_kernel_validation(seed: str) -> dict[str, Any]:
    rng = random.Random(_derived_seed(seed, "reference-kernel-validation"))
    maximum_delta = 0.0
    campaigns = 16
    family_sizes = (1, 3, PRIMARY_CONTRASTS, ALL_PAIRS_CONTRASTS)
    for campaign in range(campaigns):
        family_size = family_sizes[campaign % len(family_sizes)]
        vectors = tuple(
            tuple(rng.gauss(0.0, RATE_SD_ENVELOPE) for _ in range(BLOCKS))
            for _ in range(family_size)
        )
        fast = _exact_max_t_critical(vectors)
        reference = paired_max_t_intervals(
            {f"contrast-{index}": vector for index, vector in enumerate(vectors)},
            variance_envelope=None,
        ).critical_value
        maximum_delta = max(maximum_delta, abs(fast - reference))
    return {
        "campaigns": campaigns,
        "maximum_absolute_critical_value_delta": _float(maximum_delta),
        "tolerance": "0.000000000001",
        "passed": maximum_delta <= 1e-12,
    }


def run_calibration(
    *, campaigns_per_condition: int = MINIMUM_CAMPAIGNS, seed: str = DEFAULT_SEED
) -> dict[str, Any]:
    """Run the frozen publication calibration and return its artifact object."""

    if campaigns_per_condition < MINIMUM_CAMPAIGNS:
        raise ValueError(
            "publication calibration requires at least "
            f"{MINIMUM_CAMPAIGNS} campaigns per condition"
        )
    reference_validation = _reference_kernel_validation(seed)
    conditions = [
        simulate_condition(spec, campaigns=campaigns_per_condition, seed=seed)
        for spec in CONDITIONS
    ]
    planning = [
        _planning_gate(
            name=f"{metric}_planning_envelope_rho_{rho_label}",
            campaigns=campaigns_per_condition,
            seed=seed,
            margin=margin,
            standard_deviation=standard_deviation,
            declared_effect=declared_effect,
            cross_session_correlation=rho,
        )
        for metric, margin, standard_deviation, declared_effect in (
            ("rate", RATE_MARGIN, RATE_SD_ENVELOPE, math.log(1.06)),
            ("memory", MEMORY_MARGIN, MEMORY_SD_ENVELOPE, math.log(1.10)),
        )
        for rho, rho_label in ((0.0, "0"), (0.25, "0_25"))
    ]
    legacy_planning_failure = [
        _legacy_twelve_row_planning_reference(
            campaigns=campaigns_per_condition,
            seed=seed,
            margin=margin,
            standard_deviation=standard_deviation,
            declared_effect=declared_effect,
            name=f"{metric}_legacy_12_row",
        )
        for metric, margin, standard_deviation, declared_effect in (
            ("rate", RATE_MARGIN, RATE_SD_ENVELOPE, math.log(1.06)),
            ("memory", MEMORY_MARGIN, MEMORY_SD_ENVELOPE, math.log(1.10)),
        )
    ]
    artifact: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "algorithm_version": ALGORITHM_VERSION,
        "seed": seed,
        "campaigns_per_condition": campaigns_per_condition,
        "inference": {
            "alpha": _float(ALPHA),
            "raw_rows": RAW_ROWS,
            "superblocks": BLOCKS,
            "sign_patterns": SIGN_PATTERNS,
            "primary_baseline_contrasts": PRIMARY_CONTRASTS,
            "secondary_all_pairs_contrasts": ALL_PAIRS_CONTRASTS,
            "orientation": "positive_is_better",
            "critical_order_statistic": math.ceil((1.0 - ALPHA) * SIGN_PATTERNS),
        },
        "thresholds": {
            "iid_coverage_minimum": _float(IID_COVERAGE_LOW),
            "iid_coverage_maximum": _float(IID_COVERAGE_HIGH),
            "stress_coverage_minimum": _float(STRESS_COVERAGE_LOW),
            "maximum_familywise_type_i_error": _float(MAX_ERROR_RATE),
            "maximum_false_equivalence": _float(MAX_ERROR_RATE),
            "minimum_equivalence_probability": _float(MINIMUM_PLANNING_PROBABILITY),
            "minimum_power": _float(MINIMUM_PLANNING_PROBABILITY),
            "maximum_bias_fraction_of_margin": "0.25",
        },
        "reference_kernel_validation": reference_validation,
        "legacy_12_row_failure_reference": legacy_planning_failure,
        "conditions": conditions,
        "planning": planning,
        "reproducibility": {
            "same_seed_and_input_reproduce_bit_for_bit": True,
            "serialization": "utf8-json-sort-keys-indent-2-lf",
        },
    }
    artifact["implementation_calibration_passed"] = (
        reference_validation["passed"]
        and all(condition["passed"] for condition in conditions)
    )
    artifact["profile_design_power_gate_passed"] = all(
        gate["passed"] for gate in planning
    )
    artifact["publication_analysis_permitted"] = (
        artifact["implementation_calibration_passed"]
        and artifact["profile_design_power_gate_passed"]
    )
    artifact["passed"] = artifact["publication_analysis_permitted"]
    return artifact


def artifact_bytes(artifact: Mapping[str, Any]) -> bytes:
    """Return the sole stable serialization used for replay comparison."""

    return (
        json.dumps(artifact, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def validate_artifact(artifact: Mapping[str, Any]) -> None:
    """Fail closed on incomplete, stale, or policy-weak calibration output."""

    if artifact.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unexpected statistical-calibration schema version")
    if artifact.get("algorithm_version") != ALGORITHM_VERSION:
        raise ValueError("unexpected statistical-calibration algorithm version")
    if artifact.get("seed") != DEFAULT_SEED:
        raise ValueError("statistical calibration artifact changes the frozen seed")
    campaigns = artifact.get("campaigns_per_condition")
    if not isinstance(campaigns, int) or campaigns < MINIMUM_CAMPAIGNS:
        raise ValueError("calibration artifact has too few campaigns per condition")
    expected_inference = {
        "alpha": _float(ALPHA),
        "raw_rows": RAW_ROWS,
        "superblocks": BLOCKS,
        "sign_patterns": SIGN_PATTERNS,
        "primary_baseline_contrasts": PRIMARY_CONTRASTS,
        "secondary_all_pairs_contrasts": ALL_PAIRS_CONTRASTS,
        "orientation": "positive_is_better",
        "critical_order_statistic": math.ceil((1.0 - ALPHA) * SIGN_PATTERNS),
    }
    expected_thresholds = {
        "iid_coverage_minimum": _float(IID_COVERAGE_LOW),
        "iid_coverage_maximum": _float(IID_COVERAGE_HIGH),
        "stress_coverage_minimum": _float(STRESS_COVERAGE_LOW),
        "maximum_familywise_type_i_error": _float(MAX_ERROR_RATE),
        "maximum_false_equivalence": _float(MAX_ERROR_RATE),
        "minimum_equivalence_probability": _float(MINIMUM_PLANNING_PROBABILITY),
        "minimum_power": _float(MINIMUM_PLANNING_PROBABILITY),
        "maximum_bias_fraction_of_margin": "0.25",
    }
    if artifact.get("inference") != expected_inference:
        raise ValueError("calibration artifact changes the exact inference procedure")
    if artifact.get("thresholds") != expected_thresholds:
        raise ValueError("calibration artifact changes the frozen pass thresholds")
    if artifact.get("reproducibility") != {
        "same_seed_and_input_reproduce_bit_for_bit": True,
        "serialization": "utf8-json-sort-keys-indent-2-lf",
    }:
        raise ValueError("calibration artifact lacks the frozen reproducibility gate")
    conditions = artifact.get("conditions")
    if not isinstance(conditions, list) or tuple(
        item.get("name") for item in conditions if isinstance(item, Mapping)
    ) != CONDITION_NAMES:
        raise ValueError("calibration artifact conditions are incomplete or reordered")
    if any(item.get("campaigns") != campaigns for item in conditions):
        raise ValueError("condition campaign counts do not match the artifact plan")
    for spec, item in zip(CONDITIONS, conditions, strict=True):
        if (
            item.get("family_size") != spec.family_size
            or item.get("generator") != spec.generator
            or item.get("parameters") != dict(_condition_parameters(spec.generator))
        ):
            raise ValueError(f"condition {spec.name!r} changes its frozen design")
        if spec.generator == "invalid_rows":
            condition_passed = item.get("invalid_campaigns_rejected") == campaigns
        else:
            try:
                coverage = item["coverage"]["count"]
                errors = item["familywise_type_i_error"]["count"]
                false_equivalence = item["false_equivalence_at_margin"]["count"]
                bias = float(item["maximum_absolute_bias"])
                bias_limit = float(item["bias_limit"])
                resume = item["resume_replays_unchanged"]
                capped = item["capped_campaigns_rejected"]
                critical = item["critical_value"]
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"condition {spec.name!r} has malformed results") from exc
            if not all(
                isinstance(count, int) and 0 <= count <= campaigns
                for count in (coverage, errors, false_equivalence, resume, capped)
            ):
                raise ValueError(f"condition {spec.name!r} has invalid result counts")
            if errors != campaigns - coverage:
                raise ValueError(f"condition {spec.name!r} has inconsistent coverage counts")
            try:
                critical_minimum = float(critical["minimum"])
                critical_mean = float(critical["mean"])
                critical_maximum = float(critical["maximum"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"condition {spec.name!r} has malformed critical values"
                ) from exc
            if not (
                0.0 <= critical_minimum <= critical_mean <= critical_maximum
                and math.isfinite(critical_maximum)
            ):
                raise ValueError(f"condition {spec.name!r} has invalid critical values")
            rate_fields = (
                (item["coverage"], coverage),
                (item["familywise_type_i_error"], errors),
                (item["false_equivalence_at_margin"], false_equivalence),
            )
            if any(field["rate"] != _ratio(count, campaigns) for field, count in rate_fields):
                raise ValueError(f"condition {spec.name!r} has inconsistent display rates")
            coverage_rate = coverage / campaigns
            coverage_passed = (
                IID_COVERAGE_LOW <= coverage_rate <= IID_COVERAGE_HIGH
                if spec.iid_nominal
                else coverage_rate >= STRESS_COVERAGE_LOW
            )
            condition_passed = (
                coverage_passed
                and errors / campaigns <= MAX_ERROR_RATE
                and false_equivalence / campaigns <= MAX_ERROR_RATE
                and math.isfinite(bias)
                and bias_limit == RATE_MARGIN / 4.0
                and bias < bias_limit
                and resume == campaigns
                and (spec.generator != "caps_quantization" or capped == campaigns)
            )
            coefficient_biases = item.get("interaction_coefficient_biases")
            if spec.generator == "interactions":
                if not isinstance(coefficient_biases, Mapping) or set(
                    coefficient_biases
                ) != {"client", "session", "client_session"}:
                    raise ValueError(
                        "interaction condition omits coefficient-bias calibration"
                    )
                try:
                    numeric_coefficient_biases = tuple(
                        float(value) for value in coefficient_biases.values()
                    )
                except (TypeError, ValueError) as exc:
                    raise ValueError("interaction coefficient biases are malformed") from exc
                condition_passed = condition_passed and all(
                    math.isfinite(value) and abs(value) <= bias
                    for value in numeric_coefficient_biases
                )
            elif coefficient_biases != {}:
                raise ValueError(
                    f"condition {spec.name!r} has unexpected interaction results"
                )
        if item.get("passed") is not condition_passed or not condition_passed:
            raise ValueError(f"condition {spec.name!r} fails its frozen thresholds")
    planning = artifact.get("planning")
    if not isinstance(planning, list) or len(planning) != 4:
        raise ValueError("calibration artifact planning gates are incomplete")
    if any(item.get("campaigns") != campaigns for item in planning):
        raise ValueError("planning campaign counts do not match the artifact plan")
    expected_planning = tuple(
        (
            f"{metric}_planning_envelope_rho_{rho_label}",
            margin,
            standard_deviation,
            effect,
            rho,
        )
        for metric, margin, standard_deviation, effect in (
            ("rate", RATE_MARGIN, RATE_SD_ENVELOPE, math.log(1.06)),
            ("memory", MEMORY_MARGIN, MEMORY_SD_ENVELOPE, math.log(1.10)),
        )
        for rho, rho_label in ((0.0, "0"), (0.25, "0_25"))
    )
    for item, (name, margin, standard_deviation, effect, rho) in zip(
        planning, expected_planning, strict=True
    ):
        if (
            item.get("name") != name
            or item.get("blocks") != BLOCKS
            or item.get("raw_rows") != RAW_ROWS
            or item.get("family_size") != PRIMARY_CONTRASTS
            or item.get("margin") != _float(margin)
            or item.get("raw_session_paired_log_ratio_sd") != _float(standard_deviation)
            or item.get("cross_session_correlation") != _float(rho)
            or item.get("superblock_variance_formula")
            != "sigma_squared_times_one_plus_rho_over_two"
            or item.get("standard_error")
            != "ordinary_sample_standard_error_across_superblocks"
            or item.get("declared_effect") != _float(effect)
            or item.get("twice_margin_effect") != _float(2.0 * margin)
        ):
            raise ValueError(f"planning gate {name!r} changes its frozen design")
        counts = []
        for key in ("equivalence", "declared_effect_power", "twice_margin_power"):
            result = item.get(key)
            if not isinstance(result, Mapping):
                raise ValueError(f"planning gate {name!r} has malformed {key}")
            count = result.get("count")
            if (
                not isinstance(count, int)
                or not 0 <= count <= campaigns
                or result.get("probability") != _ratio(count, campaigns)
            ):
                raise ValueError(f"planning gate {name!r} has invalid {key}")
            try:
                lower = float(result["one_sided_95_exact_binomial_lower"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"planning gate {name!r} lacks an exact binomial lower bound"
                ) from exc
            expected_lower = exact_binomial_lower_bound(count, campaigns)
            if not math.isclose(lower, expected_lower, rel_tol=0.0, abs_tol=5e-17):
                raise ValueError(
                    f"planning gate {name!r} changes its exact binomial lower bound"
                )
            counts.append((count, lower))
        gate_passed = all(
            count / campaigns >= MINIMUM_PLANNING_PROBABILITY
            and lower >= MINIMUM_PLANNING_PROBABILITY
            for count, lower in counts
        )
        try:
            critical = item["critical_value_simulation"]
            critical_minimum = float(critical["minimum"])
            critical_mean = float(critical["mean"])
            critical_95th = float(critical["empirical_95th"])
            critical_maximum = float(critical["maximum"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"planning gate {name!r} has malformed critical values") from exc
        gate_passed = gate_passed and (
            0.0
            <= critical_minimum
            <= critical_mean
            <= critical_95th
            <= critical_maximum
            and math.isfinite(critical_maximum)
        )
        if item.get("passed") is not gate_passed:
            raise ValueError(f"planning gate {name!r} misstates its frozen threshold")
    legacy = artifact.get("legacy_12_row_failure_reference")
    if not isinstance(legacy, list) or len(legacy) != 2:
        raise ValueError("legacy 12-row failure reference is incomplete")
    for item, name in zip(
        legacy, ("rate_legacy_12_row", "memory_legacy_12_row"), strict=True
    ):
        try:
            equivalence = int(item["equivalence"]["count"])
            power = int(item["declared_effect_power"]["count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("legacy 12-row failure reference is malformed") from exc
        if (
            item.get("name") != name
            or item.get("raw_rows") != BLOCKS
            or item.get("expected_to_fail_0_80_gate") is not True
            or item.get("failure_reproduced") is not True
            or item["equivalence"].get("probability")
            != _ratio(equivalence, campaigns)
            or item["declared_effect_power"].get("probability")
            != _ratio(power, campaigns)
            or equivalence / campaigns >= MINIMUM_PLANNING_PROBABILITY
            or power / campaigns >= MINIMUM_PLANNING_PROBABILITY
        ):
            raise ValueError("legacy 12-row planning failure was not reproduced")

    reference = artifact.get("reference_kernel_validation")
    try:
        reference_delta = float(reference["maximum_absolute_critical_value_delta"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("reference-kernel validation is malformed") from exc
    if not (
        reference.get("campaigns") == 16
        and reference.get("tolerance") == "0.000000000001"
        and math.isfinite(reference_delta)
        and reference_delta <= 1e-12
        and reference.get("passed") is True
    ):
        raise ValueError("accelerated exact kernel did not match the reference implementation")
    implementation_passed = all(
        item.get("passed") is True for item in conditions
    )
    profile_design_passed = all(item.get("passed") is True for item in planning)
    publication_permitted = implementation_passed and profile_design_passed
    if artifact.get("implementation_calibration_passed") is not implementation_passed:
        raise ValueError("artifact misstates implementation-calibration status")
    if artifact.get("profile_design_power_gate_passed") is not profile_design_passed:
        raise ValueError("artifact misstates profile-design status")
    if artifact.get("publication_analysis_permitted") is not publication_permitted:
        raise ValueError("artifact misstates publication-analysis permission")
    if artifact.get("passed") is not publication_permitted:
        raise ValueError("artifact misstates its aggregate calibration status")


def require_publication_ready(artifact: Mapping[str, Any]) -> None:
    validate_artifact(artifact)
    if artifact["publication_analysis_permitted"] is not True:
        raise ValueError(
            "statistical calibration blocks publication analysis: "
            "the frozen profile design misses its power gate"
        )


def frozen_analysis_calibration(
    artifact: Mapping[str, Any], artifact_sha256: str, planning_name: str
) -> dict[str, Any]:
    """Return the exact simulation evidence frozen into an analysis plan."""

    validate_artifact(artifact)
    if len(artifact_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in artifact_sha256
    ):
        raise ValueError("calibration artifact SHA-256 is malformed")
    planning = {
        str(item["name"]): item for item in artifact["planning"]
    }
    try:
        independence = planning[f"{planning_name}_rho_0"]
        selected = planning[f"{planning_name}_rho_0_25"]
    except KeyError as exc:
        raise ValueError(
            f"calibration artifact omits paired planning results for {planning_name!r}"
        ) from exc
    return {
        "artifact_sha256": artifact_sha256,
        "algorithm_version": artifact["algorithm_version"],
        "campaigns_per_condition": artifact["campaigns_per_condition"],
        "implementation_calibration_passed": artifact[
            "implementation_calibration_passed"
        ],
        "profile_design_power_gate_passed": artifact[
            "profile_design_power_gate_passed"
        ],
        "publication_analysis_permitted": artifact[
            "publication_analysis_permitted"
        ],
        "independence_planning_result": independence,
        "planning_result": selected,
    }


def load_artifact(path: str | Path) -> dict[str, Any]:
    try:
        artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load statistical calibration artifact: {exc}") from exc
    if not isinstance(artifact, dict):
        raise ValueError("statistical calibration artifact must be an object")
    validate_artifact(artifact)
    return artifact


def write_artifact(path: str | Path, artifact: Mapping[str, Any]) -> None:
    validate_artifact(artifact)
    Path(path).write_bytes(artifact_bytes(artifact))


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaigns", type=int, default=MINIMUM_CAMPAIGNS)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    artifact = run_calibration(
        campaigns_per_condition=args.campaigns,
        seed=args.seed,
    )
    payload = artifact_bytes(artifact)
    if args.output is None:
        print(payload.decode("utf-8"), end="")
    else:
        args.output.write_bytes(payload)
    return 0 if artifact["publication_analysis_permitted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
