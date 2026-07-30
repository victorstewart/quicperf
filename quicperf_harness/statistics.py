"""Deterministic paired inference and sensitivity analysis for harness v2."""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass
from statistics import NormalDist
from typing import Mapping, Sequence


RATE_MARGIN = math.log(1.03)
MEMORY_MARGIN = math.log(1.05)
RATE_SD_ENVELOPE = 0.025
MEMORY_SD_ENVELOPE = 0.040
PLANNING_CROSS_SESSION_CORRELATION = 0.25
RAW_SESSION_ROWS = 24
SUPERBLOCKS = 12
SIGN_PERMUTATIONS = 1 << 12


def superblock_sd_envelope(
    raw_session_sd: float, correlation: float = PLANNING_CROSS_SESSION_CORRELATION
) -> float:
    """Return the SD of a two-session mean at the frozen raw-row envelope."""

    if not math.isfinite(raw_session_sd) or raw_session_sd <= 0.0:
        raise ValueError("raw session SD must be finite and positive")
    if not math.isfinite(correlation) or not -1.0 <= correlation <= 1.0:
        raise ValueError("cross-session correlation must be in [-1, 1]")
    return raw_session_sd * math.sqrt((1.0 + correlation) / 2.0)


RATE_SUPERBLOCK_SD_ENVELOPE = superblock_sd_envelope(RATE_SD_ENVELOPE)
MEMORY_SUPERBLOCK_SD_ENVELOPE = superblock_sd_envelope(MEMORY_SD_ENVELOPE)


def pair_session_superblocks(
    raw_log_contrasts: Sequence[float],
    sessions: Sequence[int],
    williams_rows: Sequence[int],
) -> tuple[float, ...]:
    """Average matching session rows into the 12 predeclared superblocks."""

    if not (
        len(raw_log_contrasts)
        == len(sessions)
        == len(williams_rows)
        == RAW_SESSION_ROWS
    ):
        raise ValueError("superblock construction requires exactly 24 raw rows")
    paired: dict[int, dict[int, float]] = {}
    for value, session, row in zip(
        raw_log_contrasts, sessions, williams_rows, strict=True
    ):
        if not math.isfinite(value):
            raise ValueError("raw log contrasts must be finite")
        if session not in {1, 2} or not 0 <= row < SUPERBLOCKS:
            raise ValueError("invalid session or Williams-row coordinate")
        by_session = paired.setdefault(row, {})
        if session in by_session:
            raise ValueError("duplicate session member in a paired superblock")
        by_session[session] = float(value)
    if set(paired) != set(range(SUPERBLOCKS)) or any(
        set(by_session) != {1, 2} for by_session in paired.values()
    ):
        raise ValueError("every Williams row requires both session members")
    return tuple(
        (paired[row][1] + paired[row][2]) / 2.0 for row in range(SUPERBLOCKS)
    )


def geometric_mean(values: Sequence[float]) -> float:
    if not values or any(not math.isfinite(value) or value <= 0.0 for value in values):
        raise ValueError("geometric mean requires finite positive values")
    return math.exp(sum(math.log(value) for value in values) / len(values))


def paired_log_differences(
    first: Sequence[float],
    second: Sequence[float],
    *,
    higher_is_better: bool,
) -> tuple[float, ...]:
    """Return paired log effects oriented so a positive value favors first."""

    if len(first) != len(second):
        raise ValueError("paired vectors must have the same length")
    if not first:
        raise ValueError("paired vectors must not be empty")
    if any(
        not math.isfinite(value) or value <= 0.0
        for value in itertools.chain(first, second)
    ):
        raise ValueError("log contrasts require finite positive observations")
    if higher_is_better:
        return tuple(math.log(a / b) for a, b in zip(first, second, strict=True))
    return tuple(math.log(b / a) for a, b in zip(first, second, strict=True))


def paired_server_contrasts(
    values: Mapping[str, Sequence[float]],
    *,
    higher_is_better: bool,
    baseline: str | None = None,
) -> dict[str, tuple[float, ...]]:
    """Build all-pairs, or every-server-versus-baseline, paired contrasts."""

    servers = sorted(values)
    if baseline is not None and baseline not in values:
        raise ValueError(f"unknown baseline {baseline!r}")
    pairs = (
        ((server, baseline) for server in servers if server != baseline)
        if baseline is not None
        else itertools.combinations(servers, 2)
    )
    return {
        f"{first}/{second}": paired_log_differences(
            values[first], values[second], higher_is_better=higher_is_better
        )
        for first, second in pairs
    }


def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values)


def _sample_se(values: Sequence[float]) -> float:
    if len(values) < 2:
        raise ValueError("studentized inference requires at least two observations")
    center = _mean(values)
    return math.sqrt(
        sum((value - center) ** 2 for value in values) / (len(values) - 1) / len(values)
    )


def _studentized_mean(values: Sequence[float]) -> float:
    numerator = _mean(values)
    denominator = _sample_se(values)
    if denominator == 0.0:
        return 0.0 if numerator == 0.0 else math.copysign(math.inf, numerator)
    return numerator / denominator


def _common_signs(count: int) -> tuple[tuple[float, ...], ...]:
    if count != 12:
        raise ValueError("publication inference requires exactly 12 paired blocks")
    return tuple(
        tuple(1.0 if bits & (1 << index) else -1.0 for index in range(count))
        for bits in range(1 << count)
    )


def conservative_order_statistic(values: Sequence[float], probability: float) -> float:
    """Return the upper conservative empirical quantile order statistic."""

    if not values:
        raise ValueError("quantile requires observations")
    if not 0.0 < probability <= 1.0:
        raise ValueError("probability must be in (0, 1]")
    ordered = sorted(values)
    return ordered[math.ceil(probability * len(ordered)) - 1]


def classify_practical_interval(
    low_log_effect: float,
    high_log_effect: float,
    *,
    margin: float = RATE_MARGIN,
) -> str:
    if low_log_effect > high_log_effect:
        raise ValueError("interval bounds are reversed")
    if margin <= 0.0 or not math.isfinite(margin):
        raise ValueError("margin must be finite and positive")
    if low_log_effect > margin:
        return "superior"
    if high_log_effect < -margin:
        return "inferior"
    if low_log_effect >= -margin and high_log_effect <= margin:
        return "equivalent"
    return "inconclusive"


def _exp_bound(value: float) -> float:
    if value == -math.inf:
        return 0.0
    if value == math.inf:
        return math.inf
    try:
        return math.exp(value)
    except OverflowError:
        return math.inf


@dataclass(frozen=True)
class SimultaneousInterval:
    contrast: str
    mean_log_effect: float
    sample_standard_deviation: float
    standard_error: float
    low_log_effect: float
    high_log_effect: float
    point_ratio: float
    low_ratio: float
    high_ratio: float
    variance_envelope: float | None
    variance_miss: bool
    classification: str


@dataclass(frozen=True)
class MaxTResult:
    alpha: float
    permutations: int
    critical_value: float
    margin: float
    intervals: tuple[SimultaneousInterval, ...]


def paired_max_t_intervals(
    contrasts: Mapping[str, Sequence[float]],
    *,
    alpha: float = 0.05,
    margin: float = RATE_MARGIN,
    variance_envelope: float | None = RATE_SUPERBLOCK_SD_ENVELOPE,
) -> MaxTResult:
    """Enumerate the exact 4096 common-sign studentized max-absolute-t null."""

    if not contrasts:
        raise ValueError("at least one contrast is required")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")
    if variance_envelope is not None and (
        variance_envelope <= 0.0 or not math.isfinite(variance_envelope)
    ):
        raise ValueError("variance_envelope must be finite and positive")
    names = sorted(contrasts)
    vectors = {name: tuple(float(value) for value in contrasts[name]) for name in names}
    if any(len(vector) != 12 for vector in vectors.values()):
        raise ValueError("every paired contrast must contain exactly 12 observations")
    if any(not math.isfinite(value) for vector in vectors.values() for value in vector):
        raise ValueError("paired contrasts must be finite")

    means = {name: _mean(vector) for name, vector in vectors.items()}
    centered = {
        name: tuple(value - means[name] for value in vector)
        for name, vector in vectors.items()
    }
    max_statistics: list[float] = []
    for signs in _common_signs(12):
        maximum = 0.0
        for name in names:
            signed = tuple(
                sign * value for sign, value in zip(signs, centered[name], strict=True)
            )
            maximum = max(maximum, abs(_studentized_mean(signed)))
        max_statistics.append(maximum)
    critical = conservative_order_statistic(max_statistics, 1.0 - alpha)

    intervals: list[SimultaneousInterval] = []
    for name in names:
        sample_standard_deviation = _sample_stdev(vectors[name])
        standard_error = _sample_se(vectors[name])
        half_width = 0.0 if standard_error == 0.0 else critical * standard_error
        low = means[name] - half_width
        high = means[name] + half_width
        variance_miss = (
            variance_envelope is not None
            and sample_standard_deviation > variance_envelope
        )
        intervals.append(
            SimultaneousInterval(
                contrast=name,
                mean_log_effect=means[name],
                sample_standard_deviation=sample_standard_deviation,
                standard_error=standard_error,
                low_log_effect=low,
                high_log_effect=high,
                point_ratio=_exp_bound(means[name]),
                low_ratio=_exp_bound(low),
                high_ratio=_exp_bound(high),
                variance_envelope=variance_envelope,
                variance_miss=variance_miss,
                classification=(
                    "inconclusive"
                    if variance_miss
                    else classify_practical_interval(low, high, margin=margin)
                ),
            )
        )
    return MaxTResult(alpha, SIGN_PERMUTATIONS, critical, margin, tuple(intervals))


def _sample_stdev(values: Sequence[float]) -> float:
    center = _mean(values)
    return math.sqrt(
        sum((value - center) ** 2 for value in values) / (len(values) - 1)
    )


def _transpose(matrix: Sequence[Sequence[float]]) -> list[list[float]]:
    return [list(column) for column in zip(*matrix, strict=True)]


def _matmul(
    left: Sequence[Sequence[float]], right: Sequence[Sequence[float]]
) -> list[list[float]]:
    right_t = _transpose(right)
    return [
        [sum(a * b for a, b in zip(row, column, strict=True)) for column in right_t]
        for row in left
    ]


def _inverse(matrix: Sequence[Sequence[float]]) -> list[list[float]]:
    size = len(matrix)
    if size == 0 or any(len(row) != size for row in matrix):
        raise ValueError("inverse requires a nonempty square matrix")
    augmented = [
        [float(value) for value in row]
        + [1.0 if row_index == column else 0.0 for column in range(size)]
        for row_index, row in enumerate(matrix)
    ]
    for column in range(size):
        pivot = max(range(column, size), key=lambda row: abs(augmented[row][column]))
        if abs(augmented[pivot][column]) <= 1e-14:
            raise ValueError("sensitivity design matrix is singular")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        scale = augmented[column][column]
        augmented[column] = [value / scale for value in augmented[column]]
        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                value - factor * pivot_value
                for value, pivot_value in zip(
                    augmented[row], augmented[column], strict=True
                )
            ]
    return [row[size:] for row in augmented]


@dataclass(frozen=True)
class _OlsFit:
    coefficients: tuple[float, ...]
    standard_errors: tuple[float, ...]
    fitted: tuple[float, ...]
    residuals: tuple[float, ...]
    leverages: tuple[float, ...]


@dataclass(frozen=True)
class _OlsDesign:
    rows: tuple[tuple[float, ...], ...]
    projection: tuple[tuple[float, ...], ...]
    leverages: tuple[float, ...]


def _prepare_ols_design(design: Sequence[Sequence[float]]) -> _OlsDesign:
    if not design:
        raise ValueError("design must not be empty")
    x = [list(map(float, row)) for row in design]
    if not x[0] or any(len(row) != len(x[0]) for row in x):
        raise ValueError("design rows must have one nonzero common width")
    xt = _transpose(x)
    xtx_inv = _inverse(_matmul(xt, x))
    projection = _matmul(xtx_inv, xt)
    leverages = tuple(
        sum(
            row[column] * projection[column][row_index]
            for column in range(len(row))
        )
        for row_index, row in enumerate(x)
    )
    if any(leverage >= 1.0 - 1e-12 or leverage < -1e-12 for leverage in leverages):
        raise ValueError("invalid sensitivity leverage")
    return _OlsDesign(
        tuple(tuple(row) for row in x),
        tuple(tuple(row) for row in projection),
        leverages,
    )


def _ols_hc2_prepared(
    design: _OlsDesign, response: Sequence[float]
) -> _OlsFit:
    if len(design.rows) != len(response):
        raise ValueError("design and response cardinalities must match")
    x = design.rows
    beta = tuple(
        sum(weight * y for weight, y in zip(row, response, strict=True))
        for row in design.projection
    )
    fitted = tuple(
        sum(
            value * coefficient
            for value, coefficient in zip(row, beta, strict=True)
        )
        for row in x
    )
    residuals = tuple(y - prediction for y, prediction in zip(response, fitted, strict=True))
    adjusted_squares = tuple(
        residual * residual / (1.0 - leverage)
        for residual, leverage in zip(
            residuals, design.leverages, strict=True
        )
    )
    standard_errors = tuple(
        math.sqrt(
            max(
                0.0,
                sum(
                    adjusted_square * weight * weight
                    for adjusted_square, weight in zip(
                        adjusted_squares, projection_row, strict=True
                    )
                ),
            )
        )
        for projection_row in design.projection
    )
    return _OlsFit(beta, standard_errors, fitted, residuals, design.leverages)


def _ols_hc2(design: Sequence[Sequence[float]], response: Sequence[float]) -> _OlsFit:
    if len(design) != len(response):
        raise ValueError("design and response cardinalities must match")
    return _ols_hc2_prepared(_prepare_ols_design(design), response)


def _effect_sensitivity(low: float, high: float, margin: float) -> str:
    if low >= -margin and high <= margin:
        return "invariance_supported"
    if low > margin or high < -margin:
        return "sensitive"
    return "unresolved"


@dataclass(frozen=True)
class SensitivityInterval:
    contrast: str
    effect: str
    estimate: float
    standard_error: float
    low: float
    high: float
    status: str


@dataclass(frozen=True)
class SensitivityResult:
    alpha: float
    permutations: int
    critical_value: float
    margin: float
    intervals: tuple[SensitivityInterval, ...]


def hc2_wild_max_t_sensitivity(
    contrasts: Mapping[str, Sequence[float]],
    client_codes: Sequence[float],
    session_codes: Sequence[float],
    cluster_ids: Sequence[int],
    *,
    alpha: float = 0.05,
    margin: float = RATE_MARGIN,
) -> SensitivityResult:
    """HC2 OLS sensitivity with a common-sign exact wild max-t family."""

    if not contrasts:
        raise ValueError("at least one contrast is required")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")
    if not (
        len(client_codes)
        == len(session_codes)
        == len(cluster_ids)
        == RAW_SESSION_ROWS
    ):
        raise ValueError("sensitivity analysis requires exactly 24 raw rows")
    if set(client_codes) - {-0.5, 0.5} or set(session_codes) - {-0.5, 0.5}:
        raise ValueError("client and session codes must be -0.5 or 0.5")
    clusters = sorted(set(cluster_ids))
    if len(clusters) != SUPERBLOCKS or any(
        sum(cluster == item for item in cluster_ids) != 2 for cluster in clusters
    ):
        raise ValueError("sensitivity analysis requires 12 two-row clusters")
    cluster_index = {cluster: index for index, cluster in enumerate(clusters)}
    design = [
        [1.0, client, session, client * session]
        for client, session in zip(client_codes, session_codes, strict=True)
    ]
    prepared_design = _prepare_ols_design(design)
    names = sorted(contrasts)
    fits: dict[str, _OlsFit] = {}
    for name in names:
        response = tuple(float(value) for value in contrasts[name])
        if len(response) != RAW_SESSION_ROWS or any(
            not math.isfinite(value) for value in response
        ):
            raise ValueError("every sensitivity contrast must contain 24 finite values")
        fits[name] = _ols_hc2_prepared(prepared_design, response)
    adjusted_residuals = {
        name: tuple(
            residual / math.sqrt(1.0 - leverage)
            for residual, leverage in zip(
                fit.residuals, fit.leverages, strict=True
            )
        )
        for name, fit in fits.items()
    }

    max_statistics: list[float] = []
    for cluster_signs in _common_signs(SUPERBLOCKS):
        signs = tuple(
            cluster_signs[cluster_index[cluster]] for cluster in cluster_ids
        )
        maximum = 0.0
        for name in names:
            fit = fits[name]
            wild_response = tuple(
                fitted + sign * residual
                for fitted, sign, residual in zip(
                    fit.fitted, signs, adjusted_residuals[name], strict=True
                )
            )
            wild_fit = _ols_hc2_prepared(prepared_design, wild_response)
            for coefficient_index in (1, 2):
                delta = (
                    wild_fit.coefficients[coefficient_index]
                    - fit.coefficients[coefficient_index]
                )
                standard_error = wild_fit.standard_errors[coefficient_index]
                statistic = (
                    0.0
                    if standard_error == 0.0 and delta == 0.0
                    else math.inf
                    if standard_error == 0.0
                    else abs(delta / standard_error)
                )
                maximum = max(maximum, statistic)
        max_statistics.append(maximum)
    critical = conservative_order_statistic(max_statistics, 1.0 - alpha)

    intervals: list[SensitivityInterval] = []
    for name in names:
        fit = fits[name]
        for effect, index in (("client", 1), ("session", 2)):
            estimate = fit.coefficients[index]
            standard_error = fit.standard_errors[index]
            half_width = 0.0 if standard_error == 0.0 else critical * standard_error
            low, high = estimate - half_width, estimate + half_width
            status = _effect_sensitivity(low, high, margin)
            if status == "sensitive":
                status = (
                    "reference_client_sensitive" if effect == "client" else "session_sensitive"
                )
            elif status == "unresolved":
                status = "sensitivity_unresolved"
            intervals.append(
                SensitivityInterval(
                    contrast=name,
                    effect=effect,
                    estimate=estimate,
                    standard_error=standard_error,
                    low=low,
                    high=high,
                    status=status,
                )
            )
    return SensitivityResult(alpha, SIGN_PERMUTATIONS, critical, margin, tuple(intervals))


def nearest_rank(values: Sequence[float], probability: float) -> float:
    if not values:
        raise ValueError("nearest-rank quantile requires observations")
    if not 0.0 < probability <= 1.0:
        raise ValueError("probability must be in (0, 1]")
    if any(not math.isfinite(value) for value in values):
        raise ValueError("nearest-rank observations must be finite")
    ordered = sorted(values)
    return ordered[math.ceil(probability * len(ordered)) - 1]


def tail_block_p99(
    operations: Sequence[tuple[int, int, float]], *, block_size: int = 1024
) -> float:
    """Compute p99 from the first complete start-time/sequence ordered tail block."""

    if block_size != 1024:
        raise ValueError("the v2 tail block size is fixed at 1024")
    if len(operations) < block_size:
        raise ValueError("insufficient completed operations for a tail block")
    block = sorted(operations, key=lambda item: (item[0], item[1]))[:block_size]
    latencies = [float(item[2]) for item in block]
    if any(not math.isfinite(value) or value < 0.0 for value in latencies):
        raise ValueError("tail latencies must be finite and nonnegative")
    return nearest_rank(latencies, 0.99)


def wilson_upper_bound(successes: int, trials: int, *, alpha: float = 0.05) -> float:
    if (
        not isinstance(successes, int)
        or isinstance(successes, bool)
        or not isinstance(trials, int)
        or isinstance(trials, bool)
        or trials <= 0
        or not 0 <= successes <= trials
    ):
        raise ValueError("Wilson inputs require 0 <= successes <= positive trials")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")
    z = 1.6448536269514722 if alpha == 0.05 else NormalDist().inv_cdf(1.0 - alpha)
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    center = proportion + z * z / (2.0 * trials)
    radius = z * math.sqrt(
        proportion * (1.0 - proportion) / trials + z * z / (4.0 * trials * trials)
    )
    return (center + radius) / denominator


@dataclass(frozen=True)
class PlanningProbabilities:
    effect: float
    standard_deviation: float
    pairs: int
    critical_value: float
    margin: float
    equivalence_probability: float
    directional_detection_probability: float


def normal_planning_probabilities(
    *,
    effect: float,
    standard_deviation: float,
    pairs: int = 12,
    critical_value: float,
    margin: float = RATE_MARGIN,
) -> PlanningProbabilities:
    """Closed-form planning probabilities for a frozen simultaneous critical value."""

    if not math.isfinite(effect):
        raise ValueError("effect must be finite")
    if standard_deviation <= 0.0 or not math.isfinite(standard_deviation):
        raise ValueError("standard_deviation must be finite and positive")
    if (
        pairs <= 1
        or critical_value < 0.0
        or not math.isfinite(critical_value)
        or margin <= 0.0
        or not math.isfinite(margin)
    ):
        raise ValueError("invalid planning inputs")
    standard_error = standard_deviation / math.sqrt(pairs)
    normal = NormalDist(mu=effect, sigma=standard_error)
    low_equivalence = -margin + critical_value * standard_error
    high_equivalence = margin - critical_value * standard_error
    equivalence_probability = (
        0.0
        if low_equivalence > high_equivalence
        else normal.cdf(high_equivalence) - normal.cdf(low_equivalence)
    )
    if effect >= 0.0:
        directional = 1.0 - normal.cdf(margin + critical_value * standard_error)
    else:
        directional = normal.cdf(-margin - critical_value * standard_error)
    return PlanningProbabilities(
        effect=effect,
        standard_deviation=standard_deviation,
        pairs=pairs,
        critical_value=critical_value,
        margin=margin,
        equivalence_probability=equivalence_probability,
        directional_detection_probability=directional,
    )
