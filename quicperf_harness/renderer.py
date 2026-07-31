"""Deterministic, cardinality-preserving v2 analysis and report rendering."""

from __future__ import annotations

import csv
import io
import json
import math
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Sequence

from .capacity import (
    CapacityPoint,
    NeighborInterval,
    confirm_nomination,
    neighbor_loads,
    nominate_capacity,
)
from .capability_matrix import canonical_matrix
from .canonical import canonical_bytes
from .journal import Journal
from .memory import MEMORY_N_VALUES, MemoryPoint, fit_memory_curve
from .statistics import (
    MEMORY_MARGIN,
    MEMORY_SUPERBLOCK_SD_ENVELOPE,
    hc2_wild_max_t_sensitivity,
    pair_session_superblocks,
    paired_log_differences,
    paired_max_t_intervals,
    paired_server_contrasts,
    tail_block_p99,
    wilson_upper_bound,
)
from .validity import assess_row_resolution


class RenderError(ValueError):
    pass


@dataclass(frozen=True)
class RenderedAnalysis:
    artifacts: Mapping[str, bytes]
    complete: bool
    publication_valid: bool
    reasons: tuple[str, ...]


def _tsv(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
    writer.writerow(headers)
    for row in rows:
        writer.writerow(["" if value is None else value for value in row])
    return stream.getvalue().encode("utf-8")


def _load_rows(journal: Journal, campaign_id: str) -> list[dict[str, Any]]:
    rows = journal.connection.execute(
        """
        SELECT p.logical_trial_id, p.trial_id AS planned_trial_id,
               p.state AS planned_trial_state,
               p.cell_id, p.ordinal AS trial_ordinal,
               pm.session_number, pm.microblock_id AS planned_microblock_id,
               pm.status AS planned_microblock_status,
               pm.phase AS planned_phase, pm.branch_candidate,
               pm.superblock_id, pm.williams_row,
               c.canonical_config,
               s.trial_id AS committed_trial_id, s.attempt_id, s.sample_json,
               cm.microblock_id AS committed_microblock_id,
               pa.attempt_id AS planned_attempt_id,
               pa.termination_reason AS planned_termination_reason
        FROM trial p JOIN microblock pm USING(microblock_id)
        JOIN cell c ON c.campaign_id=p.campaign_id AND c.cell_id=p.cell_id
        LEFT JOIN committed_sample s ON s.logical_trial_id=p.logical_trial_id
        LEFT JOIN trial ct ON ct.trial_id=s.trial_id
        LEFT JOIN microblock cm ON cm.microblock_id=ct.microblock_id
        LEFT JOIN attempt pa ON pa.trial_id=p.trial_id
        WHERE p.campaign_id=? AND pm.slot='primary' AND p.warmup=0
          AND pm.phase!='parallel_balance_control'
        ORDER BY pm.session_number, pm.ordinal, p.ordinal, p.trial_id
        """,
        (campaign_id,),
    ).fetchall()
    result = []
    for row in rows:
        value = dict(row)
        value["config"] = json.loads(value.pop("canonical_config"))
        value["sample"] = json.loads(value.pop("sample_json")) if value["sample_json"] is not None else None
        result.append(value)
    return result


def _family(config: Mapping[str, Any], sample: Mapping[str, Any]) -> tuple[str, ...]:
    metric = sample["metric"]
    return (
        str(config["estimand"]),
        str(config["scenario"]),
        str(config["path_profile"]),
        str(metric["name"]),
        str(config["server_backend"]),
    )


def _quality(rows: Sequence[Mapping[str, Any]]) -> tuple[bytes, bool, list[str]]:
    reasons: list[str] = []
    output = []
    complete = True
    for row in rows:
        sample = row["sample"]
        status = "planned_but_missing"
        validity = ""
        if sample is not None:
            status = str(sample.get("completion_status", "invalid"))
            validity = ",".join(sample.get("validity_reasons", ()))
        elif row["planned_microblock_status"] == "not_selected":
            status = "not_selected"
        elif row["planned_trial_state"] in {"unsupported", "invalid", "failed", "cancelled"}:
            status = str(row["planned_trial_state"])
        else:
            complete = False
            reasons.append("planned_but_missing")
        if status not in {"valid", "not_selected"}:
            reasons.append(status)
        output.append(
            (
                row["logical_trial_id"],
                row["planned_trial_id"],
                row["committed_trial_id"],
                row["session_number"],
                row["planned_microblock_id"],
                row["cell_id"],
                row["config"]["server"],
                row["config"]["reference_client"],
                row["config"]["server_backend"],
                row["config"]["scenario"],
                row["config"]["path_profile"],
                status,
                validity,
            )
        )
    return _tsv(
        (
            "logical_trial_id", "planned_trial_id", "committed_trial_id", "session",
            "planned_microblock_id", "cell_id", "server", "reference_client",
            "server_backend", "scenario", "path_profile", "outcome", "validity_reasons",
        ),
        output,
    ), complete, reasons


def _row_results(rows: Sequence[Mapping[str, Any]]) -> tuple[bytes, list[str]]:
    grouped: dict[tuple[str, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        config = row["config"]
        key = (
            str(config["estimand"]), str(config["server"]), str(config["server_backend"]),
            str(config["scenario"]), str(config["path_profile"]),
            str(config.get("phase", "confirmatory")),
            str(config.get("concurrency", config.get("connections", ""))),
        )
        grouped[key].append(row)
    output = []
    reasons: list[str] = []
    for key in sorted(grouped):
        members = grouped[key]
        selected_members = [member for member in members if member["planned_microblock_status"] != "not_selected"]
        samples = [member["sample"] for member in members if member["sample"] is not None]
        valid = [sample for sample in samples if sample["completion_status"] == "valid"]
        metric_names = sorted({sample["metric"]["name"] for sample in valid})
        metric_name = metric_names[0] if len(metric_names) == 1 else ""
        numerators = [int(sample["metric"]["numerator"]) for sample in valid]
        values = [float(sample["metric"]["derived_decimal"]) for sample in valid]
        status = "complete" if len(valid) == len(selected_members) else "incomplete_or_invalid"
        labels: tuple[str, ...] = ()
        if numerators and values:
            resolution = assess_row_resolution(
                numerators,
                interval_low=min(values),
                interval_high=max(values),
            )
            labels = resolution.labels
            if labels:
                status = "nonpublishable"
                reasons.extend(labels)
        elif not values:
            reasons.append("no_valid_samples")
        geometric = ""
        if values and all(value > 0.0 and math.isfinite(value) for value in values):
            geometric = format(math.exp(sum(math.log(value) for value in values) / len(values)), ".17g")
        output.append((*key, metric_name, len(selected_members), len(samples), len(valid), geometric, status, ",".join(labels)))
    return _tsv(
        (
            "estimand", "server", "server_backend", "scenario", "path_profile",
            "phase", "load", "metric",
            "planned", "committed", "valid", "geometric_mean", "status", "quality_labels",
        ),
        output,
    ), reasons


def _cleanup_artifact(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[bytes, list[str]]:
    labels = ("fin", "reset_stream", "stop_sending", "connection_close")
    output: list[tuple[Any, ...]] = []
    reasons: list[str] = []
    for row in rows:
        config = row["config"]
        if config["scenario"] != "close_reset_cleanup":
            continue
        sample = row["sample"]
        values: list[Any] = [
            config["server"], config["server_backend"], config["reference_client"],
            row["session_number"], row["planned_microblock_id"],
            row["committed_trial_id"] or row["planned_trial_id"],
        ]
        status = "planned_but_missing"
        if sample is None:
            values.extend([""] * 9)
        else:
            status = str(sample.get("completion_status", "invalid"))
            try:
                cleanup = sample["cleanup"]
                strata = cleanup["strata"]
                counts = [int(strata[label]["completed"]) for label in labels]
                rates = [
                    str(strata[label]["operations_per_second_decimal"])
                    for label in labels
                ]
                aggregate = str(
                    cleanup[
                        "aggregate_geometric_mean_operations_per_second_decimal"
                    ]
                )
                valid = (
                    set(strata) == set(labels)
                    and min(counts) >= 100
                    and sum(counts) == int(sample["metric"]["numerator"])
                    and sample["metric"]["name"]
                    == "cleanup_geometric_mean_operations_per_second"
                    and aggregate == str(sample["metric"]["derived_decimal"])
                )
            except (KeyError, TypeError, ValueError):
                counts, rates, aggregate, valid = [""] * 4, [""] * 4, "", False
            if not valid:
                status = "invalid_cleanup_evidence"
                reasons.append("invalid_cleanup_evidence")
            values.extend(
                value
                for count, rate in zip(counts, rates, strict=True)
                for value in (count, rate)
            )
            values.append(aggregate)
        output.append((*values, status))
    return _tsv(
        (
            "server", "server_backend", "reference_client", "session",
            "microblock_id", "trial_id", "fin_completed", "fin_rate",
            "reset_stream_completed", "reset_stream_rate",
            "stop_sending_completed", "stop_sending_rate",
            "connection_close_completed", "connection_close_rate",
            "aggregate_geometric_mean_rate", "status",
        ),
        output,
    ), reasons


_COMPARISON_HEADERS = (
    "family", "comparison_family", "contrast", "point_ratio", "low_ratio", "high_ratio",
    "classification", "critical_value", "sample_sd", "variance_miss",
    "client_sensitivity", "session_sensitivity",
)


def _valid_metric(row: Mapping[str, Any]) -> float | None:
    sample = row["sample"]
    if sample is None or sample.get("completion_status") != "valid":
        return None
    try:
        value = float(sample["metric"]["derived_decimal"])
    except (KeyError, TypeError, ValueError):
        return None
    return value if math.isfinite(value) and value > 0.0 else None


def _capacity_artifacts(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[bytes, bytes, list[str]]:
    """Render frozen search, held-out nomination checks, and server contrasts."""

    search: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    confirmation: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    output: list[tuple[Any, ...]] = []
    reasons: list[str] = []
    for row in rows:
        config = row["config"]
        key = (str(config["server"]), str(config["server_backend"]), str(config["scenario"]))
        if config.get("phase") == "exploratory":
            search[key].append(row)
        elif row["planned_microblock_status"] != "not_selected":
            confirmation[key].append(row)

    nominations: dict[tuple[str, str, str], int | None] = {}
    for key in sorted(search):
        points = []
        for row in search[key]:
            config = row["config"]
            value = _valid_metric(row)
            sample = row["sample"]
            headroom = bool(
                sample is not None
                and float(sample.get("telemetry", {}).get("client_cpu_p95_decimal", "inf")) < 0.8
            )
            points.append(
                CapacityPoint(
                    concurrency=int(config["concurrency"]),
                    reference_client=str(config["reference_client"]),
                    rate=value,
                    valid=value is not None,
                    client_headroom_valid=headroom,
                )
            )
        try:
            nomination = nominate_capacity(points)
        except ValueError:
            nomination = None
        candidate = nomination.candidate if nomination is not None else None
        nominations[key] = candidate
        if candidate is None:
            reasons.append("capacity_nomination_inconclusive")
        for row in sorted(
            search[key],
            key=lambda item: (
                int(item["config"]["concurrency"]),
                str(item["config"]["reference_client"]),
            ),
        ):
            config = row["config"]
            sample = row["sample"]
            output.append(
                (
                    "exploratory", *key, config["reference_client"], config["concurrency"],
                    config.get("search_round", ""), row["planned_microblock_id"],
                    sample.get("completion_status", "planned_but_missing") if sample else "planned_but_missing",
                    "" if _valid_metric(row) is None else format(_valid_metric(row), ".17g"),
                    "" if candidate is None else candidate, "", "", "",
                )
            )

    neighbor_vectors: dict[str, tuple[float, ...]] = {}
    neighbor_meta: dict[str, tuple[tuple[str, str, str], int, int]] = {}
    selected_by_key: dict[
        tuple[str, str, str],
        tuple[int, dict[int, dict[int, float]], dict[int, tuple[int, int]]],
    ] = {}
    for key in sorted(confirmation):
        selected = [
            row for row in confirmation[key]
            if row["planned_microblock_status"] != "dormant_candidate"
        ]
        candidates = {int(row["config"]["branch_candidate"]) for row in selected}
        candidate = next(iter(candidates)) if len(candidates) == 1 else None
        if candidate is None or nominations.get(key) != candidate:
            reasons.append("capacity_selected_branch_identity_mismatch")
            continue
        by_round: dict[int, dict[int, float]] = defaultdict(dict)
        round_meta: dict[int, tuple[int, int]] = {}
        bad = False
        for row in selected:
            value = _valid_metric(row)
            if value is None:
                bad = True
                continue
            config = row["config"]
            round_index = int(config["confirmation_round"])
            meta = (int(row["session_number"]), int(config["williams_row"]))
            if round_index in round_meta and round_meta[round_index] != meta:
                bad = True
            round_meta[round_index] = meta
            concurrency = int(config["concurrency"])
            if concurrency in by_round[round_index]:
                bad = True
            by_round[round_index][concurrency] = value
            output.append(
                (
                    "confirmatory", *key, config["reference_client"], concurrency,
                    round_index, row["planned_microblock_id"], "valid", format(value, ".17g"),
                    candidate, "", "", "",
                )
            )
        expected_loads = set(neighbor_loads(candidate))
        if bad or set(by_round) != set(range(24)) or any(set(values) != expected_loads for values in by_round.values()):
            reasons.append("capacity_confirmation_incomplete")
            continue
        selected_by_key[key] = (candidate, by_round, round_meta)
        for neighbor in sorted(expected_loads - {candidate}):
            name = "|".join((*key, str(candidate), str(neighbor)))
            raw = paired_log_differences(
                [by_round[index][candidate] for index in range(24)],
                [by_round[index][neighbor] for index in range(24)],
                higher_is_better=True,
            )
            neighbor_vectors[name] = pair_session_superblocks(
                raw,
                [round_meta[index][0] for index in range(24)],
                [round_meta[index][1] for index in range(24)],
            )
            neighbor_meta[name] = (key, candidate, neighbor)

    interval_by_key: dict[tuple[str, str, str], dict[int, NeighborInterval]] = defaultdict(dict)
    if neighbor_vectors:
        result = paired_max_t_intervals(neighbor_vectors)
        for interval in result.intervals:
            key, _candidate, neighbor = neighbor_meta[interval.contrast]
            interval_by_key[key][neighbor] = NeighborInterval(
                neighbor, interval.low_log_effect, interval.high_log_effect
            )
    for key, (candidate, _by_round, _round_meta) in sorted(selected_by_key.items()):
        decision = confirm_nomination(candidate, interval_by_key.get(key, {}))
        if decision.status not in {"confirmed", "right_censored"}:
            reasons.append(decision.reason or "selection_not_confirmed")
        if decision.status == "right_censored":
            reasons.append("capacity_right_censored")
        for neighbor, interval in sorted(interval_by_key.get(key, {}).items()):
            output.append(
                (
                    "confirmation_interval", *key, "", neighbor, "", "", decision.status,
                    "", candidate, format(interval.low_log_ratio, ".17g"),
                    format(interval.high_log_ratio, ".17g"), decision.reason,
                )
            )

    comparison_rows: list[tuple[Any, ...]] = []
    families: dict[
        tuple[str, str],
        dict[str, tuple[int, dict[int, dict[int, float]], dict[int, tuple[int, int]]]],
    ] = defaultdict(dict)
    for (server, backend, scenario), selected in selected_by_key.items():
        families[(backend, scenario)][server] = selected
    for family in sorted(families):
        members = families[family]
        if "ngtcp2perf" not in members or len(members) < 2:
            reasons.append("capacity_server_comparison_incomplete")
            continue
        values = {}
        for server, (candidate, rounds, round_meta) in members.items():
            raw = [rounds[index][candidate] for index in range(24)]
            by_row: dict[int, dict[int, float]] = defaultdict(dict)
            for index, value in enumerate(raw):
                session, row = round_meta[index]
                by_row[row][session] = value
            if set(by_row) != set(range(12)) or any(
                set(sessions) != {1, 2} for sessions in by_row.values()
            ):
                reasons.append("capacity_confirmation_superblock_incomplete")
                values = {}
                break
            values[server] = [
                math.sqrt(by_row[row][1] * by_row[row][2])
                for row in range(12)
            ]
        if not values:
            continue
        for comparison_family, contrasts in (
            ("baseline", paired_server_contrasts(values, higher_is_better=True, baseline="ngtcp2perf")),
            ("all_pairs", paired_server_contrasts(values, higher_is_better=True)),
        ):
            inferred = paired_max_t_intervals(contrasts)
            for interval in inferred.intervals:
                comparison_rows.append(
                    (
                        "capacity_frontier|" + "|".join(family), comparison_family,
                        interval.contrast, format(interval.point_ratio, ".17g"),
                        format(interval.low_ratio, ".17g"), format(interval.high_ratio, ".17g"),
                        interval.classification, format(inferred.critical_value, ".17g"),
                        format(interval.sample_standard_deviation, ".17g"),
                        int(interval.variance_miss), "descriptive_only", "descriptive_only",
                    )
                )

    return (
        _tsv(
            (
                "phase", "server", "server_backend", "scenario", "reference_client",
                "concurrency", "round", "microblock_id", "status", "rate", "candidate",
                "low_log_candidate_ratio", "high_log_candidate_ratio", "decision_reason",
            ),
            output,
        ),
        _tsv(_COMPARISON_HEADERS, comparison_rows),
        reasons,
    )


def _memory_artifacts(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[bytes, bytes, list[str]]:
    grouped: dict[tuple[str, str, int], list[Mapping[str, Any]]] = defaultdict(list)
    reasons: list[str] = []
    for row in rows:
        config = row["config"]
        grouped[(
            str(config["server"]),
            str(config["server_backend"]),
            int(config["block_position"]),
        )].append(row)

    output: list[tuple[Any, ...]] = []
    fits: dict[tuple[str, str], dict[int, tuple[float, float]]] = defaultdict(dict)
    fit_meta: dict[int, tuple[int, int, str]] = {}
    for key in sorted(grouped):
        members = grouped[key]
        by_n: dict[int, float] = {}
        invalid = False
        for row in members:
            sample = row["sample"]
            metric_name = "" if sample is None else str(sample.get("metric", {}).get("name", ""))
            value = _valid_metric(row)
            connections = int(row["config"]["connections"])
            if metric_name not in {"memory_current_bytes", "memory_bytes"} or value is None or connections in by_n:
                invalid = True
                continue
            by_n[connections] = value
        if invalid or tuple(sorted(by_n)) != MEMORY_N_VALUES:
            reasons.append("memory_curve_incomplete_or_invalid")
            continue
        fit = fit_memory_curve(
            tuple(MemoryPoint(n, by_n[n]) for n in MEMORY_N_VALUES)
        )
        if fit.status != "claimable":
            reasons.extend(item for item in fit.reason.split(";") if item)
        server, backend, block = key
        fits[(server, backend)][block] = (fit.intercept, fit.bytes_per_connection)
        superblock = members[0].get("superblock_id")
        williams_row = members[0].get("williams_row")
        if not isinstance(superblock, str) or williams_row is None:
            reasons.append("memory_inference_missing_superblock_identity")
        else:
            meta = (int(williams_row), int(members[0]["session_number"]), superblock)
            if block in fit_meta and fit_meta[block] != meta:
                reasons.append("memory_block_identity_mismatch")
            fit_meta[block] = meta
        for index, n in enumerate(MEMORY_N_VALUES):
            output.append(
                (
                    server, backend, block, n, format(by_n[n], ".17g"),
                    format(fit.fitted[index], ".17g"), format(fit.residuals[index], ".17g"),
                    format(fit.intercept, ".17g"), format(fit.bytes_per_connection, ".17g"),
                    fit.status, fit.reason,
                )
            )

    comparison_rows: list[tuple[Any, ...]] = []
    by_backend: dict[str, dict[str, dict[int, tuple[float, float]]]] = defaultdict(dict)
    for (server, backend), blocks in fits.items():
        by_backend[backend][server] = blocks
    for backend in sorted(by_backend):
        servers = by_backend[backend]
        if "ngtcp2perf" not in servers or any(set(blocks) != set(range(24)) for blocks in servers.values()):
            reasons.append("memory_inference_requires_twenty_four_complete_raw_blocks")
            continue
        for metric_index, metric_name in ((0, "intercept_bytes"), (1, "bytes_per_connection")):
            raw_values = {
                server: [blocks[index][metric_index] for index in range(24)]
                for server, blocks in servers.items()
            }
            if any(value <= 0.0 for vector in raw_values.values() for value in vector):
                reasons.append("inconclusive_nonpositive_estimate")
                continue
            values: dict[str, list[float]] = {}
            try:
                for server, vector in raw_values.items():
                    by_row: dict[int, dict[int, float]] = defaultdict(dict)
                    for block, value in enumerate(vector):
                        row, session, _superblock = fit_meta[block]
                        if session in by_row[row]:
                            raise ValueError("duplicate memory session row")
                        by_row[row][session] = value
                    if set(by_row) != set(range(12)) or any(
                        set(sessions) != {1, 2} for sessions in by_row.values()
                    ):
                        raise ValueError("incomplete memory session pair")
                    values[server] = [
                        math.sqrt(by_row[row][1] * by_row[row][2])
                        for row in range(12)
                    ]
            except (KeyError, ValueError):
                reasons.append("memory_inference_requires_twelve_complete_superblocks")
                continue
            for family, contrasts in (
                ("baseline", paired_server_contrasts(values, higher_is_better=False, baseline="ngtcp2perf")),
                ("all_pairs", paired_server_contrasts(values, higher_is_better=False)),
            ):
                inferred = paired_max_t_intervals(
                    contrasts,
                    margin=MEMORY_MARGIN,
                    variance_envelope=MEMORY_SUPERBLOCK_SD_ENVELOPE,
                )
                for interval in inferred.intervals:
                    comparison_rows.append(
                        (
                            f"memory_curve|{backend}|{metric_name}", family, interval.contrast,
                            format(interval.point_ratio, ".17g"), format(interval.low_ratio, ".17g"),
                            format(interval.high_ratio, ".17g"), interval.classification,
                            format(inferred.critical_value, ".17g"),
                            format(interval.sample_standard_deviation, ".17g"),
                            int(interval.variance_miss), "descriptive_only", "descriptive_only",
                        )
                    )
    return (
        _tsv(
            (
                "server", "server_backend", "block", "connections", "memory_bytes",
                "fitted_bytes", "residual_bytes", "intercept_bytes",
                "bytes_per_connection", "fit_status", "fit_reason",
            ),
            output,
        ),
        _tsv(_COMPARISON_HEADERS, comparison_rows),
        reasons,
    )


def _tail_artifacts(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[bytes, bytes, list[str]]:
    reasons: list[str] = []
    block_rows: list[tuple[Any, ...]] = []
    values: dict[tuple[str, str, str, str], dict[str, dict[str, float]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    tail_meta: dict[str, tuple[str, int, int, str]] = {}
    family_durations: dict[tuple[str, str, str], set[int]] = defaultdict(set)
    for row in rows:
        config = row["config"]
        sample = row["sample"]
        status = "claimable"
        reason = ""
        p99 = None
        eligible_count = 0
        started = failed = censored = 0
        wilson = None
        resolution = 0
        measurement_duration_ns = config.get("measurement_duration_ns")
        if (
            isinstance(measurement_duration_ns, bool)
            or not isinstance(measurement_duration_ns, int)
            or measurement_duration_ns not in {
                2_000_000_000,
                5_000_000_000,
                10_000_000_000,
                20_000_000_000,
            }
        ):
            status, reason = "unclaimable", "tail_duration_identity_missing_or_invalid"
        if sample is None or sample.get("completion_status") != "valid":
            status, reason = "unclaimable", "tail_sample_missing_or_invalid"
        elif status == "claimable":
            tail = sample.get("tail")
            if not isinstance(tail, dict):
                status, reason = "unclaimable", "tail_observations_missing"
            else:
                try:
                    started = int(tail["started_operations"])
                    failed = int(tail["failed_operations"])
                    censored = int(tail["censored_operations"])
                    resolution = int(tail["histogram_resolution_ns"])
                    operations = tail["operations"]
                    start = int(sample["timestamps"]["global_start_raw_ns"])
                    end = int(sample["timestamps"]["global_end_raw_ns"])
                    if end - start != measurement_duration_ns:
                        raise ValueError("tail measurement duration does not reconcile")
                    eligible = []
                    seen: set[int] = set()
                    for operation in operations:
                        sequence = int(operation["operation_sequence"])
                        began = int(operation["start_raw_ns"])
                        terminal = int(operation["terminal_raw_ns"])
                        latency = int(operation["latency_ns"])
                        if sequence in seen or terminal - began != latency:
                            raise ValueError("duplicate or inconsistent tail operation")
                        seen.add(sequence)
                        if start <= began < end and start <= terminal < end:
                            eligible.append((began, sequence, float(latency)))
                    eligible_count = len(eligible)
                    if started < eligible_count + failed + censored or failed < 0 or censored < 0:
                        raise ValueError("tail operation counters do not reconcile")
                    wilson = wilson_upper_bound(failed + censored, started)
                    if eligible_count < 1024:
                        status, reason = "unclaimable", "insufficient_tail_observations"
                    else:
                        p99 = tail_block_p99(eligible)
                        if wilson >= 0.01:
                            status, reason = "unclaimable", "p99_right_censored"
                        elif resolution <= 0 or resolution > 0.01 * p99:
                            status, reason = "unclaimable", "resolution_limited"
                except (KeyError, TypeError, ValueError):
                    status, reason = "unclaimable", "malformed_tail_observations"
        if status != "claimable":
            reasons.append(reason)
        family = (
            str(config["server_backend"]), str(config["scenario"]),
            str(config["path_profile"]),
        )
        if isinstance(measurement_duration_ns, int) and not isinstance(
            measurement_duration_ns, bool
        ):
            family_durations[family].add(measurement_duration_ns)
        if p99 is not None and status == "claimable":
            block = str(row["planned_microblock_id"])
            superblock = row.get("superblock_id")
            williams_row = row.get("williams_row")
            if not isinstance(superblock, str) or williams_row is None:
                reasons.append("tail_inference_missing_superblock_identity")
            else:
                metadata = (
                    superblock,
                    int(row["session_number"]),
                    int(williams_row),
                    str(config["reference_client"]),
                )
                prior = tail_meta.setdefault(block, metadata)
                if prior != metadata:
                    reasons.append("tail_block_metadata_inconsistent_across_servers")
                else:
                    values[family][block][str(config["server"])] = p99
        block_rows.append(
            (
                config["server"], config["server_backend"], config["scenario"],
                config["path_profile"], config["reference_client"], row["session_number"],
                measurement_duration_ns // 1_000_000_000
                if isinstance(measurement_duration_ns, int)
                and not isinstance(measurement_duration_ns, bool)
                else "",
                row["planned_microblock_id"], started, eligible_count, failed, censored,
                "" if wilson is None else format(wilson, ".17g"),
                "" if p99 is None else format(p99, ".17g"), resolution, status, reason,
            )
        )

    comparison_rows: list[tuple[Any, ...]] = []
    for family in sorted(values):
        raw_blocks = sorted(values[family])
        servers = sorted({server for block in raw_blocks for server in values[family][block]})
        if len(family_durations[family]) != 1:
            reasons.append("tail_inference_requires_one_qualified_scenario_duration")
            continue
        if len(raw_blocks) != 24 or "ngtcp2perf" not in servers or any(set(values[family][block]) != set(servers) for block in raw_blocks):
            reasons.append("tail_inference_requires_twenty_four_complete_raw_blocks")
            continue
        if {
            client: sum(tail_meta[block][3] == client for block in raw_blocks)
            for client in ("ngtcp2perf", "picoperf")
        } != {"ngtcp2perf": 12, "picoperf": 12}:
            reasons.append("tail_inference_requires_twelve_blocks_per_reference_client")
            continue
        paired: dict[str, dict[int, dict[str, float]]] = defaultdict(dict)
        malformed = False
        for block in raw_blocks:
            superblock, session, _row, _client = tail_meta[block]
            if session in paired[superblock]:
                malformed = True
            paired[superblock][session] = values[family][block]
        if (
            malformed
            or len(paired) != 12
            or any(set(sessions) != {1, 2} for sessions in paired.values())
        ):
            reasons.append("tail_inference_requires_twelve_complete_superblocks")
            continue
        superblocks = sorted(paired)
        by_server = {
            server: [
                math.sqrt(
                    paired[superblock][1][server]
                    * paired[superblock][2][server]
                )
                for superblock in superblocks
            ]
            for server in servers
        }
        for comparison_family, contrasts in (
            ("baseline", paired_server_contrasts(by_server, higher_is_better=False, baseline="ngtcp2perf")),
            ("all_pairs", paired_server_contrasts(by_server, higher_is_better=False)),
        ):
            inferred = paired_max_t_intervals(contrasts)
            for interval in inferred.intervals:
                comparison_rows.append(
                    (
                        "tail_latency|" + "|".join(family), comparison_family,
                        interval.contrast, format(interval.point_ratio, ".17g"),
                        format(interval.low_ratio, ".17g"), format(interval.high_ratio, ".17g"),
                        interval.classification, format(inferred.critical_value, ".17g"),
                        format(interval.sample_standard_deviation, ".17g"), int(interval.variance_miss),
                        "descriptive_only", "descriptive_only",
                    )
                )
    return (
        _tsv(
            (
                "server", "server_backend", "scenario", "path_profile", "reference_client",
                "session", "measurement_duration_seconds", "microblock_id", "started", "eligible", "failed", "censored",
                "wilson_failure_upper", "p99_ns", "histogram_resolution_ns", "status", "reason",
            ),
            block_rows,
        ),
        _tsv(_COMPARISON_HEADERS, comparison_rows),
        reasons,
    )


def _coverage(
    rows: Sequence[Mapping[str, Any]], *, publication_valid: bool = False
) -> bytes:
    grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["planned_microblock_status"] == "not_selected":
            continue
        config = row["config"]
        grouped[(str(config["server"]), str(config["scenario"]), str(config["server_backend"]))].append(row)
    output: list[tuple[Any, ...]] = []
    for cell in canonical_matrix():
        key = (cell.server, cell.scenario, cell.server_backend)
        members = grouped.get(key, ())
        samples = [member for member in members if member.get("sample") is not None]
        valid = [
            member for member in samples
            if member["sample"].get("completion_status") == "valid"
        ]
        sample_attempts = sorted({
            str(member.get("attempt_id")) for member in samples if member.get("attempt_id")
        })
        unsupported_attempts = sorted({
            str(member.get("planned_attempt_id"))
            for member in members
            if member.get("planned_termination_reason")
            in {"required_scenario_not_attested", "required_backend_not_attested"}
            and member.get("planned_attempt_id")
        })
        capability_evidence_parts = [
            f"journal:attempt:{attempt}:hello_capabilities_passed"
            for attempt in sample_attempts
        ]
        capability_evidence_parts.extend(
            f"journal:attempt:{attempt}:capability_not_attested"
            for attempt in unsupported_attempts
        )
        capability_evidence = ";".join(capability_evidence_parts)
        if not capability_evidence:
            capability_evidence = "missing:live_hello_capabilities_evidence_not_persisted"

        behavioral_evidence = (
            f"cmake-test:{cell.contract_test};source:{cell.contract_source};"
            "missing:contract_execution_result_not_persisted_in_campaign_journal"
        )
        if valid:
            interoperability_evidence = ";".join(
                f"journal:sample:{member['committed_trial_id']}:attempt:{member['attempt_id']}"
                for member in sorted(
                    valid,
                    key=lambda member: (
                        str(member["committed_trial_id"]), str(member["attempt_id"])
                    ),
                )
            )
        elif samples:
            interoperability_evidence = ";".join(
                f"journal:sample:{member['committed_trial_id']}:not_valid"
                for member in sorted(samples, key=lambda member: str(member["committed_trial_id"]))
            )
        else:
            interoperability_evidence = "missing:no_valid_native_endpoint_pair_sample"

        planned = len(members)
        valid_count = len(valid)
        if planned and valid_count == planned and publication_valid:
            publication_evidence = (
                f"artifact:row-results.tsv:{cell.server}/{cell.scenario}/{cell.server_backend}"
            )
        elif planned and valid_count == planned:
            publication_evidence = "missing:campaign_not_publication_valid"
        else:
            publication_evidence = "missing:incomplete_or_invalid_planned_cell"

        blocker = cell.blocker
        if not blocker and not planned:
            blocker = "journal_gap:canonical_planned_cell_absent"
        elif not blocker and planned != valid_count:
            reasons = sorted({
                str(member.get("planned_termination_reason"))
                for member in members if member.get("planned_termination_reason")
            })
            blocker = "runtime_gap:" + (",".join(reasons) if reasons else "missing_or_invalid_sample")

        if not cell.advertised and samples:
            coverage_status = "capability_contract_conflict"
        elif not cell.advertised:
            coverage_status = "unsupported"
        elif planned and valid_count == planned and publication_valid:
            coverage_status = "publication_evidence_complete"
        elif planned and valid_count == planned:
            coverage_status = "interoperability_evidence_complete"
        elif valid_count:
            coverage_status = "partial_interoperability_evidence"
        elif planned:
            coverage_status = "missing_interoperability_evidence"
        else:
            coverage_status = "missing_planned_cell"

        output.append((
            *key, planned, len(samples), valid_count,
            "advertised" if cell.advertised else "not_advertised",
            capability_evidence, behavioral_evidence, interoperability_evidence,
            publication_evidence, blocker, coverage_status,
        ))
    return _tsv(
        (
            "server", "scenario", "server_backend", "planned", "committed", "valid",
            "capability_contract", "capability_evidence", "behavioral_evidence",
            "interoperability_evidence", "publication_evidence", "blocker",
            "coverage_status",
        ),
        output,
    )


def _comparisons(rows: Sequence[Mapping[str, Any]]) -> tuple[bytes, list[str]]:
    if not rows or any(row["sample"] is None for row in rows):
        return _tsv(_COMPARISON_HEADERS, ()), ["inference_requires_complete_schedule"]
    by_family_block: dict[tuple[str, ...], dict[str, dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
    block_meta: dict[str, tuple[str, int, int, float, float]] = {}
    for row in rows:
        sample = row["sample"]
        if sample["completion_status"] != "valid":
            return _tsv(_COMPARISON_HEADERS, ()), ["inference_contains_invalid_sample"]
        config = row["config"]
        family = _family(config, sample)
        block = str(row["planned_microblock_id"])
        superblock = row.get("superblock_id")
        williams_row = row.get("williams_row")
        if not isinstance(superblock, str) or williams_row is None:
            return _tsv(_COMPARISON_HEADERS, ()), ["inference_missing_superblock_identity"]
        value = float(sample["metric"]["derived_decimal"])
        by_family_block[family][block][str(config["server"])] = value
        client_code = -0.5 if config["reference_client"] == "ngtcp2perf" else 0.5
        session_code = -0.5 if int(row["session_number"]) == 1 else 0.5
        block_meta[block] = (
            superblock,
            int(row["session_number"]),
            int(williams_row),
            client_code,
            session_code,
        )
    output = []
    reasons: list[str] = []
    for family in sorted(by_family_block):
        raw_blocks = sorted(by_family_block[family])
        servers = sorted({server for block in raw_blocks for server in by_family_block[family][block]})
        if len(raw_blocks) != 24 or "ngtcp2perf" not in servers or any(set(by_family_block[family][block]) != set(servers) for block in raw_blocks):
            reasons.append("inference_requires_twenty_four_complete_raw_blocks")
            continue
        paired: dict[str, dict[int, dict[str, float]]] = defaultdict(dict)
        malformed_pair = False
        for block in raw_blocks:
            superblock, session, _row, _client, _session_code = block_meta[block]
            if session in paired[superblock]:
                malformed_pair = True
            paired[superblock][session] = by_family_block[family][block]
        if (
            malformed_pair
            or len(paired) != 12
            or any(set(sessions) != {1, 2} for sessions in paired.values())
        ):
            reasons.append("inference_requires_twelve_complete_superblocks")
            continue
        superblock_ids = sorted(paired)
        values = {
            server: [
                math.sqrt(
                    paired[superblock][1][server]
                    * paired[superblock][2][server]
                )
                for superblock in superblock_ids
            ]
            for server in servers
        }
        orientation = next(
            row["sample"]["metric"]["orientation"]
            for row in rows if _family(row["config"], row["sample"]) == family
        )
        higher = orientation == "higher_is_better"
        baseline_contrasts = paired_server_contrasts(values, higher_is_better=higher, baseline="ngtcp2perf")
        all_contrasts = paired_server_contrasts(values, higher_is_better=higher)
        raw_values = {
            server: [by_family_block[family][block][server] for block in raw_blocks]
            for server in servers
        }
        raw_baseline_contrasts = paired_server_contrasts(
            raw_values, higher_is_better=higher, baseline="ngtcp2perf"
        )
        client_codes = [block_meta[block][3] for block in raw_blocks]
        session_codes = [block_meta[block][4] for block in raw_blocks]
        cluster_names = sorted({block_meta[block][0] for block in raw_blocks})
        cluster_index = {name: index for index, name in enumerate(cluster_names)}
        cluster_ids = [cluster_index[block_meta[block][0]] for block in raw_blocks]
        sensitivity = hc2_wild_max_t_sensitivity(
            raw_baseline_contrasts, client_codes, session_codes, cluster_ids
        )
        sensitivity_by_contrast: dict[str, dict[str, str]] = defaultdict(dict)
        for interval in sensitivity.intervals:
            sensitivity_by_contrast[interval.contrast][interval.effect] = interval.status
        for label, contrasts in (("baseline", baseline_contrasts), ("all_pairs", all_contrasts)):
            result = paired_max_t_intervals(contrasts)
            for interval in result.intervals:
                sens = sensitivity_by_contrast.get(interval.contrast, {})
                output.append(
                    (
                        "|".join(family), label, interval.contrast,
                        format(interval.point_ratio, ".17g"), format(interval.low_ratio, ".17g"),
                        format(interval.high_ratio, ".17g"), interval.classification,
                        format(result.critical_value, ".17g"),
                        format(interval.sample_standard_deviation, ".17g"), int(interval.variance_miss),
                        sens.get("client", "descriptive_only"), sens.get("session", "descriptive_only"),
                    )
                )
    return _tsv(_COMPARISON_HEADERS, output), reasons


def reject_mixed_leaderboard(rows: Sequence[Mapping[str, Any]]) -> None:
    """Reject aggregation across incomparable treatment or estimand strata."""

    fields = (
        "campaign_kind", "estimand", "reference_client", "server_backend", "path_profile",
        "concurrency", "tls_mode", "metric",
    )
    for field in fields:
        values = {row.get(field) for row in rows}
        if len(values) > 1:
            raise RenderError(f"global leaderboard mixes incomparable {field} values")


def render_analysis(
    journal: Journal,
    campaign_id: str,
    campaign_kind: str,
    *,
    preflight_reasons: Sequence[str] = (),
    diagnostic_manifest: Mapping[str, Any] | None = None,
    methodology: Mapping[str, Any] | None = None,
) -> RenderedAnalysis:
    rows = _load_rows(journal, campaign_id)
    quality, complete, reasons = _quality(rows)
    row_results, row_reasons = _row_results(rows)
    cleanup_strata, cleanup_reasons = _cleanup_artifact(rows)
    capacity_search = _tsv(
        (
            "phase", "server", "server_backend", "scenario", "reference_client",
            "concurrency", "round", "microblock_id", "status", "rate", "candidate",
            "low_log_candidate_ratio", "high_log_candidate_ratio", "decision_reason",
        ),
        (),
    )
    memory_curves = _tsv(
        (
            "server", "server_backend", "block", "connections", "memory_bytes",
            "fitted_bytes", "residual_bytes", "intercept_bytes",
            "bytes_per_connection", "fit_status", "fit_reason",
        ),
        (),
    )
    tail_blocks = _tsv(
        (
            "server", "server_backend", "scenario", "path_profile", "reference_client",
            "session", "microblock_id", "started", "eligible", "failed", "censored",
            "wilson_failure_upper", "p99_ns", "histogram_resolution_ns", "status", "reason",
        ),
        (),
    )
    if campaign_kind == "capacity":
        capacity_search, comparisons, comparison_reasons = _capacity_artifacts(rows)
    elif campaign_kind == "memory":
        memory_curves, comparisons, comparison_reasons = _memory_artifacts(rows)
    elif campaign_kind == "tail":
        tail_blocks, comparisons, comparison_reasons = _tail_artifacts(rows)
    elif campaign_kind == "publication":
        comparisons, comparison_reasons = _comparisons(rows)
    else:
        comparisons, comparison_reasons = _tsv(_COMPARISON_HEADERS, ()), []
    reasons.extend(row_reasons)
    reasons.extend(cleanup_reasons)
    reasons.extend(comparison_reasons)
    reasons.extend(preflight_reasons)
    diagnostic_summary = "none"
    if diagnostic_manifest is not None:
        reasons.append("diagnostic_unqualified_host")
        qualifications = diagnostic_manifest.get("qualifications", ())
        diagnostic_summary = "; ".join(
            f"{item['kind']}={item['status']}"
            + (
                f" ({','.join(item['reasons'])})"
                if item.get("reasons")
                else ""
            )
            for item in qualifications
        )
    reasons = sorted(set(reasons))
    valid = complete and not reasons
    runtime_efficiency: list[dict[str, Any]] = []
    operational_timeout_ns: int | None = None
    operational_timeout_publication_gate = False
    if methodology is not None:
        runtime_policy = methodology.get("runtime")
        if isinstance(runtime_policy, Mapping):
            operational_timeout_ns = int(
                runtime_policy["operational_session_timeout_ns"]
            )
            operational_timeout_publication_gate = methodology.get(
                "version"
            ) in {"2.2", "2.3"}
    for session_row in journal.connection.execute(
        """
        SELECT session_number FROM session
        WHERE campaign_id=? ORDER BY session_number
        """,
        (campaign_id,),
    ):
        session = int(session_row["session_number"])
        artifact = journal.connection.execute(
            """
            SELECT content FROM artifact
            WHERE campaign_id=? AND path=?
            """,
            (campaign_id, f"runtime/session-{session}.json"),
        ).fetchone()
        if artifact is None:
            continue
        document = json.loads(bytes(artifact["content"]))
        runtime = document.get("runtime")
        if not isinstance(runtime, Mapping):
            continue
        wall_ns = int(runtime["session_wall_ns"])
        timeout_exceeded = (
            operational_timeout_ns is not None
            and wall_ns > operational_timeout_ns
        )
        if operational_timeout_publication_gate and timeout_exceeded:
            reasons.append(
                f"runtime_session_{session}_operational_timeout_exceeded"
            )
        runtime_efficiency.append(
            {
                "session": session,
                "wall_ns": wall_ns,
                "useful_measurement_ns": int(
                    runtime["useful_measurement_ns"]
                ),
                "useful_wall_fraction_decimal": str(
                    runtime["useful_wall_fraction_decimal"]
                ),
                "publication_qualification_gate": (
                    operational_timeout_publication_gate
                ),
                "operational_session_timeout_ns": operational_timeout_ns,
                "operational_timeout_exceeded": timeout_exceeded,
            }
        )
    reasons = sorted(set(reasons))
    valid = complete and not reasons
    runtime_heading = (
        "Runtime efficiency (publication session ceiling)"
        if operational_timeout_publication_gate
        else "Runtime efficiency (reported, not a publication gate)"
    )
    runtime_lines = (
        f"\n## {runtime_heading}\n\n"
        + "\n".join(
            "- Session "
            f"{item['session']}: useful "
            f"{item['useful_measurement_ns'] / 1_000_000_000:.3f} s / wall "
            f"{item['wall_ns'] / 1_000_000_000:.3f} s = "
            f"{item['useful_wall_fraction_decimal']}; operational timeout "
            f"exceeded: {str(item['operational_timeout_exceeded']).lower()}."
            for item in runtime_efficiency
        )
        + "\n"
        if runtime_efficiency
        else ""
    )
    report = (
        (
            "# DIAGNOSTIC — NOT PUBLICATION DATA\n\n"
            if diagnostic_manifest is not None
            else ""
        )
        + "# quicperf v2 campaign report\n\n"
        f"Campaign ID: `{campaign_id}`\n\n"
        f"Campaign kind: `{campaign_kind}`\n\n"
        f"Analysis status: `{'publication_valid' if valid else 'nonpublishable'}`\n\n"
        f"Diagnostic qualification state: {diagnostic_summary}\n\n"
        f"Planned outcomes: {len(rows)}\n\n"
        f"Committed outcomes: {sum(row['sample'] is not None for row in rows)}\n\n"
        f"Quality reasons: {', '.join(reasons) if reasons else 'none'}\n\n"
        "No result in this report is a global cross-estimand leaderboard.\n"
        + runtime_lines
    ).encode("utf-8")
    artifacts = {
        "row-results.tsv": row_results,
        "comparisons.tsv": comparisons,
        "quality-audit.tsv": quality,
        "scenario-coverage.tsv": _coverage(
            rows, publication_valid=valid and campaign_kind == "publication"
        ),
        "capacity-search.tsv": capacity_search,
        "memory-curves.tsv": memory_curves,
        "tail-blocks.tsv": tail_blocks,
        "cleanup-strata.tsv": cleanup_strata,
        "report.md": report,
        "analysis.json": canonical_bytes(
            {
                "schema_version": (
                    f"quicperf.analysis.v{methodology.get('version', '2.1')}"
                    if methodology is not None
                    else "quicperf.analysis.v2"
                ),
                "campaign_id": campaign_id,
                "campaign_kind": campaign_kind,
                "complete": complete,
                "diagnostic_unqualified_host": diagnostic_manifest is not None,
                "publication_valid": valid,
                "reasons": reasons,
                **(
                    {"runtime_efficiency": runtime_efficiency}
                    if methodology is not None
                    else {}
                ),
                "watermark": (
                    "DIAGNOSTIC — NOT PUBLICATION DATA"
                    if diagnostic_manifest is not None
                    else None
                ),
            }
        ),
    }
    return RenderedAnalysis(artifacts, complete, valid, tuple(reasons))
