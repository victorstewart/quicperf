#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path


LIBRARY_NAMES = {
    "lsperf": "LSQUIC",
    "mvfstperf": "mvfst",
    "neqoperf": "Neqo",
    "ngtcp2perf": "ngtcp2",
    "noqperf": "noq",
    "picoperf": "picoquic",
    "quicheperf": "quiche",
    "quiczigperf": "quic-zig",
    "quinnperf": "Quinn",
    "s2nperf": "s2n-quic",
    "tquicperf": "TQUIC",
    "xquicperf": "XQUIC",
}

BENCHMARK_NAMES = {
    "bidi": "bidirectional",
    "close_reset_cleanup": "close/reset cleanup",
    "connect": "connect",
    "datagram": "datagram",
    "download": "download",
    "flow_control": "flow control",
    "idle_footprint": "idle footprint",
    "loss_recovery": "loss recovery",
    "multistream_download": "multistream download",
    "multistream_upload": "multistream upload",
    "reqresp": "request/response",
    "small_payload_pps": "small payload messages",
    "stream_churn": "stream churn",
    "upload": "upload",
}

BENCHMARK_SUMMARIES = {
    "download": "Server-to-client bulk transfer; higher throughput is better.",
    "upload": "Client-to-server bulk transfer; higher throughput is better.",
    "bidi": "Simultaneous upload and download on one connection.",
    "multistream_download": "Server-to-client transfer split across concurrent streams.",
    "multistream_upload": "Client-to-server transfer split across concurrent streams.",
    "reqresp": "Small request/response exchanges on fresh bidirectional streams.",
    "stream_churn": "Repeated stream open, send, receive, and finish lifecycle.",
    "small_payload_pps": "Tiny-message packet and API overhead.",
    "loss_recovery": "Deterministic impairment path covering loss recovery behavior.",
    "flow_control": "Small-window transfer pressure and flow-control update behavior.",
    "connect": "Full connection establishment plus stream creation.",
    "datagram": "Unreliable application DATAGRAM echo capability.",
    "idle_footprint": "Server RSS delta per held idle connection; lower is better.",
    "close_reset_cleanup": "Graceful fresh-stream close and cleanup throughput.",
}

BENCHMARK_ORDER = [
    "download",
    "upload",
    "bidi",
    "multistream_download",
    "multistream_upload",
    "reqresp",
    "stream_churn",
    "small_payload_pps",
    "loss_recovery",
    "flow_control",
    "connect",
    "datagram",
    "idle_footprint",
    "close_reset_cleanup",
]

NETWORK_NAMES = {
    "syscall": "syscall",
    "iouring": "io_uring",
}

METRIC_UNITS = {
    "throughput_gbps": "gigabits/second",
    "connections_per_second": "connections/second",
    "requests_per_second": "requests/second",
    "messages_per_second": "messages/second",
    "streams_per_second": "streams/second",
    "server_rss_delta_bytes_per_connection": "bytes/connection",
}

METRIC_SORT_DIRECTION = {
    "throughput_gbps": "descending",
    "connections_per_second": "descending",
    "requests_per_second": "descending",
    "messages_per_second": "descending",
    "streams_per_second": "descending",
    "server_rss_delta_bytes_per_connection": "ascending",
}


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def fmt_value(metric: str, value: str | None) -> str:
    if not value:
        return "-"
    try:
        numeric = float(value)
    except ValueError:
        return "-"
    if metric == "throughput_gbps":
        return f"{numeric:.3f}"
    if metric == "server_rss_delta_bytes_per_connection":
        return f"{numeric:,.0f}"
    return f"{numeric:,.0f}"


def load_rows(
    run_dir: Path,
    *,
    include_scenarios: set[str] | None = None,
    skip_scenarios: set[str] | None = None,
) -> list[dict[str, str]]:
    publication_rows = read_tsv(run_dir / "publication-results.tsv")
    row_stats = read_tsv(run_dir / "row-stats.tsv")

    stats_by_key: dict[tuple[str, str, str, str, str], dict[str, str]] = {}
    best_stats: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for row in row_stats:
        if row.get("phase") != "combined":
            continue
        key = (
            row["binary"],
            row["scenario"],
            row["network"],
            row["metric"],
            row["client_threads"],
        )
        stats_by_key[key] = row
        group = key[:4]
        try:
            median = float(row["median"])
        except ValueError:
            continue
        old = best_stats.get(group)
        if old is None or median > float(old["median"]):
            best_stats[group] = row

    rows: list[dict[str, str]] = []
    for publication in publication_rows:
        binary = publication["binary"]
        scenario = publication["scenario"]
        network = publication["network"]
        metric = publication["metric"]
        if include_scenarios is not None and scenario not in include_scenarios:
            continue
        if skip_scenarios is not None and scenario in skip_scenarios:
            continue
        if scenario == "idle_footprint" and metric == "idle_connections":
            continue
        selected_threads = publication.get("selected_threads", "").strip()

        stat = None
        if selected_threads:
            stat = stats_by_key.get((binary, scenario, network, metric, selected_threads))
        else:
            stat = best_stats.get((binary, scenario, network, metric))

        if stat is None:
            continue

        client_threads = stat["client_threads"]
        samples = stat["samples"]
        p50 = fmt_value(metric, stat.get("median"))
        p90 = fmt_value(metric, stat.get("p90"))
        p99 = fmt_value(metric, stat.get("p99"))
        sort_p50 = stat.get("median", "")
        sort_p90 = stat.get("p90", "")
        sort_p99 = stat.get("p99", "")

        rows.append(
            {
                "library": LIBRARY_NAMES.get(binary, binary),
                "scenario": scenario,
                "benchmark": BENCHMARK_NAMES.get(scenario, scenario),
                "network": NETWORK_NAMES.get(network, network),
                "sort_direction": METRIC_SORT_DIRECTION.get(metric, "ascending"),
                "client_threads": client_threads,
                "samples": samples,
                "unit": METRIC_UNITS.get(metric, metric),
                "p50": p50,
                "p90": p90,
                "p99": p99,
                "sort_p50": sort_p50,
                "sort_p90": sort_p90,
                "sort_p99": sort_p99,
            }
        )

    return rows


def grouped_by_benchmark(rows: list[dict[str, str]]) -> list[tuple[str, list[dict[str, str]]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        grouped.setdefault(row["scenario"], []).append(row)
    ordered = [scenario for scenario in BENCHMARK_ORDER if scenario in grouped]
    ordered.extend(sorted(set(grouped) - set(ordered)))
    sorted_groups = []
    for scenario in ordered:
        first_row = grouped[scenario][0]
        reverse = first_row["sort_direction"] == "descending"
        unsupported_sentinel = float("-inf") if reverse else float("inf")
        benchmark_rows = sorted(
            grouped[scenario],
            key=lambda row: (
                float(row["sort_p99"]) if row["sort_p99"] else unsupported_sentinel,
                row["library"],
                row["network"],
            ),
            reverse=reverse,
        )
        sorted_groups.append((BENCHMARK_NAMES.get(scenario, scenario), benchmark_rows))
    return sorted_groups


def render_markdown(
    rows: list[dict[str, str]],
    artifact_dir: Path,
    datagram_artifact_dir: Path | None = None,
) -> str:
    artifact_sentence = (
        "The TCP+TLS sidecar is excluded from these QUIC tables. Full raw data "
        "and gate details are committed under "
        f"[`{artifact_dir}`]({artifact_dir}/)."
    )
    if datagram_artifact_dir is not None:
        artifact_sentence = (
            "The TCP+TLS sidecar is excluded from these QUIC tables. Full raw "
            "data and gate details are committed under "
            f"[`{artifact_dir}`]({artifact_dir}/), with DATAGRAM addendum data "
            f"under [`{datagram_artifact_dir}`]({datagram_artifact_dir}/)."
        )

    lines = [
        "# Latest Results",
        "",
        (
            "The adaptive publication runner samples each library/network/test row "
            "in randomized blocks until the row converges or reaches its bounded "
            "sample cap. Rows that remain noisy or nonstationary are retained with "
            "their measured distribution instead of being promoted as clean."
        ),
        "",
        (
            "Client load is swept upward per row to find server saturation using "
            "as many client threads as needed within the configured limit. Tables "
            "are sorted by best p99 first; for the current rate and throughput "
            "metrics, higher is better."
        ),
        "",
        artifact_sentence,
        "",
        "## Results",
        "",
    ]

    for benchmark, benchmark_rows in grouped_by_benchmark(rows):
        lines.extend(
            [
                f"### {benchmark.title()}",
                "",
                BENCHMARK_SUMMARIES.get(benchmark_rows[0]["scenario"], ""),
                "",
                (
                    "| Library | Network | Client threads | Samples | "
                    "Unit | p50 | p90 | p99 |"
                ),
                "|---|---|---:|---:|---|---:|---:|---:|",
            ]
        )
        for row in benchmark_rows:
            lines.append(
                "| {library} | {network} | {client_threads} | "
                "{samples} | {unit} | {p50} | {p90} | {p99} |".format(**row)
            )
        lines.append("")

    lines.extend(
        [
            "## Caveats",
            "",
            "- `idle_footprint` is omitted from the current table because this run captured only the old completion marker, not resource footprint. Rerun with the RSS sampler before publishing idle-footprint claims.",
            "- `datagram` rows come from the addendum run with a shared 1,024-message outstanding cap and 65,536 echo operations. They are measured distributions, not a clean DATAGRAM leaderboard, because strict publication gates still marked the rows noisy or nonstationary.",
            "- Unsupported capability rows are explicit unsupported markers, not crashes.",
            (
                "- Row-level caveats and full gate reasons are in "
                f"[`publication-results.tsv`]({artifact_dir}/publication-results.tsv), "
                f"[`row-stats.tsv`]({artifact_dir}/row-stats.tsv), "
                f"[`publication-row-audit.tsv`]({artifact_dir}/publication-row-audit.tsv), "
                f"and [`saturation-decisions.tsv`]({artifact_dir}/saturation-decisions.tsv)."
            ),
            f"- Raw samples are in [`adaptive-samples.tsv`]({artifact_dir}/adaptive-samples.tsv).",
        ]
    )
    if datagram_artifact_dir is not None:
        lines.extend(
            [
                (
                    "- DATAGRAM addendum gate reasons are in "
                    f"[`publication-results.tsv`]({datagram_artifact_dir}/publication-results.tsv), "
                    f"[`row-stats.tsv`]({datagram_artifact_dir}/row-stats.tsv), "
                    f"[`publication-row-audit.tsv`]({datagram_artifact_dir}/publication-row-audit.tsv), "
                    f"and [`saturation-decisions.tsv`]({datagram_artifact_dir}/saturation-decisions.tsv); "
                    f"raw samples are in [`adaptive-samples.tsv`]({datagram_artifact_dir}/adaptive-samples.tsv), "
                    f"with notes in [`README.md`]({datagram_artifact_dir}/README.md)."
                ),
                "",
            ]
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Render latest result docs.")
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=Path(".run/adaptive-production-all-benchmarks-20260515T-full31"),
    )
    parser.add_argument("--markdown", type=Path, default=Path("docs/latest-results.md"))
    parser.add_argument("--artifact-dir", type=Path, default=Path("results/full31"))
    parser.add_argument("--datagram-run-dir", type=Path, default=Path("docs/results/datagram-fairness-20260516"))
    parser.add_argument("--datagram-artifact-dir", type=Path, default=Path("results/datagram-fairness-20260516"))
    args = parser.parse_args()

    rows = load_rows(args.run_dir, skip_scenarios={"datagram"})
    datagram_artifact_dir = None
    if args.datagram_run_dir.exists():
        rows.extend(load_rows(args.datagram_run_dir, include_scenarios={"datagram"}))
        datagram_artifact_dir = args.datagram_artifact_dir
    args.markdown.write_text(
        render_markdown(rows, args.artifact_dir, datagram_artifact_dir),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
