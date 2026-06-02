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
    "resumed_connect": "resumed connect",
    "small_payload_pps": "small payload messages",
    "stream_churn": "stream churn",
    "upload": "upload",
    "zero_rtt_reqresp": "0-RTT request/response",
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
    "resumed_connect": "Session-ticket resumption proof for connection establishment.",
    "zero_rtt_reqresp": "Session resumption with early request/response data.",
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
    "resumed_connect",
    "zero_rtt_reqresp",
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
    "datagrams_per_second": "DATAGRAMs/second",
    "streams_per_second": "streams/second",
    "server_rss_delta_bytes_per_connection": "bytes/connection",
}

METRIC_SORT_DIRECTION = {
    "throughput_gbps": "descending",
    "connections_per_second": "descending",
    "requests_per_second": "descending",
    "messages_per_second": "descending",
    "datagrams_per_second": "descending",
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


def adapter_feature_value(features: str, name: str) -> str:
    prefix = f"{name}="
    for item in features.split("|"):
        if item.startswith(prefix):
            return item[len(prefix):]
    return ""


def metric_better_than(metric: str, candidate: float, current: float) -> bool:
    return candidate < current if METRIC_SORT_DIRECTION.get(metric) == "ascending" else candidate > current


def load_rows(
    run_dir: Path,
    *,
    include_scenarios: set[str] | None = None,
    skip_scenarios: set[str] | None = None,
) -> list[dict[str, str]]:
    publication_rows = read_tsv(run_dir / "publication-results.tsv")
    row_stats = read_tsv(run_dir / "row-stats.tsv")

    stats_by_key: dict[tuple[str, str, str, str, str, str], dict[str, str]] = {}
    best_stats: dict[tuple[str, str, str, str, str], dict[str, str]] = {}
    for row in row_stats:
        phase = row.get("phase", "publication")
        if phase not in {"combined", "publication", ""}:
            continue
        median_value = row.get("median") or row.get("p50") or ""
        key = (
            row["binary"],
            row["scenario"],
            row["network"],
            row.get("path_profile", "loopback") or "loopback",
            row["metric"],
            row["client_threads"],
        )
        stats_by_key[key] = row
        group = key[:5]
        try:
            median = float(median_value)
        except ValueError:
            continue
        old = best_stats.get(group)
        old_median = (old.get("median") or old.get("p50") or "0") if old else "0"
        if old is None or metric_better_than(row["metric"], median, float(old_median)):
            best_stats[group] = row

    rows: list[dict[str, str]] = []
    for publication in publication_rows:
        binary = publication["binary"]
        scenario = publication["scenario"]
        network = publication["network"]
        path_profile = publication.get("path_profile", "loopback") or "loopback"
        metric = publication["metric"]
        if binary == "tcpperf":
            continue
        if include_scenarios is not None and scenario not in include_scenarios:
            continue
        if skip_scenarios is not None and scenario in skip_scenarios:
            continue
        if scenario == "idle_footprint" and metric == "idle_connections":
            continue
        selected_threads = publication.get("selected_threads", "").strip()

        stat = None
        if selected_threads:
            stat = stats_by_key.get((binary, scenario, network, path_profile, metric, selected_threads))
        else:
            stat = best_stats.get((binary, scenario, network, path_profile, metric))

        if stat is None:
            continue

        client_threads = stat["client_threads"]
        samples = stat["samples"]
        p50_raw = stat.get("median") or stat.get("p50")
        p50 = fmt_value(metric, p50_raw)
        p90 = fmt_value(metric, stat.get("p90"))
        p99 = fmt_value(metric, stat.get("p99"))
        sort_p50 = p50_raw or ""
        sort_p90 = stat.get("p90", "")
        sort_p99 = stat.get("p99", "")
        adapter_features = publication.get("adapter_features", "")
        congestion_controller = (
            publication.get("congestion_controller", "")
            or adapter_feature_value(adapter_features, "cc")
            or "-"
        )
        publication_status = publication.get("publication_status", "") or stat.get("publication_status", "")
        audit_status = publication.get("audit_status", "") or stat.get("audit_status", "")
        reason = publication.get("reason", "") or stat.get("reason", "")
        rows.append(
            {
                "library": LIBRARY_NAMES.get(binary, binary),
                "scenario": scenario,
                "benchmark": BENCHMARK_NAMES.get(scenario, scenario),
                "network": NETWORK_NAMES.get(network, network),
                "status": publication_status or audit_status or "-",
                "audit_status": audit_status or "-",
                "reason": reason or "-",
                "sort_direction": METRIC_SORT_DIRECTION.get(metric, "ascending"),
                "client_threads": client_threads,
                "congestion_controller": congestion_controller,
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
                float(row["sort_p50"]) if row["sort_p50"] else unsupported_sentinel,
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
    run_dir: Path,
) -> str:
    summary_rows = [
        row
        for row in read_tsv(run_dir / "publication-results.tsv")
        if row.get("binary") != "tcpperf"
    ]
    publishable_rows = sum(1 for row in summary_rows if row.get("publication_status") in {"publishable", "converged"})
    inconclusive_rows = sum(1 for row in summary_rows if row.get("publication_status") in {"inconclusive", "not_ready"})
    failed_rows = sum(1 for row in summary_rows if row.get("publication_status") == "failed")
    unsupported_rows = sum(1 for row in summary_rows if row.get("publication_status") == "unsupported")
    complete_rows = sum(1 for row in summary_rows if row.get("measurement_status") in {"complete", "converged", ""})
    run_status = "complete" if summary_rows and failed_rows == 0 and unsupported_rows == 0 else ("failed" if failed_rows else "partial")
    artifact_sentence = (
        "Raw QUIC data and gate details are committed under "
        f"[`{artifact_dir}`]({artifact_dir}/)."
    )

    lines = [
        "# Latest Results",
        "",
        (
            "The publication runner uses a predeclared plan: scout data selects "
            "client threads, then fixed randomized publication blocks collect the "
            "measured samples without adaptive extension."
        ),
        "",
        (
            "Tables are sorted by p50, the publication statistic. p90 and p99 "
            "remain diagnostic tail-visibility columns unless a separate tail "
            "campaign has enough samples to claim them."
        ),
        "",
        (
            f"Current run status: `{run_status}`. The run completed {complete_rows} "
            f"of {len(summary_rows)} selected rows: {publishable_rows} publishable, "
            f"{inconclusive_rows} inconclusive/noisy, {failed_rows} failed, and "
            f"{unsupported_rows} unsupported."
        ),
        "",
        (
            "All completed selected rows are shown below. `inconclusive` means "
            "the row completed but tripped at least one audit gate; it is data "
            "with a visible caveat, not a failed or hidden row."
        ),
        "",
        artifact_sentence,
        "",
        "## Results",
        "",
    ]

    for benchmark, benchmark_rows in grouped_by_benchmark(rows):
        heading = benchmark if benchmark.startswith("0-RTT") else benchmark.title()
        lines.extend(
            [
                f"### {heading}",
                "",
                BENCHMARK_SUMMARIES.get(benchmark_rows[0]["scenario"], ""),
                "",
                (
                    "| Library | Network | CC | Client threads | Samples | "
                    "Status | Unit | p50 | p90 | p99 |"
                ),
                "|---|---|---|---:|---:|---|---|---:|---:|---:|",
            ]
        )
        for row in benchmark_rows:
            lines.append(
                "| {library} | {network} | {congestion_controller} | {client_threads} | "
                "{samples} | {status} | {unit} | {p50} | {p90} | {p99} |".format(**row)
            )
        lines.append("")

    lines.extend(
        [
            "## Caveats",
            "",
            "- Scout samples choose workload shape and client threads; they are excluded from publication statistics.",
            "- A completed row with CI, spread, or drift problems is inconclusive/noisy, not extended in the same run.",
            "- DATAGRAM rows report delivered unique echo rate; delivery/loss counters are in the raw sample TSV.",
            "- `idle_footprint` reports server RSS delta per connection, where lower is better.",
            (
                "- Row-level caveats and full gate reasons are in "
                f"[`publication-results.tsv`]({artifact_dir}/publication-results.tsv), "
                f"[`row-stats.tsv`]({artifact_dir}/row-stats.tsv), "
                f"[`publication-row-audit.tsv`]({artifact_dir}/publication-row-audit.tsv), "
                f"and [`benchmark-plan.tsv`]({artifact_dir}/benchmark-plan.tsv)."
            ),
            f"- Raw samples are in [`adaptive-samples.tsv`]({artifact_dir}/adaptive-samples.tsv).",
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
    args = parser.parse_args()

    rows = load_rows(args.run_dir)
    args.markdown.write_text(
        render_markdown(rows, args.artifact_dir, args.run_dir) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
