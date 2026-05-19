#!/usr/bin/env python3
import argparse
import csv
import sys
from pathlib import Path

from quicperf_stats import bad_tail_quantile, flat_bootstrap_ci, median, parse_client_log_samples, quantile, stable_seed

def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def fnum(row: dict[str, str], key: str) -> float:
    try:
        return float(row.get(key, "0") or "0")
    except ValueError:
        return 0.0


def inum(row: dict[str, str], key: str) -> int:
    try:
        return int(row.get(key, "0") or "0")
    except ValueError:
        return 0


def max_metric_row(rows: list[dict[str, str]], key: str) -> dict[str, str] | None:
    candidates = [row for row in rows if row.get(key)]
    return max(candidates, key=lambda row: fnum(row, key), default=None)


def raw_values(out_dir: Path, expected_metric: str) -> list[float]:
    values = []
    for path in sorted(out_dir.glob("*.client.log")):
        if ".warmup." in path.name:
            continue
        for sample in parse_client_log_samples(path):
            if sample.metric == expected_metric and sample.value is not None:
                values.append(sample.value)
    return values


def path_profile(row: dict[str, str]) -> str:
    return row.get("path_profile", "loopback") or "loopback"


def sample_lookup(samples_path: Path) -> tuple[dict[tuple[str, str, str, str, str], dict[str, str]], list[dict[str, str]]]:
    rows = {}
    if not samples_path.exists():
        return rows, []
    all_rows = read_rows(samples_path)
    for row in all_rows:
        rows[(row["binary"], row["scenario"], row["network"], path_profile(row), row["threads"])] = row
    return rows, all_rows


def curve_role(row_threads: int, selected_threads: int, boundary_threads: int) -> str:
    roles = []
    if row_threads == 1:
        roles.append("baseline_1c1s")
    if selected_threads and row_threads < selected_threads:
        roles.append("pre_saturation")
    if selected_threads and row_threads == selected_threads:
        roles.append("selected_saturation")
    if boundary_threads and row_threads == boundary_threads and row_threads != selected_threads:
        roles.append("saturation_boundary")
    if selected_threads and boundary_threads and selected_threads < row_threads < boundary_threads:
        roles.append("post_selected")
    return "+".join(roles) if roles else "curve"


def audit_sweep(root: Path, args: argparse.Namespace) -> tuple[Path, bool, list[dict[str, str]]]:
    summary_path = root / "saturation-summary.tsv"
    if not summary_path.exists():
        raise FileNotFoundError(summary_path)

    samples, sample_rows = sample_lookup(root / "saturation-samples.tsv")
    rows = []
    curve_rows = []
    result_rows = []
    ready = True
    for selected in read_rows(summary_path):
        binary = selected["binary"]
        scenario = selected["scenario"]
        network = selected["network"]
        profile = path_profile(selected)
        status = selected["status"]
        metric = selected.get("metric", "")
        threads = selected.get("selected_threads", "")

        allowed_unsupported = binary == "tcpperf" and network == "iouring"
        if status == "unsupported" and allowed_unsupported:
            unsupported_note = "allowed_sidecar_unsupported"
            audit_row = {
                "sweep": root.name,
                "binary": binary,
                "scenario": scenario,
                "network": network,
                "path_profile": profile,
                "selection_status": status,
                "row_status": status,
                "publication_role": "sidecar",
                "metric": metric,
                "row_threads": threads,
                "selected_threads": threads,
                "samples": "0",
                "p50": "",
                "p50_ci95_low": "",
                "p50_ci95_high": "",
                "p50_ci95_relative_width": "",
                "spread_low_pct": "",
                "spread_high_pct": "",
                "spread_low": "",
                "spread_high": "",
                "middle_spread_ratio": "",
                "min": "",
                "max": "",
                "minmax_spread_ratio": "",
                "publication_status": unsupported_note,
                "reason": selected.get("reason", ""),
            }
            rows.append(audit_row)
            result_rows.append({
                "binary": binary,
                "scenario": scenario,
                "network": network,
                "path_profile": profile,
                "selection_status": status,
                "publication_status": unsupported_note,
                "metric": metric,
                "selected_threads": threads,
                "selected_samples": selected.get("selected_samples", ""),
                "selected_p50": selected.get("selected_p50", ""),
                "selected_p90": selected.get("selected_p90", ""),
                "selected_p99": selected.get("selected_p99", ""),
                "best_threads": selected.get("best_threads", ""),
                "best_p50": selected.get("best_p50", ""),
                "audited_rows": "0",
                "not_ready_rows": "0",
                "spread_low_pct": "",
                "spread_high_pct": "",
                "selected_p50_ci95_relative_width": "",
                "selected_middle_spread_ratio": "",
                "selected_spread_low": "",
                "selected_spread_high": "",
                "max_audited_p50_ci95_relative_width": "",
                "max_audited_p50_ci95_row_threads": "",
                "max_audited_middle_spread_ratio": "",
                "max_audited_middle_spread_row_threads": "",
                "reason": selected.get("reason", ""),
            })
            continue

        key = (binary, scenario, network, profile, threads)
        selected_thread = inum(selected, "selected_threads")
        boundary_thread = inum(selected, "boundary_threads")
        curve_limit = max(1, selected_thread, boundary_thread)
        display_samples = [
            row for row in sample_rows
            if row["binary"] == binary
            and row["scenario"] == scenario
            and row["network"] == network
            and path_profile(row) == profile
            and 1 <= inum(row, "threads") <= curve_limit
        ]
        if not display_samples and samples.get(key):
            display_samples = [samples[key]]

        for sample in sorted(display_samples, key=lambda row: inum(row, "threads")):
            row_threads = inum(sample, "threads")
            row_metric = sample.get("metric") or metric
            row_status = sample.get("status", status)
            out_dir = Path(sample.get("out_dir", "")) if sample else Path()
            if out_dir and not out_dir.is_absolute():
                out_dir = Path.cwd() / out_dir
            values = raw_values(out_dir, row_metric) if out_dir and row_metric else []
            values.sort()

            p50 = quantile(values, 0.50) if values else fnum(sample, "p50")
            p90 = bad_tail_quantile(values, 0.90, row_metric) if values else fnum(sample, "p90")
            p99 = bad_tail_quantile(values, 0.99, row_metric) if values else fnum(sample, "p99")
            spread_low = quantile(values, args.spread_low_pct / 100.0) if values else 0.0
            spread_high = quantile(values, args.spread_high_pct / 100.0) if values else 0.0
            ci_low, ci_high = flat_bootstrap_ci(values, median, args.bootstrap_iterations, stable_seed([binary, scenario, network, profile, row_threads, "curve"])) if values else (0.0, 0.0)
            ci_width = ((ci_high - ci_low) / p50) if values and p50 > 0 else 0.0
            middle_spread = (spread_high / spread_low) if spread_low > 0 else 0.0

            reasons = []
            if row_status not in ("ok", "plateau"):
                reasons.append(f"row_status_{row_status}")
            if values and ci_width > args.max_ci_relative_width:
                reasons.append(f"p50_ci_width_{ci_width:.3f}_gt_{args.max_ci_relative_width:.3f}")
            if values and middle_spread > args.max_middle_spread_ratio:
                reasons.append(f"middle_spread_{middle_spread:.3f}_gt_{args.max_middle_spread_ratio:.3f}")

            curve_rows.append({
                "binary": binary,
                "scenario": scenario,
                "network": network,
                "path_profile": profile,
                "selection_status": status,
                "metric": row_metric,
                "client_threads": str(row_threads),
                "curve_role": curve_role(row_threads, selected_thread, boundary_thread),
                "row_status": row_status,
                "samples": str(len(values) if values else inum(sample, "samples")),
                "p50": f"{p50:.6f}" if p50 else "",
                "p90": f"{p90:.6f}" if p90 else "",
                "p99": f"{p99:.6f}" if p99 else "",
                "p50_ci95_relative_width": f"{ci_width:.6f}" if values else "",
                "spread_low_pct": f"{args.spread_low_pct:.1f}" if values else "",
                "spread_high_pct": f"{args.spread_high_pct:.1f}" if values else "",
                "spread_low": f"{spread_low:.6f}" if values else "",
                "spread_high": f"{spread_high:.6f}" if values else "",
                "middle_spread_ratio": f"{middle_spread:.6f}" if values else "",
                "selected_threads": str(selected_thread) if selected_thread else "",
                "best_threads": selected.get("best_threads", ""),
                "boundary_threads": str(boundary_thread) if boundary_thread else "",
                "boundary_status": selected.get("boundary_status", ""),
                "publication_status": "ready" if not reasons else "not_ready",
                "reason": ";".join(reasons),
            })

        rows_to_audit = [
            row for row in sample_rows
            if row["binary"] == binary
            and row["scenario"] == scenario
            and row["network"] == network
            and path_profile(row) == profile
            and int(row.get("threads", "0") or "0") <= selected_thread
            and row.get("status") in ("ok", "plateau")
        ]
        if not rows_to_audit and samples.get(key):
            rows_to_audit = [samples[key]]
        if not rows_to_audit:
            rows_to_audit = [{"threads": threads, "status": status, "out_dir": ""}]

        result_audit_rows = []
        for sample in rows_to_audit:
            row_threads = sample.get("threads", threads)
            row_status = sample.get("status", status)
            publication_role = "selected" if row_threads == threads else "curve"
            out_dir = Path(sample.get("out_dir", "")) if sample else Path()
            if out_dir and not out_dir.is_absolute():
                out_dir = Path.cwd() / out_dir
            values = raw_values(out_dir, metric) if out_dir else []
            values.sort()

            reasons = []
            if status not in ("ok", "plateau"):
                reasons.append(f"selection_status_{status}")
            if row_status not in ("ok", "plateau"):
                reasons.append(f"row_status_{row_status}")
            if len(values) < args.min_samples:
                reasons.append(f"samples_{len(values)}_lt_{args.min_samples}")

            p50 = quantile(values, 0.50)
            spread_low = quantile(values, args.spread_low_pct / 100.0)
            spread_high = quantile(values, args.spread_high_pct / 100.0)
            ci_low, ci_high = flat_bootstrap_ci(values, median, args.bootstrap_iterations, stable_seed([binary, scenario, network, profile, row_threads]))
            ci_width = ((ci_high - ci_low) / p50) if p50 > 0 else 0.0
            middle_spread = (spread_high / spread_low) if spread_low > 0 else 0.0
            minmax_spread = (values[-1] / values[0]) if values and values[0] > 0 else 0.0

            if p50 > 0 and ci_width > args.max_ci_relative_width:
                reasons.append(f"p50_ci_width_{ci_width:.3f}_gt_{args.max_ci_relative_width:.3f}")
            if middle_spread > args.max_middle_spread_ratio:
                reasons.append(f"middle_spread_{middle_spread:.3f}_gt_{args.max_middle_spread_ratio:.3f}")

            publication_status = "ready" if not reasons else "not_ready"
            if reasons:
                ready = False

            audit_row = {
                "sweep": root.name,
                "binary": binary,
                "scenario": scenario,
                "network": network,
                "path_profile": profile,
                "selection_status": status,
                "row_status": row_status,
                "publication_role": publication_role,
                "metric": metric,
                "row_threads": row_threads,
                "selected_threads": threads,
                "samples": str(len(values)),
                "p50": f"{p50:.6f}" if values else "",
                "p50_ci95_low": f"{ci_low:.6f}" if values else "",
                "p50_ci95_high": f"{ci_high:.6f}" if values else "",
                "p50_ci95_relative_width": f"{ci_width:.6f}" if values else "",
                "spread_low_pct": f"{args.spread_low_pct:.1f}" if values else "",
                "spread_high_pct": f"{args.spread_high_pct:.1f}" if values else "",
                "spread_low": f"{spread_low:.6f}" if values else "",
                "spread_high": f"{spread_high:.6f}" if values else "",
                "middle_spread_ratio": f"{middle_spread:.6f}" if values else "",
                "min": f"{values[0]:.6f}" if values else "",
                "max": f"{values[-1]:.6f}" if values else "",
                "minmax_spread_ratio": f"{minmax_spread:.6f}" if values else "",
                "publication_status": publication_status,
                "reason": ";".join(reasons),
            }
            rows.append(audit_row)
            result_audit_rows.append(audit_row)

        selected_audit = next((row for row in result_audit_rows if row["publication_role"] == "selected"), None)
        not_ready_rows = [row for row in result_audit_rows if row["publication_status"] == "not_ready"]
        max_ci = max_metric_row(result_audit_rows, "p50_ci95_relative_width")
        max_middle = max_metric_row(result_audit_rows, "middle_spread_ratio")
        result_ready = not not_ready_rows and status in ("ok", "plateau")
        result_rows.append({
            "binary": binary,
            "scenario": scenario,
            "network": network,
            "path_profile": profile,
            "selection_status": status,
            "publication_status": "ready" if result_ready else "not_ready",
            "metric": metric,
            "selected_threads": threads,
            "selected_samples": selected.get("selected_samples", ""),
            "selected_p50": selected.get("selected_p50", ""),
            "selected_p90": selected.get("selected_p90", ""),
            "selected_p99": selected.get("selected_p99", ""),
            "best_threads": selected.get("best_threads", ""),
            "best_p50": selected.get("best_p50", ""),
            "audited_rows": str(len(result_audit_rows)),
            "not_ready_rows": str(len(not_ready_rows)),
            "spread_low_pct": selected_audit.get("spread_low_pct", "") if selected_audit else "",
            "spread_high_pct": selected_audit.get("spread_high_pct", "") if selected_audit else "",
            "selected_p50_ci95_relative_width": selected_audit.get("p50_ci95_relative_width", "") if selected_audit else "",
            "selected_middle_spread_ratio": selected_audit.get("middle_spread_ratio", "") if selected_audit else "",
            "selected_spread_low": selected_audit.get("spread_low", "") if selected_audit else "",
            "selected_spread_high": selected_audit.get("spread_high", "") if selected_audit else "",
            "max_audited_p50_ci95_relative_width": max_ci.get("p50_ci95_relative_width", "") if max_ci else "",
            "max_audited_p50_ci95_row_threads": max_ci.get("row_threads", "") if max_ci else "",
            "max_audited_middle_spread_ratio": max_middle.get("middle_spread_ratio", "") if max_middle else "",
            "max_audited_middle_spread_row_threads": max_middle.get("row_threads", "") if max_middle else "",
            "reason": ";".join(
                f"{row['publication_role']}:t{row['row_threads']}:{row['reason']}"
                for row in not_ready_rows
                if row.get("reason")
            ),
            })
        continue

    curve_path = root / "publication-curve.tsv"
    curve_fields = [
        "binary",
        "scenario",
        "network",
        "path_profile",
        "selection_status",
        "metric",
        "client_threads",
        "curve_role",
        "row_status",
        "samples",
        "p50",
        "p90",
        "p99",
        "p50_ci95_relative_width",
        "spread_low_pct",
        "spread_high_pct",
        "spread_low",
        "spread_high",
        "middle_spread_ratio",
        "selected_threads",
        "best_threads",
        "boundary_threads",
        "boundary_status",
        "publication_status",
        "reason",
    ]
    with curve_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=curve_fields)
        writer.writeheader()
        writer.writerows(curve_rows)

    audit_path = root / "publication-row-audit.tsv"
    fields = [
        "sweep",
        "binary",
        "scenario",
        "network",
        "path_profile",
        "selection_status",
        "row_status",
        "publication_role",
        "metric",
        "row_threads",
        "selected_threads",
        "samples",
        "p50",
        "p50_ci95_low",
        "p50_ci95_high",
        "p50_ci95_relative_width",
        "spread_low_pct",
        "spread_high_pct",
        "spread_low",
        "spread_high",
        "middle_spread_ratio",
        "min",
        "max",
        "minmax_spread_ratio",
        "publication_status",
        "reason",
    ]
    with audit_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    results_path = root / "publication-results.tsv"
    result_fields = [
        "binary",
        "scenario",
        "network",
        "path_profile",
        "selection_status",
        "publication_status",
        "metric",
        "selected_threads",
        "selected_samples",
        "selected_p50",
        "selected_p90",
        "selected_p99",
        "best_threads",
        "best_p50",
        "audited_rows",
        "not_ready_rows",
        "spread_low_pct",
        "spread_high_pct",
        "selected_p50_ci95_relative_width",
        "selected_middle_spread_ratio",
        "selected_spread_low",
        "selected_spread_high",
        "max_audited_p50_ci95_relative_width",
        "max_audited_p50_ci95_row_threads",
        "max_audited_middle_spread_ratio",
        "max_audited_middle_spread_row_threads",
        "reason",
    ]
    with results_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=result_fields)
        writer.writeheader()
        writer.writerows(result_rows)

    bad = [row for row in rows if row["publication_status"] == "not_ready"]
    bad_results = [row for row in result_rows if row["publication_status"] == "not_ready"]
    summary_path = root / "publication-summary.md"
    with summary_path.open("w", encoding="utf-8") as handle:
        handle.write("# Publication Audit\n\n")
        handle.write(f"- Status: {'ready' if ready else 'not_ready'}\n")
        handle.write(f"- Min samples: {args.min_samples}\n")
        handle.write(f"- Max p50 CI relative width: {args.max_ci_relative_width:.3f}\n")
        handle.write(f"- Middle spread band: p{args.spread_low_pct:.1f}/p{args.spread_high_pct:.1f}\n")
        handle.write(f"- Max middle spread ratio: {args.max_middle_spread_ratio:.3f}\n")
        handle.write(f"- Rows audited: {len(rows)}\n")
        handle.write(f"- Rows not ready: {len(bad)}\n")
        handle.write(f"- Result rows not ready: {len(bad_results)}\n")
        handle.write(f"- Client-count curve table: `{curve_path.name}`\n")
        handle.write(f"- Result stability table: `{results_path.name}`\n")
        if bad:
            handle.write("\n## Not Ready Rows\n\n")
            handle.write("| Binary | Scenario | Network | Path | Row | Role | Samples | p50 CI width | p80/p20 | Reason |\n")
            handle.write("|---|---|---|---|---:|---|---:|---:|---:|---|\n")
            for row in bad:
                handle.write(
                    f"| `{row['binary']}` | `{row['scenario']}` | `{row['network']}` | `{row.get('path_profile', 'loopback')}` | "
                    f"{row['row_threads']} | {row['publication_role']} | {row['samples']} | "
                    f"{row['p50_ci95_relative_width']} | {row['middle_spread_ratio']} | "
                    f"{row['reason']} |\n"
                )

    return audit_path, ready, rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sweep", nargs="+", type=Path)
    parser.add_argument("--min-samples", type=int, default=10)
    parser.add_argument("--max-ci-relative-width", type=float, default=0.20)
    parser.add_argument("--max-middle-spread-ratio", type=float, default=2.00)
    parser.add_argument("--spread-low-pct", type=float, default=20.0)
    parser.add_argument("--spread-high-pct", type=float, default=80.0)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--fail-on-not-ready", action="store_true")
    args = parser.parse_args()

    all_ready = True
    for sweep in args.sweep:
        audit_path, ready, _ = audit_sweep(sweep, args)
        print(f"publication_audit path={audit_path} status={'ready' if ready else 'not_ready'}")
        all_ready = all_ready and ready
    return 1 if args.fail_on_not_ready and not all_ready else 0


if __name__ == "__main__":
    raise SystemExit(main())
