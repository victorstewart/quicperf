#!/usr/bin/env python3
"""Validate and publish the one qualified quicperf V2.3 campaign."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
from typing import Any, Mapping


CAMPAIGN_ID = "ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492"
SOURCE_COMMIT = "44250d751e650f11f620733aa6e5d0498f947d12"
SOURCE_TREE = "a72228525e2f09fabd0b01cee4888e201a376ef4"
SOURCE_ARCHIVE_SHA256 = (
    "89f1ba46539f3a881f088ed0495ab441c04c165a7fa85db7da650c6981e41fd8"
)
SERVERS = (
    "ngtcp2perf",
    "lsperf",
    "tquicperf",
    "quicheperf",
    "picoperf",
    "xquicperf",
    "quinnperf",
    "s2nperf",
    "neqoperf",
    "noqperf",
    "quiczigperf",
    "mvfstperf",
)
SCENARIOS = (
    "download",
    "upload",
    "multistream_download",
    "multistream_upload",
    "bidi",
    "small_payload_pps",
    "datagram",
    "reqresp",
    "stream_churn",
    "connect",
    "resumed_connect",
    "zero_rtt_reqresp",
    "loss_recovery",
    "flow_control",
    "close_reset_cleanup",
)
SCENARIO_TITLES = {
    "download": "Download",
    "upload": "Upload",
    "multistream_download": "Multi-stream download",
    "multistream_upload": "Multi-stream upload",
    "bidi": "Bidirectional transfer",
    "small_payload_pps": "Small-payload packet rate",
    "datagram": "QUIC DATAGRAM",
    "reqresp": "Request/response",
    "stream_churn": "Stream churn",
    "connect": "Connection setup",
    "resumed_connect": "Resumed connection setup",
    "zero_rtt_reqresp": "0-RTT request/response",
    "loss_recovery": "Loss recovery",
    "flow_control": "Flow control",
    "close_reset_cleanup": "Close/reset cleanup",
}
CLIENTS = ("ngtcp2perf", "picoperf")
EXECUTION_DATE = "2026-07-29–30 (America/New_York)"
MAX_PUBLIC_FILE_BYTES = 10 * 1024 * 1024
ASSET_NAMES = (
    "quicperf-v2.3-ca3fc476-full-run.tar.zst",
    "quicperf-v2.3-ca3fc476-samples.tsv.zst",
    "quicperf-v2.3-ca3fc476-executed-source.tar.zst",
)

# campaign-relative source -> public-bundle-relative destination
COPIED_FILES = {
    "status.json": "status.json",
    "artifacts/analysis.json": "analysis.json",
    "manifest.json": "manifest.json",
    "spec.json": "spec.json",
    "artifacts/row-results.tsv": "row-results.tsv",
    "artifacts/comparisons.tsv": "comparisons.tsv",
    "artifacts/scenario-coverage.tsv": "scenario-coverage.tsv",
    "artifacts/quality-audit.tsv": "quality-audit.tsv",
    "artifacts/cleanup-strata.tsv": "cleanup-strata.tsv",
    "artifacts/checksums.sha256": "export-checksums.sha256",
    "artifacts/qualification/client-headroom.json": "qualification/client-headroom.json",
    "artifacts/qualification/host-stability.json": "qualification/host-stability.json",
    "artifacts/qualification/native-interoperability.json": (
        "qualification/native-interoperability.json"
    ),
    "artifacts/runtime/planning.json": "runtime/planning.json",
    "artifacts/runtime/session-1.json": "runtime/session-1.json",
    "artifacts/runtime/session-2.json": "runtime/session-2.json",
    "artifacts/runtime/render.json": "runtime/render.json",
}


class PublicationError(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicationError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise PublicationError(f"expected JSON object: {path}")
    return value


def _rows(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as stream:
            return list(csv.DictReader(stream, delimiter="\t"))
    except (OSError, csv.Error) as exc:
        raise PublicationError(f"invalid TSV: {path}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if (
        not value
        or pure.is_absolute()
        or ".." in pure.parts
        or str(pure) != value
    ):
        raise PublicationError(f"unsafe checksum path: {value!r}")
    return Path(*pure.parts)


def _verify_export_checksums(campaign: Path, status: Mapping[str, Any]) -> None:
    artifact_root = campaign / "artifacts"
    expected = status.get("artifact_checksums")
    if not isinstance(expected, dict) or not expected:
        raise PublicationError("terminal status has no canonical artifact checksums")
    seen: dict[str, str] = {}
    checksum_path = artifact_root / "checksums.sha256"
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise PublicationError("malformed canonical checksum manifest")
        digest, name = match.groups()
        relative = _safe_relative(name)
        path = artifact_root / relative
        if path.is_symlink() or not path.is_file():
            raise PublicationError(f"canonical artifact missing or symlinked: {name}")
        if name in seen:
            raise PublicationError(f"duplicate canonical checksum entry: {name}")
        actual = _sha256(path)
        if actual != digest:
            raise PublicationError(f"canonical artifact checksum mismatch: {name}")
        seen[name] = digest
    normalized = {str(key): str(value) for key, value in expected.items()}
    if seen != normalized:
        raise PublicationError("checksum manifest and terminal status disagree")


def _require_repository_tree(repo_root: Path) -> None:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{SOURCE_TREE}^{{tree}}"],
        cwd=repo_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise PublicationError("public history lacks the exact executed Git tree")
    commits = subprocess.run(
        ["git", "rev-list", "HEAD"],
        cwd=repo_root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.splitlines()
    for commit in commits:
        tree = subprocess.run(
            ["git", "rev-parse", f"{commit}^{{tree}}"],
            cwd=repo_root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        if tree == SOURCE_TREE:
            return
    raise PublicationError("executed Git tree is not an ancestor of the review branch")


def _require_identity(campaign: Path, repo_root: Path) -> dict[str, Any]:
    status = _json(campaign / "status.json")
    analysis = _json(campaign / "artifacts" / "analysis.json")
    manifest = _json(campaign / "manifest.json")
    spec = _json(campaign / "spec.json")
    if (
        status.get("campaign_id") != CAMPAIGN_ID
        or status.get("finalization_status") != "publication_qualified"
        or status.get("finalized") is not True
        or status.get("publication_valid") is not True
        or status.get("committed_samples") != 4320
        or status.get("expected_samples") != 4320
        or status.get("finalization_reasons") != []
    ):
        raise PublicationError("campaign is not the exact qualified V2.3 result")
    sessions = status.get("sessions")
    if not isinstance(sessions, list) or [
        (row.get("session_number"), row.get("planned"), row.get("committed"), row.get("status"))
        for row in sessions
        if isinstance(row, dict)
    ] != [(1, 2160, 2160, "complete"), (2, 2160, 2160, "complete")]:
        raise PublicationError("terminal session cardinality is not exact")
    if (
        analysis.get("campaign_id") != CAMPAIGN_ID
        or analysis.get("schema_version") != "quicperf.analysis.v2.3"
        or analysis.get("complete") is not True
        or analysis.get("publication_valid") is not True
        or analysis.get("reasons") != []
    ):
        raise PublicationError("analysis is not the exact valid V2.3 analysis")
    source = manifest.get("source")
    if not isinstance(source, dict) or (
        source.get("git_commit"),
        source.get("archive_sha256"),
        source.get("clean"),
        source.get("dirty_patch"),
    ) != (SOURCE_COMMIT, SOURCE_ARCHIVE_SHA256, True, None):
        raise PublicationError("executed source identity does not match V2.3")
    methodology = spec.get("methodology")
    expected_cardinality = spec.get("expected_cardinality")
    backends = spec.get("backends")
    if (
        not isinstance(methodology, dict)
        or methodology.get("version") != "2.3"
        or spec.get("campaign_kind") != "publication"
        or spec.get("estimand") != "fixed_treatment_server"
        or expected_cardinality
        != {
            "committed_samples": 4320,
            "maximum_trial_ids": 8640,
            "planned_trials": 4320,
            "sessions": 2,
            "williams_rows": 12,
        }
        or backends != {"reference_client": "iouring", "server": ["iouring"]}
    ):
        raise PublicationError("experiment spec is not the frozen V2.3 design")
    _verify_export_checksums(campaign, status)
    _require_repository_tree(repo_root)
    return {
        "status": status,
        "analysis": analysis,
        "manifest": manifest,
        "spec": spec,
    }


def _require_cardinality(campaign: Path) -> dict[str, Any]:
    artifact_root = campaign / "artifacts"
    quality = _rows(artifact_root / "quality-audit.tsv")
    if len(quality) != 4320:
        raise PublicationError("quality audit must contain exactly 4,320 rows")
    required = {
        "session",
        "server",
        "reference_client",
        "server_backend",
        "scenario",
        "outcome",
        "validity_reasons",
    }
    if not quality or not required.issubset(quality[0]):
        raise PublicationError("quality audit columns are incomplete")
    if any(
        row["outcome"] != "valid"
        or row["validity_reasons"]
        or row["server_backend"] != "iouring"
        or row["server"] not in SERVERS
        or row["scenario"] not in SCENARIOS
        or row["reference_client"] not in CLIENTS
        or row["session"] not in {"1", "2"}
        for row in quality
    ):
        raise PublicationError("quality audit contains a non-V2.3 or invalid row")
    if Counter(row["session"] for row in quality) != {"1": 2160, "2": 2160}:
        raise PublicationError("quality audit session balance is not exact")
    if Counter(row["reference_client"] for row in quality) != {
        "ngtcp2perf": 2160,
        "picoperf": 2160,
    }:
        raise PublicationError("reference-client balance is not 2,160/2,160")
    cell_counts = Counter(
        (row["server"], row["scenario"], row["server_backend"]) for row in quality
    )
    if (
        len(cell_counts) != 180
        or set(cell_counts) != {
            (server, scenario, "iouring")
            for server in SERVERS
            for scenario in SCENARIOS
        }
        or set(cell_counts.values()) != {24}
    ):
        raise PublicationError("retained cell cardinality is not 180 × 24")
    session_cells = Counter(
        (row["session"], row["server"], row["scenario"], row["reference_client"])
        for row in quality
    )
    if len(session_cells) != 720 or set(session_cells.values()) != {6}:
        raise PublicationError("per-session reference-client pairing is not exact")
    rows = _rows(artifact_root / "row-results.tsv")
    if (
        len(rows) != 180
        or any(
            row["planned"] != "24"
            or row["committed"] != "24"
            or row["valid"] != "24"
            or row["status"] != "complete"
            or row["server_backend"] != "iouring"
            for row in rows
        )
    ):
        raise PublicationError("row-results cardinality is not 180 complete cells")
    return {"quality": quality, "rows": rows}


def _require_qualifications(campaign: Path, manifest: Mapping[str, Any]) -> None:
    qualification = campaign / "artifacts/qualification"
    for kind in ("host-stability", "client-headroom"):
        artifact = _json(qualification / f"{kind}.json")
        if (
            artifact.get("artifact_kind") != kind
            or artifact.get("status") != "qualified"
            or artifact.get("qualified") is not True
            or artifact.get("reasons") != []
        ):
            raise PublicationError(f"required qualification is not exact: {kind}")
    interoperability = _json(qualification / "native-interoperability.json")
    if (
        interoperability.get("status") != "PASS"
        or interoperability.get("passed") != 180
        or interoperability.get("failed") != 0
        or len(interoperability.get("records", [])) != 180
    ):
        raise PublicationError("native interoperability is not 180/180 PASS")
    host = manifest.get("host_policy")
    if not isinstance(host, dict) or (
        host.get("governor"),
        host.get("epp"),
        host.get("turbo"),
        host.get("frequency_min_khz"),
        host.get("frequency_max_khz"),
    ) != ("performance", "performance", False, "3800000", "3800000"):
        raise PublicationError("published host policy is not the qualified policy")


def _temperature_max(path: Path) -> int:
    maximum = -1
    tail = b""
    pattern = re.compile(br'"tctl_millicelsius":([0-9]+)')
    with path.open("rb") as stream:
        while block := stream.read(4 * 1024 * 1024):
            data = tail + block
            values = [int(value) for value in pattern.findall(data)]
            if values:
                maximum = max(maximum, *values)
            tail = data[-64:]
    if maximum < 0:
        raise PublicationError(f"no Tctl observations in {path.name}")
    return maximum


def _asset_metadata(asset_dir: Path | None) -> dict[str, Any]:
    assets: list[dict[str, Any]] = []
    sums: dict[str, str] = {}
    if asset_dir is not None:
        manifest = asset_dir / "SHA256SUMS"
        for line in manifest.read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
            if match is None:
                raise PublicationError("malformed release-asset SHA256SUMS")
            digest, name = match.groups()
            sums[name] = digest
        if set(sums) != set(ASSET_NAMES):
            raise PublicationError("release-asset checksum inventory is not exact")
    for name in ASSET_NAMES:
        entry: dict[str, Any] = {"name": name}
        if asset_dir is not None:
            path = asset_dir / name
            if not path.is_file() or path.is_symlink() or _sha256(path) != sums[name]:
                raise PublicationError(f"release asset is missing or corrupt: {name}")
            entry.update({"bytes": path.stat().st_size, "sha256": sums[name]})
        else:
            entry.update({"bytes": None, "sha256": None})
        assets.append(entry)
    return {
        "schema_version": "quicperf.release-assets.v1",
        "campaign_id": CAMPAIGN_ID,
        "executed_source_commit": SOURCE_COMMIT,
        "executed_git_tree": SOURCE_TREE,
        "manifest_source_archive_sha256": SOURCE_ARCHIVE_SHA256,
        "assets": assets,
    }


def _human_rate(metric: str, value: float) -> str:
    if metric == "validated_body_bits_per_second":
        return f"{value / 1_000_000_000:.3f} Gbit/s"
    return f"{value:,.1f} operations/s"


def _label(value: str) -> str:
    return value.replace("_", " ")


def _scenario_title(scenario: str) -> str:
    return SCENARIO_TITLES[scenario]


def _scenario_pages(
    rows: list[dict[str, str]], comparisons: list[dict[str, str]]
) -> tuple[str, dict[str, str]]:
    baseline = {
        (item["family"].split("|")[1], item["contrast"].split("/")[0]): item
        for item in comparisons
        if item["comparison_family"] == "baseline"
    }
    line_number = {
        (row["server"], row["scenario"]): index
        for index, row in enumerate(rows, start=2)
    }
    pages: dict[str, str] = {}
    navigation = ["## Scenario results", ""]
    for scenario in SCENARIOS:
        scenario_rows = [row for row in rows if row["scenario"] == scenario]
        scenario_rows.sort(key=lambda row: float(row["geometric_mean"]), reverse=True)
        metric = scenario_rows[0]["metric"]
        lines = [
            f"# {_scenario_title(scenario)}",
            "",
            "Primary estimand: one isolated server core, 16 active connections, "
            "four client cores, and the equal reference-client mixture.",
            "",
            "| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |",
            "|---|---:|---:|---|---|---|---|---|",
        ]
        for row in scenario_rows:
            server = row["server"]
            if server == "ngtcp2perf":
                ratio = "1.000 (baseline)"
                classification = "baseline"
                variance = "baseline"
                client = "baseline"
                session = "baseline"
            else:
                comparison = baseline[(scenario, server)]
                ratio = (
                    f"{float(comparison['point_ratio']):.3f} "
                    f"[{float(comparison['low_ratio']):.3f}, "
                    f"{float(comparison['high_ratio']):.3f}]"
                )
                classification = _label(comparison["classification"])
                variance = (
                    "planning envelope missed"
                    if comparison["variance_miss"] == "1"
                    else "within planning envelope"
                )
                client = _label(comparison["client_sensitivity"])
                session = _label(comparison["session_sensitivity"])
            machine = f"../row-results.tsv#L{line_number[(server, scenario)]}"
            lines.append(
                f"| `{server}` | {_human_rate(metric, float(row['geometric_mean']))} "
                f"| {ratio} | {classification} | {variance} | {client} | {session} "
                f"| [TSV]({machine}) |"
            )
        lines.extend(
            [
                "",
                "Ratios are implementation/ngtcp2perf. Interpret them with the "
                "classification and sensitivity columns; this table is not a "
                "cross-scenario leaderboard.",
                "",
            ]
        )
        pages[f"scenarios/{scenario}.md"] = "\n".join(lines)
        navigation.append(
            f"- [{_scenario_title(scenario)}](scenarios/{scenario}.md)"
        )
    navigation.append("")
    return "\n".join(navigation), pages


def _latest(
    runtime1: Mapping[str, Any],
    runtime2: Mapping[str, Any],
    render: Mapping[str, Any],
    classifications: Counter[str],
    temperatures: tuple[int, int],
    retries: Counter[str],
    manifest: Mapping[str, Any],
) -> str:
    r1 = runtime1["runtime"]
    r2 = runtime2["runtime"]
    rr = render["runtime"]
    host = manifest["host_policy"]
    scenario_links = "\n".join(
        f"- [{_scenario_title(scenario)}]"
        f"(results/v2/{CAMPAIGN_ID}/scenarios/{scenario}.md)"
        for scenario in SCENARIOS
    )
    return f"""# Latest qualified results

Campaign [`{CAMPAIGN_ID}`](results/v2/{CAMPAIGN_ID}/README.md) is
`publication_qualified`.

- Executed: {EXECUTION_DATE}
- Source: `{SOURCE_COMMIT}`; exact Git tree `{SOURCE_TREE}`
- Host: {host['cpu_model']}; turbo {'enabled' if host['turbo'] else 'disabled'};
  {int(host['frequency_min_khz']) / 1_000_000:g} GHz
  `{host['governor']}`/`{host['epp']}` policy
- Treatment: one `iouring` server core, four client cores, exactly 16 active
  connections, 50/50 `ngtcp2perf`/`picoperf` reference-client mixture
- Matrix: 12 server implementations × 15 scenarios × 24 rows = 4,320/4,320
  valid samples
- Session walls: {r1['session_wall_ns'] / 1e9:.3f}s and
  {r2['session_wall_ns'] / 1e9:.3f}s (10,800s ceiling each)
- Maximum Tctl: {temperatures[0] / 1000:.3f}°C and
  {temperatures[1] / 1000:.3f}°C (80°C ceiling)
- Localized preallocated retries: {retries['1']} in session 1 and
  {retries['2']} in session 2
- Deterministic render: {rr['wall_ns'] / 1e9:.3f}s (60s ceiling)
- Simultaneous classifications: {classifications['superior']} superior,
  {classifications['inferior']} inferior, {classifications['equivalent']}
  equivalent, {classifications['inconclusive']} inconclusive
- Admission: 180/180 native interoperability, host stability qualified, and
  four-client-core headroom qualified

## Read the results

Use the [campaign page](results/v2/{CAMPAIGN_ID}/README.md) for
scenario-specific tables. There is deliberately no global leaderboard:
throughput and operation rates have different meanings across scenarios, and
reference-client or session sensitivity constrains some comparisons.

{scenario_links}

Compact machine-readable files are committed with the campaign page. Complete
raw evidence is prepared as release assets described in
[`release-assets.json`](results/v2/{CAMPAIGN_ID}/release-assets.json).

## Limitations

These results describe this host and exact fixed treatment. They do not estimate
capacity, memory scaling, long-tail latency, a syscall backend, or same-stack
client/server performance. GitHub Actions validates publication artifacts but
does not reproduce physical qualification.
"""


def _campaign_readme(navigation: str, classifications: Counter[str]) -> str:
    return f"""# quicperf V2.3 qualified campaign

Campaign `{CAMPAIGN_ID}` is the publication-qualified fixed-treatment server
benchmark produced by source `{SOURCE_COMMIT}` (Git tree `{SOURCE_TREE}`).

The primary estimand is server performance on one isolated physical core at
exactly 16 active connections, using four isolated client cores and an equal
50/50 mixture of the `ngtcp2perf` and `picoperf` reference clients. All 12
servers use the common C++ `iouring` UDP backend. Two independently started
sessions contribute 24 raw rows and 12 matching-session superblocks per
server/scenario family.

All 4,320 planned samples are valid. Exact 4,096 common-sign inference produced
{classifications['superior']} superior, {classifications['inferior']} inferior,
{classifications['equivalent']} equivalent, and
{classifications['inconclusive']} inconclusive pairwise classifications. These
counts span scenario-specific families and are not a global ranking.

{navigation}
## Machine-readable evidence

- [`row-results.tsv`](row-results.tsv): 180 retained server/scenario rows
- [`comparisons.tsv`](comparisons.tsv): simultaneous intervals and sensitivity
- [`quality-audit.tsv`](quality-audit.tsv): all 4,320 validity decisions
- [`scenario-coverage.tsv`](scenario-coverage.tsv): canonical capability audit
- [`status.json`](status.json), [`analysis.json`](analysis.json),
  [`manifest.json`](manifest.json), and [`spec.json`](spec.json): terminal
  qualification and identity
- [`public-bundle-manifest.json`](public-bundle-manifest.json): hashes and
  authoritative source paths for this compact bundle
- [`release-assets.json`](release-assets.json): full-evidence asset inventory

Dataset files are licensed under [CC BY 4.0](DATA-LICENSE.txt). Code remains
Apache-2.0. See [citation instructions](CITATION.md).
"""


def _citation() -> str:
    return f"""# Citation

Please cite the repository release and identify campaign `{CAMPAIGN_ID}`.

Suggested dataset citation:

> Stewart, Victor. *quicperf V2.3 fixed-treatment QUIC server benchmark*.
> Campaign `{CAMPAIGN_ID}`, 2026. CC BY 4.0.

Always retain the campaign ID, executed source commit `{SOURCE_COMMIT}`, and
exact Git tree `{SOURCE_TREE}` when redistributing derived tables.
"""


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _sync_tree(expected: Path, destination: Path) -> None:
    expected_files = {
        path.relative_to(expected)
        for path in expected.rglob("*")
        if path.is_file()
    }
    if destination.exists():
        for path in sorted(destination.rglob("*"), reverse=True):
            if path.is_symlink():
                raise PublicationError(f"refusing symlink in destination: {path}")
            if path.is_file() and path.relative_to(destination) not in expected_files:
                path.unlink()
            elif path.is_dir() and not any(path.iterdir()):
                path.rmdir()
    for relative in sorted(expected_files):
        source = expected / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def validate_committed_bundle(repo_root: Path, *, require_tree: bool = True) -> None:
    repo_root = repo_root.resolve()
    bundle = repo_root / "docs/results/v2" / CAMPAIGN_ID
    manifest = _json(bundle / "public-bundle-manifest.json")
    if (
        manifest.get("schema_version") != "quicperf.public-bundle.v1"
        or manifest.get("campaign_id") != CAMPAIGN_ID
        or manifest.get("executed_source_commit") != SOURCE_COMMIT
        or manifest.get("executed_git_tree") != SOURCE_TREE
        or manifest.get("manifest_source_archive_sha256")
        != SOURCE_ARCHIVE_SHA256
        or manifest.get("manifest_self_excluded") is not True
    ):
        raise PublicationError("committed public bundle identity is wrong")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise PublicationError("committed public bundle manifest is empty")
    expected: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "authoritative_source",
            "sha256",
        }:
            raise PublicationError("committed bundle manifest entry is malformed")
        name = str(entry["path"])
        relative = _safe_relative(name)
        if name in expected:
            raise PublicationError(f"duplicate committed bundle path: {name}")
        expected.add(name)
        path = bundle / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size >= MAX_PUBLIC_FILE_BYTES
            or _sha256(path) != entry["sha256"]
        ):
            raise PublicationError(f"committed bundle file is invalid: {name}")
    actual = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    if actual != expected | {"public-bundle-manifest.json"}:
        raise PublicationError("committed public bundle inventory is not exact")
    status = _json(bundle / "status.json")
    analysis = _json(bundle / "analysis.json")
    if (
        status.get("campaign_id") != CAMPAIGN_ID
        or status.get("finalization_status") != "publication_qualified"
        or status.get("publication_valid") is not True
        or status.get("committed_samples") != 4320
        or status.get("expected_samples") != 4320
        or analysis.get("campaign_id") != CAMPAIGN_ID
        or analysis.get("schema_version") != "quicperf.analysis.v2.3"
        or analysis.get("publication_valid") is not True
    ):
        raise PublicationError("committed bundle is not qualified V2.3")
    quality = _rows(bundle / "quality-audit.tsv")
    rows = _rows(bundle / "row-results.tsv")
    if len(quality) != 4320 or len(rows) != 180:
        raise PublicationError("committed bundle cardinality is incomplete")
    if Counter(row["session"] for row in quality) != {"1": 2160, "2": 2160}:
        raise PublicationError("committed bundle session balance is wrong")
    if Counter(row["reference_client"] for row in quality) != {
        "ngtcp2perf": 2160,
        "picoperf": 2160,
    }:
        raise PublicationError("committed bundle client balance is wrong")
    cells = Counter((row["server"], row["scenario"]) for row in quality)
    if len(cells) != 180 or set(cells.values()) != {24}:
        raise PublicationError("committed bundle cell cardinality is wrong")
    if require_tree:
        _require_repository_tree(repo_root)


def publish(
    campaign: Path,
    repo_root: Path,
    *,
    asset_dir: Path | None,
    check: bool,
) -> None:
    campaign = campaign.resolve()
    repo_root = repo_root.resolve()
    identities = _require_identity(campaign, repo_root)
    cardinality = _require_cardinality(campaign)
    _require_qualifications(campaign, identities["manifest"])
    comparisons = _rows(campaign / "artifacts" / "comparisons.tsv")
    classifications = Counter(row["classification"] for row in comparisons)
    if sum(classifications.values()) != 1155:
        raise PublicationError("comparison cardinality is not 1,155")
    schedule = _rows(campaign / "artifacts" / "schedule.tsv")
    retries = Counter(
        row["session"]
        for row in schedule
        if row["trial_state"] == "superseded_incomplete_microblock"
    )
    retries = Counter({session: count // 12 for session, count in retries.items()})
    if retries != {"1": 1, "2": 1}:
        raise PublicationError("localized retry history is not the qualified run")
    temperatures = (
        _temperature_max(
            campaign / "artifacts/qualification/host-stability-session-1.json"
        ),
        _temperature_max(
            campaign / "artifacts/qualification/host-stability-session-2.json"
        ),
    )
    runtime1 = _json(campaign / "artifacts/runtime/session-1.json")
    runtime2 = _json(campaign / "artifacts/runtime/session-2.json")
    render = _json(campaign / "artifacts/runtime/render.json")
    assets = _asset_metadata(asset_dir.resolve() if asset_dir is not None else None)

    with tempfile.TemporaryDirectory(prefix="quicperf-publish-v2.3-") as temporary:
        staging = Path(temporary)
        bundle = staging / "bundle"
        copied_entries: list[dict[str, Any]] = []
        for source_name, destination_name in sorted(COPIED_FILES.items()):
            source = campaign / source_name
            if source.is_symlink() or not source.is_file():
                raise PublicationError(f"allowlisted source missing: {source_name}")
            if source.stat().st_size >= MAX_PUBLIC_FILE_BYTES:
                raise PublicationError(f"allowlisted source is too large: {source_name}")
            destination = bundle / destination_name
            _write(destination, source.read_bytes())
            copied_entries.append(
                {
                    "path": destination_name,
                    "authoritative_source": source_name,
                    "sha256": _sha256(source),
                }
            )
        navigation, pages = _scenario_pages(cardinality["rows"], comparisons)
        generated = {
            "README.md": _campaign_readme(navigation, classifications),
            "CITATION.md": _citation(),
            "DATA-LICENSE.txt": (
                repo_root / "DATA-LICENSE"
            ).read_text(encoding="utf-8"),
            "release-assets.json": json.dumps(
                assets, sort_keys=True, separators=(",", ":")
            )
            + "\n",
            **pages,
        }
        for name, text in generated.items():
            _write(bundle / name, text.encode("utf-8"))
        entries = copied_entries + [
            {
                "path": name,
                "authoritative_source": f"generated:{name}",
                "sha256": _sha256(bundle / name),
            }
            for name in sorted(generated)
        ]
        public_manifest = {
            "schema_version": "quicperf.public-bundle.v1",
            "campaign_id": CAMPAIGN_ID,
            "executed_source_commit": SOURCE_COMMIT,
            "executed_git_tree": SOURCE_TREE,
            "manifest_source_archive_sha256": SOURCE_ARCHIVE_SHA256,
            "manifest_self_excluded": True,
            "files": sorted(entries, key=lambda item: item["path"]),
        }
        _write(
            bundle / "public-bundle-manifest.json",
            (
                json.dumps(public_manifest, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8"),
        )
        latest = _latest(
            runtime1,
            runtime2,
            render,
            classifications,
            temperatures,
            retries,
            identities["manifest"],
        )
        index_scenarios = "\n".join(
            f"- [{_scenario_title(scenario)}]"
            f"(results/v2/{CAMPAIGN_ID}/scenarios/{scenario}.md)"
            for scenario in SCENARIOS
        )
        index = f"""# quicperf

Publication-grade QUIC server benchmarking across 12 implementations using a
shared C++ I/O path, a fixed treatment, and paired simultaneous inference.

## Latest qualified campaign

[{CAMPAIGN_ID}](results/v2/{CAMPAIGN_ID}/README.md) contains 4,320/4,320 valid
V2.3 samples. Read the [result summary](latest-results.md), browse
[scenario-specific tables](results/v2/{CAMPAIGN_ID}/README.md), review the
[methodology](methodology.md), or follow the [operator guide](harness-v2.md).

There is no global leaderboard. Full raw evidence is distributed as release
assets; Git contains the compact qualified bundle only.

## Scenarios

{index_scenarios}

## Reproducibility and downloads

- [Compact bundle manifest](results/v2/{CAMPAIGN_ID}/public-bundle-manifest.json)
- [Prepared full-evidence asset inventory](results/v2/{CAMPAIGN_ID}/release-assets.json)
- [V2.3 methodology](methodology.md)
- [Operator guide](harness-v2.md)
- [Migration guide](migration-v2.3.md)
"""
        target = repo_root / "docs/results/v2" / CAMPAIGN_ID
        if check:
            if not target.is_dir() or _tree_hashes(bundle) != _tree_hashes(target):
                raise PublicationError("committed compact result bundle is stale")
            if (repo_root / "docs/latest-results.md").read_text() != latest:
                raise PublicationError("latest-results.md is stale")
            if (repo_root / "docs/index.md").read_text() != index:
                raise PublicationError("docs/index.md is stale")
        else:
            _sync_tree(bundle, target)
            _write(repo_root / "docs/latest-results.md", latest.encode("utf-8"))
            _write(repo_root / "docs/index.md", index.encode("utf-8"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and publish the exact qualified V2.3 campaign"
    )
    parser.add_argument("--campaign-dir", type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--asset-dir", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--check-bundle",
        action="store_true",
        help="validate the committed compact bundle without raw campaign access",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.check_bundle:
            if arguments.campaign_dir is not None or arguments.asset_dir is not None:
                raise PublicationError(
                    "--check-bundle does not accept campaign or asset inputs"
                )
            validate_committed_bundle(arguments.repo_root)
        else:
            if arguments.campaign_dir is None:
                raise PublicationError("--campaign-dir is required")
            publish(
                arguments.campaign_dir,
                arguments.repo_root,
                asset_dir=arguments.asset_dir,
                check=arguments.check,
            )
    except (PublicationError, OSError, subprocess.CalledProcessError) as exc:
        print(f"publish-v2-3-results: {exc}", file=os.sys.stderr)
        return 4
    print(
        f"published V2.3 campaign {CAMPAIGN_ID}"
        if not arguments.check and not arguments.check_bundle
        else f"verified V2.3 campaign {CAMPAIGN_ID}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
