#!/usr/bin/env python3
"""Create and independently verify the immutable V2.3 release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import subprocess
import tempfile


CAMPAIGN_ID = "ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492"
SOURCE_COMMIT = "44250d751e650f11f620733aa6e5d0498f947d12"
SOURCE_TREE = "a72228525e2f09fabd0b01cee4888e201a376ef4"
SOURCE_ARCHIVE_SHA256 = (
    "89f1ba46539f3a881f088ed0495ab441c04c165a7fa85db7da650c6981e41fd8"
)
FIXED_MTIME = "2026-07-30T00:00:00Z"
PREFIX = "quicperf-v2.3-ca3fc476"
FULL_RUN = f"{PREFIX}-full-run.tar.zst"
SAMPLES = f"{PREFIX}-samples.tsv.zst"
SOURCE = f"{PREFIX}-executed-source.tar.zst"
ASSETS = (FULL_RUN, SAMPLES, SOURCE)


class AssetError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _stream_sha256(command: list[str]) -> str:
    digest = hashlib.sha256()
    process = subprocess.Popen(command, stdout=subprocess.PIPE)
    assert process.stdout is not None
    while block := process.stdout.read(1024 * 1024):
        digest.update(block)
    if process.wait() != 0:
        raise AssetError(f"command failed: {' '.join(command)}")
    return digest.hexdigest()


def _pipe_to_file(
    producer: list[str], consumer: list[str], destination: Path
) -> None:
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        with temporary.open("wb") as output:
            first = subprocess.Popen(producer, stdout=subprocess.PIPE)
            assert first.stdout is not None
            second = subprocess.Popen(consumer, stdin=first.stdout, stdout=output)
            first.stdout.close()
            second_status = second.wait()
            first_status = first.wait()
        if first_status or second_status:
            raise AssetError(
                f"asset pipeline failed ({first_status}, {second_status})"
            )
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _compress_file(source: Path, destination: Path) -> None:
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        with temporary.open("wb") as output:
            completed = subprocess.run(
                [
                    "zstd",
                    "--quiet",
                    "--threads=1",
                    "-19",
                    "--stdout",
                    source,
                ],
                stdout=output,
                check=False,
            )
        if completed.returncode:
            raise AssetError(
                f"asset compression failed ({completed.returncode}): {source}"
            )
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssetError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise AssetError(f"expected JSON object: {path}")
    return value


def _safe_tar_names(archive: Path, *, required_prefix: str | None) -> None:
    completed = subprocess.run(
        ["tar", "--use-compress-program=zstd", "-tf", archive],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    names = completed.stdout.splitlines()
    if not names:
        raise AssetError(f"empty archive: {archive}")
    for name in names:
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            raise AssetError(f"unsafe archive member: {name}")
        if required_prefix is not None and pure.parts[0] != required_prefix:
            raise AssetError(f"archive member escapes suite prefix: {name}")


def _verify_artifact_checksums(campaign: Path) -> None:
    artifacts = campaign / "artifacts"
    seen: dict[str, str] = {}
    for line in (artifacts / "checksums.sha256").read_text(
        encoding="utf-8"
    ).splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise AssetError("malformed canonical artifact checksum manifest")
        digest, name = match.groups()
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            raise AssetError(f"unsafe canonical artifact path: {name}")
        path = artifacts.joinpath(*pure.parts)
        if not path.is_file() or path.is_symlink() or _sha256(path) != digest:
            raise AssetError(f"canonical artifact mismatch: {name}")
        seen[name] = digest
    expected = _json(campaign / "status.json").get("artifact_checksums")
    if seen != expected:
        raise AssetError("status and canonical artifact checksums disagree")


def _require_campaign_identity(campaign: Path) -> None:
    status = _json(campaign / "status.json")
    manifest = _json(campaign / "manifest.json")
    if (
        status.get("campaign_id") != CAMPAIGN_ID
        or status.get("finalization_status") != "publication_qualified"
        or status.get("publication_valid") is not True
        or status.get("committed_samples") != 4320
        or status.get("expected_samples") != 4320
    ):
        raise AssetError("campaign is not the exact qualified V2.3 result")
    source = manifest.get("source")
    if not isinstance(source, dict) or (
        source.get("git_commit"),
        source.get("archive_sha256"),
        source.get("clean"),
        source.get("dirty_patch"),
    ) != (SOURCE_COMMIT, SOURCE_ARCHIVE_SHA256, True, None):
        raise AssetError("campaign source identity is not exact")
    _verify_artifact_checksums(campaign)


def _sqlite_check(path: Path) -> None:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    finally:
        connection.close()
    if integrity != [("ok",)] or foreign_keys:
        raise AssetError("extracted journal failed SQLite integrity checks")


def _source_tree(extracted: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=extracted, check=True)
    subprocess.run(
        ["git", "config", "core.autocrlf", "false"], cwd=extracted, check=True
    )
    subprocess.run(["git", "add", "-A"], cwd=extracted, check=True)
    return subprocess.run(
        ["git", "write-tree"],
        cwd=extracted,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


def verify_assets(suite: Path, repo: Path, output: Path) -> None:
    for name in ASSETS:
        path = output / name
        if not path.is_file() or path.is_symlink():
            raise AssetError(f"missing asset: {name}")
        subprocess.run(["zstd", "--test", "--quiet", path], check=True)

    _safe_tar_names(output / FULL_RUN, required_prefix=suite.name)
    _safe_tar_names(output / SOURCE, required_prefix=None)
    raw_source_digest = _stream_sha256(
        ["zstd", "--decompress", "--stdout", output / SOURCE]
    )
    if raw_source_digest != SOURCE_ARCHIVE_SHA256:
        raise AssetError("executed-source tar digest does not match the manifest")

    with tempfile.TemporaryDirectory(prefix="quicperf-v2.3-assets-") as name:
        root = Path(name)
        full = root / "full"
        source = root / "source"
        full.mkdir()
        source.mkdir()
        subprocess.run(
            [
                "tar",
                "--use-compress-program=zstd",
                "--extract",
                "--file",
                output / FULL_RUN,
                "--directory",
                full,
                "--no-same-owner",
            ],
            check=True,
        )
        extracted_suite = full / suite.name
        campaign = extracted_suite / "fixed"
        _require_campaign_identity(campaign)
        _sqlite_check(campaign / "journal.sqlite3")
        subprocess.run(
            [
                "tar",
                "--use-compress-program=zstd",
                "--extract",
                "--file",
                output / SOURCE,
                "--directory",
                source,
                "--no-same-owner",
            ],
            check=True,
        )
        if _source_tree(source) != SOURCE_TREE:
            raise AssetError("extracted executed source does not reproduce Git tree")

    lines = (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    expected = [f"{_sha256(output / name)}  {name}" for name in ASSETS]
    if lines != expected:
        raise AssetError("SHA256SUMS is stale or noncanonical")
    _require_campaign_identity(suite / "fixed")
    if (
        subprocess.run(
            ["git", "rev-parse", f"{SOURCE_COMMIT}^{{tree}}"],
            cwd=repo,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        != SOURCE_TREE
    ):
        raise AssetError("local executed commit no longer resolves to exact tree")


def create_assets(suite: Path, repo: Path, output: Path) -> None:
    suite = suite.resolve()
    repo = repo.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if not suite.is_dir() or any(path.is_symlink() for path in suite.rglob("*")):
        raise AssetError("authoritative suite is missing or contains a symlink")
    _require_campaign_identity(suite / "fixed")
    tree = subprocess.run(
        ["git", "rev-parse", f"{SOURCE_COMMIT}^{{tree}}"],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if tree != SOURCE_TREE:
        raise AssetError("executed source commit has the wrong tree")

    _pipe_to_file(
        [
            "tar",
            "--sort=name",
            "--format=posix",
            "--pax-option=delete=atime,delete=ctime",
            f"--mtime={FIXED_MTIME}",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mode=u+rwX,go+rX,go-w",
            "--create",
            "--file=-",
            "--directory",
            str(suite.parent),
            suite.name,
        ],
        ["zstd", "--quiet", "--threads=1", "-19", "--stdout"],
        output / FULL_RUN,
    )
    _compress_file(
        suite / "fixed/artifacts/samples.tsv",
        output / SAMPLES,
    )
    _pipe_to_file(
        ["git", "archive", "--format=tar", SOURCE_COMMIT],
        ["zstd", "--quiet", "--threads=1", "-19", "--stdout"],
        output / SOURCE,
    )
    sums = "".join(f"{_sha256(output / name)}  {name}\n" for name in ASSETS)
    (output / "SHA256SUMS").write_text(sums, encoding="utf-8")
    (output / "DRAFT-RELEASE-NOTES.md").write_text(
        f"""# quicperf V2.3 draft release notes

Qualified campaign: `{CAMPAIGN_ID}`

- `{FULL_RUN}` contains the complete finalized suite, campaign journal,
  raw health streams, logs, and canonical export.
- `{SAMPLES}` is the compressed raw-sample table.
- `{SOURCE}` is `git archive {SOURCE_COMMIT}`. Its uncompressed
  tar SHA-256 is `{SOURCE_ARCHIVE_SHA256}` and its Git tree is `{SOURCE_TREE}`.
- `SHA256SUMS` authenticates the compressed assets.

The full-run tar normalizes paths, ownership, modes, and timestamps to
`{FIXED_MTIME}` before deterministic single-threaded zstd compression.

Code is Apache-2.0. Benchmark data is CC BY 4.0. These are staged review
artifacts; do not publish a final release until the review branch is approved.
""",
        encoding="utf-8",
    )
    verify_assets(suite, repo, output)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite-dir", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.verify_only:
            verify_assets(
                args.suite_dir.resolve(),
                args.repo.resolve(),
                args.output_dir.resolve(),
            )
        else:
            create_assets(
                args.suite_dir.resolve(),
                args.repo.resolve(),
                args.output_dir.resolve(),
            )
    except (AssetError, OSError, sqlite3.Error, subprocess.CalledProcessError) as exc:
        print(f"package-v2-3-release-assets: {exc}")
        return 4
    print("verified V2.3 release assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
