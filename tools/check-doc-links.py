#!/usr/bin/env python3
"""Fail when a checked-in Markdown link targets a missing local path."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from urllib.parse import unquote


LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def check(root: Path) -> list[str]:
    failures: list[str] = []
    documents = [root / "README.md", root / "CHANGELOG.md"]
    documents.extend(sorted((root / "docs").rglob("*.md")))
    documents.extend(sorted((root / "schemas").rglob("*.md")))
    documents.extend(sorted((root / "tls").rglob("*.md")))
    for document in documents:
        if not document.is_file():
            continue
        for line_number, line in enumerate(
            document.read_text(encoding="utf-8").splitlines(), start=1
        ):
            for match in LINK.finditer(line):
                target = match.group(1).strip()
                if target.startswith("<") and target.endswith(">"):
                    target = target[1:-1]
                target = target.split(maxsplit=1)[0]
                if (
                    not target
                    or target.startswith(("#", "http://", "https://", "mailto:"))
                ):
                    continue
                path_text = unquote(target.split("#", 1)[0].split("?", 1)[0])
                if not path_text:
                    continue
                path = (
                    root / path_text.lstrip("/")
                    if path_text.startswith("/")
                    else document.parent / path_text
                )
                if not path.resolve().exists():
                    failures.append(
                        f"{document.relative_to(root)}:{line_number}: {target}"
                    )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    failures = check(parser.parse_args().repo_root.resolve())
    if failures:
        print("missing local Markdown targets:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("documentation links resolve")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
