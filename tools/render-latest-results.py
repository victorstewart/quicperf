#!/usr/bin/env python3
"""Migration guard for the removed legacy TSV-to-publication renderer."""

from __future__ import annotations

import sys


MESSAGE = """quicperf legacy result renderer removed

tools/render-latest-results.py no longer reads legacy TSV files or writes
docs/latest-results.md. Legacy result trees are not v2 inputs and cannot be
upgraded into publication evidence.

Use tools/quicperfctl campaign analyze for deterministic journal analysis and
tools/quicperfctl export --run-dir <run-dir> for an atomic v2 export. Copy or
link an export under docs/results/v2/ only after canonical finalize records
publication_qualified.
"""


def main() -> int:
    print(MESSAGE, file=sys.stderr, end="")
    if len(sys.argv) > 1:
        print(f"refused {len(sys.argv) - 1} legacy renderer argument(s)", file=sys.stderr)
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
