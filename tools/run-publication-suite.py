#!/usr/bin/env python3
"""One-release migration guard for the removed publication coordinator."""

from __future__ import annotations

import sys


MESSAGE = """quicperf legacy publication coordinator removed

tools/run-publication-suite.py no longer schedules, resumes, analyzes, or
publishes benchmark data. Its historical environment variables and arguments
are not interpreted.

Use the canonical v2.3 workflow:
  tools/quicperfctl doctor --profile profiles/v2.3/publication.json
  tools/quicperfctl campaign create --profile profiles/v2.3/publication.json --out <run-dir>
  tools/quicperfctl campaign run --run-dir <run-dir> --session 1
  tools/quicperfctl campaign run --run-dir <run-dir> --session 2
  tools/quicperfctl campaign analyze --run-dir <run-dir>
  tools/quicperfctl campaign finalize --run-dir <run-dir>

To convert supported legacy environment settings into explicit diagnostic JSON,
use tools/quicperfctl legacy translate. Translation never launches a run.
"""


def main() -> int:
    print(MESSAGE, file=sys.stderr, end="")
    if len(sys.argv) > 1:
        print(f"refused {len(sys.argv) - 1} untranslatable command-line argument(s)", file=sys.stderr)
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
