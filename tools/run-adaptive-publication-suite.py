#!/usr/bin/env python3
"""Migration guard for the removed adaptive publication engine."""

import sys


def main() -> int:
    sys.stderr.write(
        "quicperf legacy adaptive publication engine removed\n"
        "No legacy schedule or sample can become v2 evidence. Use "
        "tools/quicperfctl campaign create --profile profiles/v2.3/publication.json --out <run-dir>.\n"
    )
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
