#!/usr/bin/env python3
"""Migration guard for the removed fixed-design publication engine."""

import sys


def main() -> int:
    sys.stderr.write(
        "quicperf legacy fixed publication engine removed\n"
        "Old benchmark-plan.tsv files are not resumable inputs. Use "
        "tools/quicperfctl campaign create --profile profiles/v2.3/publication.json --out <run-dir>.\n"
    )
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
