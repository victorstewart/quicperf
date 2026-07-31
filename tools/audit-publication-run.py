#!/usr/bin/env python3
"""Migration guard for the removed legacy publication auditor."""

import sys


def main() -> int:
    sys.stderr.write(
        "quicperf legacy publication auditor removed; use tools/quicperfctl campaign analyze "
        "and finalize against the transactional journal.\n"
    )
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
