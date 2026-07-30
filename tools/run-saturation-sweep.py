#!/usr/bin/env python3
"""Migration guard for the removed legacy saturation sweep."""

import sys


def main() -> int:
    sys.stderr.write(
        "quicperf legacy saturation sweep removed; use the frozen capacity workflow via "
        "tools/quicperfctl capacity create.\n"
    )
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
