#!/usr/bin/env python3
"""Migration guard for the removed universal saturation scout."""

import sys


def main() -> int:
    sys.stderr.write(
        "quicperf universal saturation scout removed\n"
        "Fixed-treatment publication has no scout. For the distinct capacity estimand use "
        "tools/quicperfctl capacity create --profile profiles/v2/capacity.json --out <run-dir>.\n"
    )
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
