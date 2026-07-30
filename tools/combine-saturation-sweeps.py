#!/usr/bin/env python3
"""Migration guard for removed result-dependent saturation combining."""

import sys


if __name__ == "__main__":
    sys.stderr.write("legacy saturation sweep combination removed; use quicperfctl capacity analyze.\n")
    raise SystemExit(4)
