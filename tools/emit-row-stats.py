#!/usr/bin/env python3
"""Migration guard for removed legacy row statistics."""

import sys


if __name__ == "__main__":
    sys.stderr.write("legacy row-statistics engine removed; use quicperfctl campaign analyze.\n")
    raise SystemExit(4)
