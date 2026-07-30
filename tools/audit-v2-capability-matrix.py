#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quicperf_harness.capability_matrix import main

raise SystemExit(main())
