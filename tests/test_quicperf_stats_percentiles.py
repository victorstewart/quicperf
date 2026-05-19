#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from quicperf_stats import bad_tail_quantile  # noqa: E402


class QuicperfStatsPercentileTests(unittest.TestCase):
    def test_rate_metric_bad_tail_uses_lower_tail(self):
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        self.assertEqual(bad_tail_quantile(values, 0.90, "throughput_gbps"), 14.0)
        self.assertEqual(bad_tail_quantile(values, 0.99, "throughput_gbps"), 10.4)

    def test_lower_is_better_metric_bad_tail_uses_upper_tail(self):
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        self.assertEqual(bad_tail_quantile(values, 0.90, "server_rss_delta_bytes_per_connection"), 46.0)
        self.assertEqual(bad_tail_quantile(values, 0.99, "server_rss_delta_bytes_per_connection"), 49.6)


if __name__ == "__main__":
    unittest.main()
