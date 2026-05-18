#!/usr/bin/env python3
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PicoperfCongestionProfileTests(unittest.TestCase):
    def test_default_and_path_auto_use_current_bbr(self):
        text = (ROOT / "perf.picoquic.h").read_text(encoding="utf-8")
        selector = re.search(
            r"static inline const char \*benchmarkPicoquicCongestionAlgorithmName\(void\)"
            r"\s*\{(?P<body>.*?)\n\}",
            text,
            re.S,
        )
        self.assertIsNotNone(selector)
        body = selector.group("body")
        self.assertIn('strcmp(benchmarkCongestionProfile, "path-auto")', body)
        self.assertIn('return "cubic";', body)
        self.assertIn('return "bbr";', body)
        self.assertTrue(body.rstrip().endswith('return "bbr";'))


if __name__ == "__main__":
    unittest.main()
