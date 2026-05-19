#!/usr/bin/env python3
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def load_runner_module():
    spec = importlib.util.spec_from_file_location(
        "run_adaptive_publication_suite",
        ROOT / "tools" / "run-adaptive-publication-suite.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RunAdaptiveConfigTests(unittest.TestCase):
    def test_adaptive_random_seed_alias_takes_precedence(self):
        runner = load_runner_module()

        with mock.patch.dict(
            os.environ,
            {"QUICPERF_RANDOM_SEED": "11", "QUICPERF_ADAPTIVE_RANDOM_SEED": "22"},
            clear=True,
        ):
            self.assertEqual(runner.load_config().random_seed, 22)

    def test_random_seed_legacy_name_still_works(self):
        runner = load_runner_module()

        with mock.patch.dict(os.environ, {"QUICPERF_RANDOM_SEED": "11"}, clear=True):
            self.assertEqual(runner.load_config().random_seed, 11)


if __name__ == "__main__":
    unittest.main()
