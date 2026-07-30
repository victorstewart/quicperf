from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class V2LegacyWrapperTests(unittest.TestCase):
    def test_current_publication_profile_translates_to_one_diagnostic_cell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "diagnostic.json"
            completed = subprocess.run(
                [
                    str(ROOT / "tools" / "quicperfctl"),
                    "legacy",
                    "translate",
                    "--base-profile",
                    str(ROOT / "profiles" / "v2" / "publication.json"),
                    "--out",
                    str(output),
                    "--set",
                    "QUICPERF_BINARIES=xquicperf",
                    "--set",
                    "QUICPERF_REFERENCE_CLIENTS=picoperf",
                    "--set",
                    "QUICPERF_SCENARIOS=upload",
                    "--set",
                    "QUICPERF_NETWORKS=iouring",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            translated = json.loads(output.read_text())
            self.assertEqual(translated["roles"], {
                "servers": ["xquicperf"],
                "reference_clients": ["picoperf"],
            })
            self.assertEqual(translated["backends"]["server"], ["iouring"])
            self.assertEqual(
                [workload["scenario"] for workload in translated["workloads"]],
                ["upload"],
            )
            self.assertEqual(translated["expected_cardinality"]["planned_trials"], 1)
            self.assertFalse(any(translated["qualification"].values()))

    def test_every_independent_legacy_engine_is_an_exit_four_guard(self) -> None:
        commands = {
            "run-adaptive-publication-suite.py": "adaptive publication engine removed",
            "run-fixed-publication-suite.py": "fixed publication engine removed",
            "run-saturation-scout.py": "universal saturation scout removed",
            "run-saturation-sweep.py": "legacy saturation sweep removed",
            "audit-publication-run.py": "publication auditor removed",
            "combine-saturation-sweeps.py": "saturation sweep combination removed",
            "emit-row-stats.py": "row-statistics engine removed",
        }
        for script, message in commands.items():
            with self.subTest(script=script):
                completed = subprocess.run(
                    [sys.executable, str(ROOT / "tools" / script), "--ignored"],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(completed.returncode, 4)
                self.assertEqual(completed.stdout, "")
                self.assertIn(message, completed.stderr)

    def test_removed_publication_coordinator_fails_without_side_effects(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "run-publication-suite.py")],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 4)
        self.assertEqual(completed.stdout, "")
        self.assertIn("legacy publication coordinator removed", completed.stderr)
        self.assertIn("tools/quicperfctl campaign create", completed.stderr)
        self.assertIn("Translation never launches a run", completed.stderr)

    def test_unknown_legacy_arguments_are_explicitly_refused(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "run-publication-suite.py"),
                "--old-option",
                "value",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 4)
        self.assertIn("refused 2 untranslatable command-line argument(s)", completed.stderr)

    def test_legacy_result_renderer_cannot_recreate_public_claims(self) -> None:
        before = (ROOT / "docs" / "latest-results.md").read_bytes()
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "render-latest-results.py"),
                "old-results",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 4)
        self.assertEqual(completed.stdout, "")
        self.assertIn("legacy result renderer removed", completed.stderr)
        self.assertIn("tools/quicperfctl export", completed.stderr)
        self.assertEqual((ROOT / "docs" / "latest-results.md").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
