from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN_ID = (
    "ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492"
)


class V2DocumentationPolicyTests(unittest.TestCase):
    def test_only_the_qualified_compact_campaign_is_published(self) -> None:
        result_root = ROOT / "docs/results/v2"
        campaigns = sorted(
            path.name
            for path in result_root.iterdir()
            if path.is_dir()
        )
        self.assertEqual(campaigns, [CAMPAIGN_ID])
        status = json.loads(
            (result_root / CAMPAIGN_ID / "status.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(status["finalization_status"], "publication_qualified")
        self.assertEqual(status["committed_samples"], 4320)
        forbidden = {
            "journal.sqlite3",
            "samples.tsv",
            "events.jsonl",
            "schedule.tsv",
        }
        self.assertFalse(
            forbidden
            & {
                path.name
                for path in (result_root / CAMPAIGN_ID).rglob("*")
                if path.is_file()
            }
        )

    def test_public_pages_state_the_exact_estimand_and_limitations(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        methodology = (ROOT / "docs/methodology.md").read_text(encoding="utf-8")
        latest = (ROOT / "docs/latest-results.md").read_text(encoding="utf-8")
        for text in (readme, methodology):
            self.assertIn("fixed-treatment server", text.lower())
            self.assertIn("exactly 16 active connections", text)
            self.assertIn("50/50", text)
            self.assertIn("iouring", text)
            self.assertIn("NOT_RUN", text)
            self.assertIn("publication_qualified", text)
        self.assertIn("4,320/4,320", latest)
        self.assertIn("There is deliberately no global leaderboard", latest)
        self.assertIn(CAMPAIGN_ID, latest)

    def test_arm_monitor_and_runtime_contract_is_explicit(self) -> None:
        methodology = " ".join(
            (ROOT / "docs/methodology.md").read_text(encoding="utf-8").split()
        )
        operations = " ".join(
            (ROOT / "docs/harness-v2.md").read_text(encoding="utf-8").split()
        )
        for marker in (
            "750 ms",
            "500 ms",
            "250 ms",
            "0.1%",
            "80°C",
            "10,800 s",
            "30,000 s",
        ):
            self.assertIn(marker, methodology)
        self.assertIn("repeatedly querying the live journal", operations)
        self.assertIn("suite resume", operations)

    def test_removed_public_commands_and_profiles_are_absent(self) -> None:
        for relative in ("profiles/v2.1", "profiles/v2.2", "profiles/network"):
            path = ROOT / relative
            self.assertFalse(
                path.exists() and any(item.is_file() for item in path.rglob("*"))
            )
        help_text = (ROOT / "docs/harness-v2.md").read_text(encoding="utf-8")
        self.assertIn("Removed scout, adaptive, capacity, memory, tail", help_text)
        for removed in (
            "run-saturation-scout.py",
            "run-fixed-publication-suite.py",
            "run-publication-suite.py",
        ):
            self.assertFalse((ROOT / "tools" / removed).exists())

    def test_public_tls_fixture_warning_and_dual_license_are_present(self) -> None:
        warning = (ROOT / "tls/README.md").read_text(encoding="utf-8")
        self.assertIn("intentionally public", warning)
        self.assertIn("Never install", warning)
        self.assertTrue((ROOT / "LICENSE").is_file())
        data_license = (ROOT / "DATA-LICENSE").read_text(encoding="utf-8")
        self.assertIn("CC BY 4.0", data_license)


if __name__ == "__main__":
    unittest.main()
