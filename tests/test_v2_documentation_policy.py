from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class V2DocumentationPolicyTests(unittest.TestCase):
    def test_result_tree_contains_only_the_v2_admission_readme(self) -> None:
        files = sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "docs" / "results").rglob("*")
            if path.is_file()
        )
        self.assertEqual(files, ["docs/results/v2/README.md"])
        readme = (ROOT / files[0]).read_text(encoding="utf-8")
        self.assertIn("publication_qualified", readme)
        self.assertIn("NOT_RUN", readme)

    def test_mutable_scout_cache_is_absent(self) -> None:
        cache = ROOT / "profiles" / "fixed-design" / "default-scout"
        self.assertFalse(cache.exists() and any(cache.rglob("*")))

    def test_latest_results_is_a_number_free_qualification_index(self) -> None:
        index = (ROOT / "docs" / "latest-results.md").read_text(encoding="utf-8")
        self.assertIn("no publication-qualified v2 results", index)
        self.assertIn("publication_qualified", index)
        self.assertIn("NOT_RUN", index)
        for legacy_claim_marker in (
            "| Library | Network |",
            "gigabits/second",
            "requests/second",
            "streams/second",
            "datagrams/second",
        ):
            self.assertNotIn(legacy_claim_marker, index)

    def test_removed_inference_terms_occur_only_in_migration_note(self) -> None:
        removed_long = "statistical_" + "t" + "ie"
        removed_short = "t" + "ie"
        exact_removed_term = re.compile(
            rf"(?<![A-Za-z0-9_])(?:{removed_long}|{removed_short})(?![A-Za-z0-9_])"
        )
        found: list[str] = []
        for relative in ("README.md", "AGENTS.md", "docs", "tools", "tests", "schemas", "quicperf_harness"):
            path = ROOT / relative
            candidates = [path] if path.is_file() else path.rglob("*")
            for candidate in candidates:
                if not candidate.is_file() or candidate.suffix not in {".md", ".py", ".json"}:
                    continue
                if "__pycache__" in candidate.parts:
                    continue
                text = candidate.read_text(encoding="utf-8")
                if exact_removed_term.search(text):
                    found.append(candidate.relative_to(ROOT).as_posix())
        self.assertEqual(found, ["docs/migration-v2.md"])

    def test_primary_estimand_and_physical_gate_are_explicit(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        methodology = (ROOT / "docs" / "methodology.md").read_text(encoding="utf-8")
        for text in (readme, methodology):
            self.assertIn("fixed-treatment server", text.lower())
            self.assertIn("exactly 16 active connections", text)
            self.assertIn("50/50", text)
            self.assertIn("NOT_RUN", text)
            self.assertIn("publication_qualified", text)

    def test_v21_arm_and_passive_monitoring_contract_is_explicit(self) -> None:
        methodology = (ROOT / "docs" / "methodology.md").read_text(
            encoding="utf-8"
        )
        migration = (ROOT / "docs" / "migration-v2.1.md").read_text(
            encoding="utf-8"
        )
        for text in (methodology, migration):
            text = " ".join(text.split())
            self.assertIn("750 ms", text)
            self.assertIn("500 ms", text)
            self.assertIn("ARM_REJECTED", text)
            self.assertIn("Repeated live-journal polling is prohibited", text)
            self.assertIn("quicperfctl campaign status", text)
            self.assertIn("sqlite3", text)


if __name__ == "__main__":
    unittest.main()
