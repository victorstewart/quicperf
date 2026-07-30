from __future__ import annotations

from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN_ID = (
    "ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492"
)
BUNDLE = ROOT / "docs/results/v2" / CAMPAIGN_ID
SCRIPT = ROOT / "tools/publish-v2-3-results.py"
SPEC = importlib.util.spec_from_file_location("publish_v2_3_results", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PublicationBundleTests(unittest.TestCase):
    def copy_bundle(self, root: Path) -> Path:
        destination = root / "docs/results/v2" / CAMPAIGN_ID
        destination.parent.mkdir(parents=True)
        shutil.copytree(BUNDLE, destination)
        return destination

    def rehash(self, bundle: Path, relative: str) -> None:
        manifest_path = bundle / "public-bundle-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest["files"]:
            if entry["path"] == relative:
                entry["sha256"] = sha256(bundle / relative)
                break
        else:
            self.fail(f"manifest has no entry for {relative}")
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def test_exact_committed_bundle_is_valid_and_allowlisted(self) -> None:
        publisher.validate_committed_bundle(ROOT, require_tree=False)
        names = {
            path.name
            for path in BUNDLE.rglob("*")
            if path.is_file()
        }
        self.assertFalse(
            names
            & {
                "journal.sqlite3",
                "samples.tsv",
                "events.jsonl",
                "schedule.tsv",
            }
        )

    def test_tampered_and_incomplete_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.copy_bundle(root)
            with (bundle / "row-results.tsv").open("ab") as stream:
                stream.write(b"tampered")
            with self.assertRaisesRegex(
                publisher.PublicationError, "bundle file is invalid"
            ):
                publisher.validate_committed_bundle(root, require_tree=False)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.copy_bundle(root)
            (bundle / "comparisons.tsv").unlink()
            with self.assertRaisesRegex(
                publisher.PublicationError, "bundle file is invalid"
            ):
                publisher.validate_committed_bundle(root, require_tree=False)

    def test_nonqualified_and_wrong_campaign_inputs_are_rejected(self) -> None:
        for field, value in (
            ("finalization_status", "diagnostic_failed_nonpublication"),
            ("campaign_id", "0" * 64),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = self.copy_bundle(root)
                status_path = bundle / "status.json"
                status = json.loads(status_path.read_text(encoding="utf-8"))
                status[field] = value
                status_path.write_text(
                    json.dumps(status, sort_keys=True, separators=(",", ":"))
                    + "\n",
                    encoding="utf-8",
                )
                self.rehash(bundle, "status.json")
                with self.assertRaisesRegex(
                    publisher.PublicationError, "not qualified V2.3"
                ):
                    publisher.validate_committed_bundle(root, require_tree=False)

    def test_wrong_source_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.copy_bundle(root)
            manifest_path = bundle / "public-bundle-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["executed_git_tree"] = "0" * 40
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                publisher.PublicationError, "bundle identity is wrong"
            ):
                publisher.validate_committed_bundle(root, require_tree=False)

    def test_oversized_allowlisted_input_is_rejected(self) -> None:
        with mock.patch.object(publisher, "MAX_PUBLIC_FILE_BYTES", 100):
            with self.assertRaisesRegex(
                publisher.PublicationError, "bundle file is invalid"
            ):
                publisher.validate_committed_bundle(ROOT, require_tree=False)

    def test_result_generation_is_deterministic_and_not_a_global_ranking(self) -> None:
        rows = publisher._rows(BUNDLE / "row-results.tsv")
        comparisons = publisher._rows(BUNDLE / "comparisons.tsv")
        first = publisher._scenario_pages(rows, comparisons)
        second = publisher._scenario_pages(rows, comparisons)
        self.assertEqual(first, second)
        self.assertEqual(
            tuple(publisher.SCENARIO_TITLES),
            publisher.SCENARIOS,
        )
        self.assertEqual(set(first[1]), {
            f"scenarios/{scenario}.md" for scenario in publisher.SCENARIOS
        })
        for scenario, page in first[1].items():
            scenario_name = Path(scenario).stem
            self.assertTrue(
                page.startswith(f"# {publisher.SCENARIO_TITLES[scenario_name]}\n")
            )
            self.assertIn("simultaneous 95% interval", page)
            self.assertIn("Reference-client sensitivity", page)
            self.assertIn("this table is not a cross-scenario leaderboard", page)
        self.assertNotIn("Reqresp", first[0])
        self.assertNotIn("Pps", first[0])

    def test_published_counts_and_balance_are_exact(self) -> None:
        quality = publisher._rows(BUNDLE / "quality-audit.tsv")
        self.assertEqual(len(quality), 4320)
        self.assertEqual(
            Counter(row["session"] for row in quality),
            {"1": 2160, "2": 2160},
        )
        self.assertEqual(
            Counter(row["reference_client"] for row in quality),
            {"ngtcp2perf": 2160, "picoperf": 2160},
        )


if __name__ == "__main__":
    unittest.main()
