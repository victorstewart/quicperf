from __future__ import annotations

import csv
import io
from pathlib import Path
import unittest
from unittest import mock
from dataclasses import replace

from quicperf_harness.capability_matrix import (
    ADAPTER_CONTRACTS,
    CapabilityAuditError,
    audit_snapshots,
    canonical_matrix,
    expected_snapshots,
    main,
    matrix_tsv,
)
from quicperf_harness.planner import (
    CANONICAL_SERVERS,
    PUBLICATION_SCENARIOS,
    SERVER_BACKENDS,
)
from quicperf_harness.renderer import _coverage


class CapabilityMatrixTests(unittest.TestCase):
    @staticmethod
    def contract_tests() -> set[str]:
        return {contract.contract_test for contract in ADAPTER_CONTRACTS.values()}

    def test_canonical_inventory_is_exact_complete_and_explained(self) -> None:
        cells = canonical_matrix()
        self.assertEqual(len(cells), 12 * 15 * 2)
        self.assertEqual(
            {(cell.server, cell.scenario, cell.server_backend) for cell in cells},
            {
                (server, scenario, backend)
                for server in CANONICAL_SERVERS
                for scenario in PUBLICATION_SCENARIOS
                for backend in SERVER_BACKENDS
            },
        )
        self.assertEqual(sum(cell.advertised for cell in cells), 360)
        self.assertFalse(any(not cell.advertised for cell in cells))
        self.assertTrue(all(cell.blocker for cell in cells if not cell.advertised))
        self.assertFalse(any("unexplained" in cell.blocker for cell in cells))

    def test_close_reset_cleanup_requires_peer_terminal_evidence(self) -> None:
        cells = [
            cell for cell in canonical_matrix()
            if cell.scenario == "close_reset_cleanup"
        ]
        self.assertEqual(len(cells), 12 * 2)
        promoted = [
            cell for cell in cells
            if cell.server in {
                "ngtcp2perf", "lsperf", "tquicperf", "quicheperf", "picoperf", "quinnperf",
                "xquicperf", "s2nperf", "neqoperf", "noqperf", "quiczigperf", "mvfstperf"
            }
        ]
        self.assertTrue(all(cell.advertised for cell in promoted))
        self.assertFalse(any(
            cell.advertised
            for cell in cells
            if cell.server not in {
                "ngtcp2perf", "lsperf", "tquicperf", "quicheperf", "picoperf", "quinnperf",
                "xquicperf", "s2nperf", "neqoperf", "noqperf", "quiczigperf", "mvfstperf"
            }
        ))

    def test_quiczig_lifecycle_rows_require_successor_one_use_tickets(self) -> None:
        cells = [
            cell for cell in canonical_matrix()
            if cell.server == "quiczigperf"
            and cell.scenario in {"resumed_connect", "zero_rtt_reqresp"}
        ]
        self.assertEqual(len(cells), 4)
        resumed = [cell for cell in cells if cell.scenario == "resumed_connect"]
        zero_rtt = [cell for cell in cells if cell.scenario == "zero_rtt_reqresp"]
        self.assertTrue(all(cell.advertised for cell in resumed))
        self.assertTrue(all(cell.advertised for cell in zero_rtt))
        self.assertTrue(all(not cell.blocker for cell in zero_rtt))

    def test_tquic_flow_control_is_advertised_after_exact_counter_proof(self) -> None:
        cells = [
            cell for cell in canonical_matrix()
            if cell.server == "tquicperf" and cell.scenario == "flow_control"
        ]
        self.assertEqual(len(cells), 2)
        self.assertTrue(all(cell.advertised and not cell.blocker for cell in cells))

    def test_tquic_loss_and_cleanup_are_advertised_after_native_contract(self) -> None:
        cells = [
            cell for cell in canonical_matrix()
            if cell.server == "tquicperf"
            and cell.scenario in {"loss_recovery", "close_reset_cleanup"}
        ]
        self.assertEqual(len(cells), 4)
        self.assertTrue(all(cell.advertised and not cell.blocker for cell in cells))

    def test_xquic_cleanup_is_advertised_after_exact_terminal_contract(self) -> None:
        cells = [
            cell for cell in canonical_matrix()
            if cell.server == "xquicperf" and cell.scenario == "close_reset_cleanup"
        ]
        self.assertEqual(len(cells), 2)
        self.assertTrue(all(cell.advertised and not cell.blocker for cell in cells))

    def test_picoquic_flow_control_is_advertised_after_live_counter_proof(self) -> None:
        cells = [
            cell for cell in canonical_matrix()
            if cell.server == "picoperf" and cell.scenario == "flow_control"
        ]
        self.assertEqual(len(cells), 2)
        self.assertTrue(all(cell.advertised and not cell.blocker for cell in cells))

    def test_exact_snapshot_audit_rejects_an_unexpected_missing_cell(self) -> None:
        snapshots = dict(expected_snapshots())
        ngtcp2 = snapshots["ngtcp2perf"]
        snapshots["ngtcp2perf"] = replace(
            ngtcp2, scenario_ids=ngtcp2.scenario_ids - {"1"}
        )
        with self.assertRaisesRegex(CapabilityAuditError, "ngtcp2perf:scenario_ids"):
            audit_snapshots(snapshots, self.contract_tests())

    def test_exact_snapshot_audit_rejects_unreviewed_advertised_support(self) -> None:
        snapshots = dict(expected_snapshots())
        zig = snapshots["quiczigperf"]
        snapshots["quiczigperf"] = replace(
            zig, scenario_ids=zig.scenario_ids | {"99"}
        )
        with self.assertRaisesRegex(CapabilityAuditError, "quiczigperf:scenario_ids"):
            audit_snapshots(snapshots, self.contract_tests())

    def test_snapshot_audit_requires_every_cmake_contract_test(self) -> None:
        tests = self.contract_tests() - {"quicperf_s2n_adapter_contract"}
        with self.assertRaisesRegex(
            CapabilityAuditError,
            "s2nperf:missing_cmake_contract_test:quicperf_s2n_adapter_contract",
        ):
            audit_snapshots(expected_snapshots(), tests)

    def test_inventory_tsv_is_deterministic_and_cardinality_preserving(self) -> None:
        snapshots = expected_snapshots()
        first = matrix_tsv(canonical_matrix(), snapshots)
        second = matrix_tsv(canonical_matrix(), snapshots)
        self.assertEqual(first, second)
        self.assertEqual(len(first.splitlines()), 361)

    def test_selected_binary_directory_selects_its_cmake_inventory(self) -> None:
        cells = canonical_matrix()
        with (
            mock.patch(
                "quicperf_harness.capability_matrix.live_snapshots",
                return_value={},
            ),
            mock.patch(
                "quicperf_harness.capability_matrix.cmake_contract_tests",
                return_value=frozenset(),
            ) as contract_tests,
            mock.patch(
                "quicperf_harness.capability_matrix.audit_snapshots",
                return_value=cells,
            ),
            mock.patch(
                "quicperf_harness.capability_matrix.matrix_tsv",
                return_value="",
            ),
        ):
            self.assertEqual(main(["--bin-dir", "selected-build/bin"]), 0)
        contract_tests.assert_called_once_with(Path("selected-build"))

    def test_renderer_keeps_all_cells_when_only_one_sample_survives(self) -> None:
        rows = [{
            "planned_microblock_status": "selected",
            "config": {
                "server": "ngtcp2perf",
                "scenario": "download",
                "server_backend": "syscall",
            },
            "sample": {"completion_status": "valid"},
            "committed_trial_id": "committed-trial",
            "attempt_id": "attempt",
            "planned_attempt_id": "attempt",
            "planned_termination_reason": None,
        }]
        rendered = list(csv.DictReader(
            io.StringIO(_coverage(rows, publication_valid=True).decode("utf-8")), delimiter="\t"
        ))
        self.assertEqual(len(rendered), 360)
        by_key = {
            (row["server"], row["scenario"], row["server_backend"]): row
            for row in rendered
        }
        survivor = by_key[("ngtcp2perf", "download", "syscall")]
        self.assertEqual(survivor["coverage_status"], "publication_evidence_complete")
        self.assertIn("journal:sample:committed-trial", survivor["interoperability_evidence"])

        missing = by_key[("ngtcp2perf", "upload", "iouring")]
        self.assertEqual(missing["coverage_status"], "missing_planned_cell")
        self.assertEqual(missing["blocker"], "journal_gap:canonical_planned_cell_absent")
        self.assertTrue(missing["capability_evidence"].startswith("missing:"))

        picoquic_missing = by_key[("picoperf", "close_reset_cleanup", "syscall")]
        self.assertEqual(picoquic_missing["coverage_status"], "missing_planned_cell")
        self.assertEqual(
            picoquic_missing["blocker"], "journal_gap:canonical_planned_cell_absent"
        )
        self.assertIn(
            "cmake-test:quicperf_picoquic_adapter_contract",
            picoquic_missing["behavioral_evidence"],
        )


if __name__ == "__main__":
    unittest.main()
