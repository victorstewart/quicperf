#!/usr/bin/env python3
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "run-picoquic-dynamic-cc-suite.py"


def load_module():
    spec = importlib.util.spec_from_file_location("run_picoquic_dynamic_cc_suite", MODULE_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PicoquicDynamicCcSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def args(self):
        return SimpleNamespace(
            network="syscall",
            repeat=2,
            warmup=1,
            test_bytes=123456,
            timeout="30s",
            seed=10,
            bin_dir=None,
            path_time_scale=None,
        )

    def test_matrix_rows_are_picoquic_cc_specific(self):
        rows = self.mod.matrix_rows(
            ["cellular-public-5g-lte-switching"],
            ["bbr", "c4"],
            ["connect", "download"],
            ["off", "on"],
        )
        self.assertEqual(len(rows), 8)
        self.assertEqual(rows[0].profile, "cellular-public-5g-lte-switching")
        self.assertEqual(rows[0].controller, "bbr")
        self.assertEqual(rows[0].scenario, "connect")
        self.assertEqual(rows[0].packet_train, "off")
        self.assertEqual(rows[-1].controller, "c4")
        self.assertEqual(rows[-1].scenario, "download")
        self.assertEqual(rows[-1].packet_train, "on")

    def test_default_controllers_are_current_baseline_set(self):
        self.assertEqual(self.mod.DEFAULT_CONTROLLERS, ["bbr", "cubic", "newreno"])
        self.assertNotIn("c4", self.mod.DEFAULT_CONTROLLERS)

    def test_default_network_is_iouring_for_dynamic_cellular_suite(self):
        self.assertEqual(self.mod.DEFAULT_NETWORK, "iouring")

    def test_row_env_executes_picoperf_only_for_one_controller_and_schedule(self):
        row = self.mod.MatrixRow(
            row_id=7,
            profile="cellular-public-5g-lte-switching",
            controller="c4",
            scenario="download",
            packet_train="on",
        )
        env = self.mod.row_env(self.args(), row, Path("/tmp/suite"))
        self.assertEqual(env["QUICPERF_BINARIES"], "picoperf")
        self.assertEqual(env["QUICPERF_CONGESTION_PROFILE"], "c4")
        self.assertEqual(env["QUICPERF_PATH_PROFILES"], "cellular-public-5g-lte-switching")
        self.assertEqual(env["QUICPERF_SCENARIOS"], "download")
        self.assertEqual(env["QUICPERF_PICOQUIC_PACKET_TRAIN"], "1")
        self.assertEqual(env["QUICPERF_UDP_GSO"], "1")
        self.assertEqual(env["QUICPERF_TEST_BYTES"], "123456")

    def test_optional_path_time_scale_is_forwarded(self):
        args = self.args()
        args.path_time_scale = 0.001
        row = self.mod.MatrixRow(
            row_id=9,
            profile="cellular-public-5g-lte-switching",
            controller="bbr",
            scenario="download",
            packet_train="off",
        )
        env = self.mod.row_env(args, row, Path("/tmp/suite"))
        self.assertEqual(env["QUICPERF_PATH_TIME_SCALE"], "0.001")

    def test_packet_train_off_disables_udp_gso_for_real_adapter_mode(self):
        row = self.mod.MatrixRow(
            row_id=8,
            profile="cellular-public-5g-lte-switching",
            controller="bbr",
            scenario="connect",
            packet_train="off",
        )
        env = self.mod.row_env(self.args(), row, Path("/tmp/suite"))
        self.assertEqual(env["QUICPERF_PICOQUIC_PACKET_TRAIN"], "0")
        self.assertEqual(env["QUICPERF_UDP_GSO"], "0")

    def test_write_matrix_records_all_rows(self):
        rows = self.mod.matrix_rows(["p1"], ["bbr", "cubic"], ["download"], ["off"])
        with tempfile.TemporaryDirectory() as tmp:
            matrix_path = Path(tmp) / "matrix.tsv"
            self.mod.write_matrix(matrix_path, rows, Path(tmp))
            text = matrix_path.read_text(encoding="utf-8")
        self.assertIn("profile\tscenario\tpacket_train\tcontroller", text)
        self.assertIn("p1\tdownload\toff\tbbr", text)
        self.assertIn("p1\tdownload\toff\tcubic", text)


if __name__ == "__main__":
    unittest.main()
