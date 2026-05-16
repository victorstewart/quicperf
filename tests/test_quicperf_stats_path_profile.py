#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from quicperf_stats import parse_client_log_samples  # noqa: E402


BASE_LINE = (
    "quicperf_result library=picoquic scenario=download role=client network=syscall "
    "address=loopback local_address=loopback remote_address=loopback threads=1 "
    "seconds=1.000000 build_profile=native-lto window_profile=wan-bdp "
    "congestion_profile=default-bbr network_profile=syscall {path_profile}"
    "app_chunk=65536 server_connections=1 tls_verify_mode=disabled tls_cert_profile=ed25519 "
    "adapter_features=cc=bbr initial_cwnd_packets=10 ack_frequency_packets=2 "
    "socket_sndbuf_requested=1048576 socket_sndbuf_effective=1048576 "
    "socket_rcvbuf_requested=1048576 socket_rcvbuf_effective=1048576 "
    "throughput_gbps=1.234000"
)


class QuicperfStatsPathProfileTests(unittest.TestCase):
    def parse_line(self, line: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "picoperf-download-syscall-lte-good-1.client.log"
            path.write_text(line + "\n", encoding="utf-8")
            return parse_client_log_samples(path)

    def test_path_profile_is_parsed_from_new_result_lines(self):
        samples = self.parse_line(BASE_LINE.format(path_profile="path_profile=lte-good "))
        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(sample.path_profile, "lte-good")
        self.assertEqual(sample.row_key.path_profile, "lte-good")
        self.assertEqual(sample.group_key.path_profile, "lte-good")

    def test_legacy_result_lines_default_to_loopback(self):
        samples = self.parse_line(BASE_LINE.format(path_profile=""))
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].path_profile, "loopback")


if __name__ == "__main__":
    unittest.main()
