#!/usr/bin/env python3
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "quicperf_network_validate.py"


def load_module():
    spec = importlib.util.spec_from_file_location("quicperf_network_validate", MODULE_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class NetworkValidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_parse_ping_summary_with_rtt(self):
        output = """
64 bytes from 2001:db8::1: icmp_seq=1 ttl=63 time=45.1 ms
64 bytes from 2001:db8::1: icmp_seq=2 ttl=63 time=46.2 ms
--- 2001:db8::1 ping statistics ---
40 packets transmitted, 39 received, 2.5% packet loss, time 798ms
rtt min/avg/max/mdev = 30.100/45.250/80.500/9.125 ms
"""
        parsed = self.mod.parse_ping(output)
        self.assertEqual(parsed["transmitted"], 40)
        self.assertEqual(parsed["received"], 39)
        self.assertEqual(parsed["loss_percent"], 2.5)
        self.assertEqual(parsed["rtt_avg_ms"], 45.250)
        self.assertEqual(parsed["rtt_mdev_ms"], 9.125)
        self.assertEqual(parsed["rtt_samples"], 2)
        self.assertAlmostEqual(parsed["rtt_p50_ms"], 45.65)

    def test_profile_expectations_compute_roundtrip_loss_bdp_and_trace_average(self):
        profile = {
            "kind": "namespace",
            "name": "unit",
            "one_way_delay_us": 50000,
            "one_way_jitter_us": 25000,
            "loss_percent": 0.7,
            "downlink_bps": 8000000,
            "uplink_bps": 2000000,
            "queue_bdp": 2.0,
            "mtu_bytes": 1500,
            "trace": [
                {"duration_ms": 100, "downlink_bps": 10000000, "uplink_bps": 1000000},
                {"duration_ms": 300, "downlink_bps": 2000000, "uplink_bps": 500000},
            ],
        }
        exp = self.mod.profile_expectations(profile)
        self.assertAlmostEqual(exp["roundtrip_loss_percent"], 1.3951, places=3)
        self.assertEqual(exp["rtt_ms"], 100.0)
        self.assertEqual(exp["downlink_bdp_bytes"], 100000)
        self.assertEqual(exp["downlink_trace_avg_bps"], 4000000)
        self.assertGreaterEqual(exp["downlink_queue_packets"], 32)

    def test_classify_warns_on_large_rtt_deviation(self):
        profile = {
            "kind": "namespace",
            "name": "unit",
            "one_way_delay_us": 10000,
            "one_way_jitter_us": 1000,
            "loss_percent": 0.0,
            "downlink_bps": 100000000,
            "uplink_bps": 100000000,
            "queue_bdp": 1.0,
            "mtu_bytes": 1500,
            "trace": [],
        }
        exp = self.mod.profile_expectations(profile)
        ping = self.mod.ProbeResult("ok", {"received": 10, "loss_percent": 0.0, "rtt_avg_ms": 100.0}, "", "")
        good = [self.mod.ProbeResult("ok", {"throughput_bps": 1.0, "loss_percent": 0.0}, "", "")]
        qdisc = {"status": "ok", "reasons": []}
        status, reasons = self.mod.classify_profile(profile, exp, qdisc, qdisc, ping, good, good, good, good)
        self.assertEqual(status, "warn")
        self.assertTrue(any(reason.startswith("rtt_avg_outside_tolerance") for reason in reasons))

    def test_probe_summary_includes_tail_and_spread(self):
        results = [
            self.mod.ProbeResult("ok", {"throughput_bps": 10.0}, "", ""),
            self.mod.ProbeResult("ok", {"throughput_bps": 20.0}, "", ""),
            self.mod.ProbeResult("ok", {"throughput_bps": 30.0}, "", ""),
            self.mod.ProbeResult("ok", {"throughput_bps": 40.0}, "", ""),
        ]
        summary = self.mod.summarize_probe_results(results, "throughput_bps")
        self.assertEqual(summary["p50"], 25.0)
        self.assertEqual(summary["p90"], 40.0)
        self.assertEqual(summary["p99"], 40.0)
        self.assertGreater(summary["cv"], 0.0)

    def test_classify_fails_when_tcp_exceeds_shaped_rate(self):
        profile = {
            "kind": "namespace",
            "name": "unit",
            "one_way_delay_us": 10000,
            "one_way_jitter_us": 0,
            "loss_percent": 0.0,
            "downlink_bps": 1000000,
            "uplink_bps": 1000000,
            "queue_bdp": 1.0,
            "mtu_bytes": 1500,
            "trace": [],
        }
        exp = self.mod.profile_expectations(profile)
        ping = self.mod.ProbeResult("ok", {"received": 10, "loss_percent": 0.0, "rtt_avg_ms": 20.0}, "", "")
        too_fast = [self.mod.ProbeResult("ok", {"throughput_bps": 2000000.0, "loss_percent": 0.0, "target_bps": 500000.0}, "", "")]
        normal = [self.mod.ProbeResult("ok", {"throughput_bps": 500000.0, "loss_percent": 0.0, "target_bps": 500000.0}, "", "")]
        qdisc = {"status": "ok", "reasons": []}
        status, reasons = self.mod.classify_profile(profile, exp, qdisc, qdisc, ping, too_fast, normal, normal, normal)
        self.assertEqual(status, "fail")
        self.assertTrue(any(reason.startswith("tcp_downlink_above_shaped_rate") for reason in reasons))

    def test_qdisc_validation_matches_expected_netem_json(self):
        profile = {
            "kind": "namespace",
            "name": "unit",
            "one_way_delay_us": 22500,
            "one_way_jitter_us": 8000,
            "jitter_correlation_percent": 35,
            "loss_percent": 0.08,
            "loss_correlation_percent": 25,
            "downlink_bps": 50000000,
            "uplink_bps": 12000000,
            "queue_bdp": 1.5,
            "mtu_bytes": 1500,
            "trace": [],
        }
        qdisc = {
            "downlink": [
                {
                    "kind": "netem",
                    "options": {
                        "limit": self.mod.network_path.queue_packets(profile, 50000000),
                        "delay": {"delay": 0.0225, "jitter": 0.008},
                        "loss-random": {"loss": 0.0008},
                        "rate": {"rate": 6250000},
                    },
                }
            ],
            "uplink": [
                {
                    "kind": "netem",
                    "options": {
                        "limit": self.mod.network_path.queue_packets(profile, 12000000),
                        "delay": {"delay": 0.0225, "jitter": 0.008},
                        "loss-random": {"loss": 0.0008},
                        "rate": {"rate": 1500000},
                    },
                }
            ],
        }
        result = self.mod.validate_qdisc_snapshot(profile, qdisc)
        self.assertEqual(result["status"], "ok")


if __name__ == "__main__":
    unittest.main()
