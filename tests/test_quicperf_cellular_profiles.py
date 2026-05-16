#!/usr/bin/env python3
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "quicperf_cellular_profiles.py"


def load_module():
    spec = importlib.util.spec_from_file_location("quicperf_cellular_profiles", MODULE_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CellularProfileGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def args(self):
        return SimpleNamespace(
            source_name="unit source",
            source_url="https://example.test/unit",
            description="unit generated profile",
            window="first",
            max_steps=10,
            step_ms=1000,
            min_bps=64000,
            uplink_policy="ratio",
            uplink_ratio=0.20,
            min_uplink_bps=1000000,
            default_rtt_ms=40.0,
            default_jitter_ms=5.0,
            default_loss_percent=0.1,
            queue_bdp=1.5,
            jitter_correlation_percent=35,
            loss_correlation_percent=25,
            handover_outage_ms=250,
            handover_queue_bdp=0.25,
            zero_as_outage=True,
            zero_outage_bps=128000,
            zero_outage_loss_percent=35.0,
        )

    def test_normalized_trace_builds_dynamic_profile_with_handover_and_outage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.csv"
            path.write_text(
                "\n".join(
                    [
                        "timestamp_ms,downlink_bps,uplink_bps,rtt_ms,jitter_ms,loss_percent,cell_id,state",
                        "0,10000000,1000000,30,3,0,A,D",
                        "1000,0,0,100,20,0,A,I",
                        "2000,20000000,2000000,40,5,0,B,D",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            samples = self.mod.read_normalized_csv(path)
            profile = self.mod.build_profile(samples, self.args(), str(path))

        self.assertEqual(profile["description"], "unit generated profile")
        self.assertEqual(profile["one_way_delay_us"], 20000)
        self.assertTrue(any(step.get("event") == "handover-outage" for step in profile["trace"]))
        outage_steps = [step for step in profile["trace"] if step["downlink_bps"] == 64000 and "event" not in step]
        self.assertTrue(outage_steps)
        self.assertEqual(outage_steps[0]["loss_percent"], 35.0)

    def test_ucc_4g_reader_accepts_lte_schema(self):
        rows = [
            "Timestamp,Longitude,Latitude,Speed,Operatorname,CellID,NetworkMode,RSRP,RSRQ,SNR,CQI,RSSI,DL_bitrate,UL_bitrate,State,NRxRSRP,NRxRSRQ,ServingCell_Lon,ServingCell_Lat,ServingCell_Distance",
            "2017.11.22_10.07.03,-8.5,51.8,4,A,2,LTE,-119,-14,2.0,6,-94,5178,194,D,-120.0,-18.0,-8.49,51.89,609.7",
            "2017.11.22_10.07.04,-8.5,51.8,5,A,3,LTE,-116,-13,3.0,6,-94,6990,130,D,-119.0,-18.0,-8.49,51.89,609.7",
        ]
        samples = self.mod.read_ucc_4g_csv(rows)
        self.assertEqual(len(samples), 2)
        self.assertEqual(samples[0].downlink_bps, 5178000)
        self.assertEqual(samples[0].uplink_bps, 194000)
        self.assertEqual(samples[1].cell_id, "3")

    def test_5gophers_reader_filters_walking_trace_to_5g(self):
        rows = [
            "protocol,num_tcp_conn,seq_num,anonymized_mCid,radio_type,throughput_mbps,nrStatus,primitive_handoff_type",
            "TCP,8,1,3,4G,92.1,NOT_RESTRICTED,",
            "TCP,8,2,3,5G,227,CONNECTED,P2",
            "TCP,8,3,4,5G,94.3,CONNECTED,",
        ]
        samples = self.mod.read_5gophers_walking_csv(rows)
        self.assertEqual(len(samples), 2)
        self.assertEqual(samples[0].timestamp_ms, 1000)
        self.assertEqual(samples[0].downlink_bps, 227000000)
        self.assertEqual(samples[0].cell_id, "3")
        self.assertEqual(samples[1].cell_id, "4")

    def test_highest_median_window_prefers_best_window(self):
        samples = [
            self.mod.Sample(timestamp_ms=0, downlink_bps=1000, uplink_bps=1000),
            self.mod.Sample(timestamp_ms=1000, downlink_bps=2000, uplink_bps=1000),
            self.mod.Sample(timestamp_ms=2000, downlink_bps=9000, uplink_bps=1000),
            self.mod.Sample(timestamp_ms=3000, downlink_bps=8000, uplink_bps=1000),
        ]
        window = self.mod.select_window(samples, 2, "highest-median-downlink")
        self.assertEqual([sample.downlink_bps for sample in window], [9000, 8000])


if __name__ == "__main__":
    unittest.main()
