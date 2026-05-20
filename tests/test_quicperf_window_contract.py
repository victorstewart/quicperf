from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WindowContractTests(unittest.TestCase):
    def assertNoScenarioConfigPolicy(self, label, snippet):
        forbidden = (
            "benchmarkScenario",
            "BenchmarkScenario::",
            "benchmarkScenarioStreamsInFlight",
            "benchmarkScenarioOperations",
            "benchmarkIsLossRecovery",
            "benchmarkIsUpload",
            "benchmarkIsFlowControl",
        )
        for token in forbidden:
            with self.subTest(label=label, token=token):
                self.assertNotIn(token, snippet)

    def slice_source(self, source, start, end):
        return source[source.index(start) : source.index(end, source.index(start))]

    def test_xquic_depofile_does_not_patch_internal_receive_window_cap(self):
        depofile = (ROOT / "depofiles/xquic.DepoFile").read_text()
        self.assertNotIn("XQC_MAX_RECV_WINDOW", depofile)

    def test_quiczig_adapter_requests_profile_windows_without_clamping(self):
        source = (ROOT / "perf.packet_engine.h").read_text()
        self.assertNotIn(
            "config.connection_window = std::min<uint64_t>(benchmarkConnectionWindow",
            source,
        )
        self.assertNotIn(
            "config.stream_window = std::min<uint64_t>(benchmarkStreamWindow",
            source,
        )

    def test_quiczig_adapter_does_not_disable_library_pacing(self):
        source = (ROOT / "perf.packet_engine.h").read_text()
        self.assertNotIn("config.disable_pacing = true", source)

    def test_mvfst_pacing_is_not_disabled_by_scenario_policy(self):
        mvfst = (ROOT / "perf.mvfst.h").read_text()
        features = (ROOT / "perf.cpp").read_text()
        self.assertNotIn("benchmarkMvfstPacingEnabled", mvfst)
        self.assertNotIn("benchmarkMvfstPacingEnabled", features)
        self.assertNotIn('pacing=%s"', features)

    def test_datagram_capability_config_is_scenario_constant(self):
        lsquic = (ROOT / "perf.lsquic.h").read_text()
        xquic = (ROOT / "perf.xquic.h").read_text()
        tquic = (ROOT / "perf.tquic.h").read_text()
        mvfst = (ROOT / "perf.mvfst.h").read_text()
        ngtcp2 = (ROOT / "perf.ngtcp2.h").read_text()
        quiche = (ROOT / "perf.quiche.h").read_text()

        self.assertIn("settings.es_datagrams = 1;", lsquic)
        self.assertIn("settings.max_datagram_frame_size = benchmarkUdpPayloadSize;", xquic)
        self.assertIn("quic_config_set_max_datagram_frame_size(config, benchmarkUdpPayloadSize);", tquic)
        self.assertIn("settings.datagramConfig.enabled = true;", mvfst)
        self.assertEqual(ngtcp2.count("params.max_datagram_frame_size = benchmarkUdpPayloadSize;"), 2)
        self.assertIn("benchmarkDatagramQueueBytes", quiche)

        configure = tquic[tquic.index("  void configureTransport(void)") :]
        transport = mvfst[mvfst.index("  quic::TransportSettings transportSettings(void) const") :]
        set_socket = mvfst[mvfst.index("  void setSocket(std::shared_ptr<quic::QuicSocket> value)") :]
        self.assertNotIn("benchmarkScenario == BenchmarkScenario::datagram", configure[: configure.index("    const char *protos[]")])
        self.assertNotIn("benchmarkScenario == BenchmarkScenario::datagram", transport[: transport.index("    std::array<uint8_t")])
        self.assertNotIn("benchmarkScenario == BenchmarkScenario::datagram", set_socket[: set_socket.index("  void onConnectionSetupError")])
        self.assertNotIn("benchmarkScenarioStreamsInFlight", quiche[quiche.index("quiche_config_enable_dgram") : quiche.index("    quiche_config_enable_early_data")])

    def test_transport_config_setup_is_scenario_constant_per_adapter(self):
        packet_engine = (ROOT / "perf.packet_engine.h").read_text()
        picoquic = (ROOT / "perf.picoquic.h").read_text()
        lsquic = (ROOT / "perf.lsquic.h").read_text()
        quiche = (ROOT / "perf.quiche.h").read_text()
        xquic = (ROOT / "perf.xquic.h").read_text()
        tquic = (ROOT / "perf.tquic.h").read_text()
        mvfst = (ROOT / "perf.mvfst.h").read_text()
        ngtcp2 = (ROOT / "perf.ngtcp2.h").read_text()

        setup_slices = {
            "packet_engine.instanceSetup": self.slice_source(
                packet_engine,
                "  void instanceSetup(uint16_t localPort, int argc, char *argv[])",
                "  void connectToServer(struct sockaddr *address)",
            ),
            "picoquic.createConfiguredEngine": self.slice_source(
                picoquic,
                "  void createConfiguredEngine(const char *ticketStoreFile)",
                "  void instanceSetup(uint16_t localPort, int argc, char *argv[])",
            ),
            "picoquic.instanceSetup": self.slice_source(
                picoquic,
                "  void instanceSetup(uint16_t localPort, int argc, char *argv[])",
                "  void connectToServer(struct sockaddr *address)",
            ),
            "lsquic.instanceSetup": self.slice_source(
                lsquic,
                "  void instanceSetup(uint16_t localPort, int argc, char *argv[])",
                "  void connectToServer(struct sockaddr *address)",
            ),
            "quiche.instanceSetup": self.slice_source(
                quiche,
                "  void instanceSetup(uint16_t localPort, int argc, char *argv[])",
                "  void createClientConnection(struct sockaddr *address)",
            ),
            "xquic.benchmarkConnSettings": self.slice_source(
                xquic,
                "  static xqc_conn_settings_t benchmarkConnSettings(void)",
                "  void createEngine(void)",
            ),
            "tquic.configureTransport": self.slice_source(
                tquic,
                "  void configureTransport(void)",
                "  void advance(int32_t count = 0)",
            ),
            "mvfst.transportSettings": self.slice_source(
                mvfst,
                "  quic::TransportSettings transportSettings(void) const",
                "  void driveEvents(void)",
            ),
            "mvfst.setSocket": self.slice_source(
                mvfst,
                "  void setSocket(std::shared_ptr<quic::QuicSocket> value)",
                "  void onConnectionSetupError",
            ),
            "ngtcp2.server_transport_setup": self.slice_source(
                ngtcp2,
                "    ngtcp2_settings settings;\n    ngtcp2_settings_default(&settings);",
                "    if (auto rv = ngtcp2_conn_server_new",
            ),
            "ngtcp2.client_transport_setup": self.slice_source(
                ngtcp2,
                "    ngtcp2_settings settings;\n    ngtcp2_settings_default(&settings);",
                "    if (auto rv = ngtcp2_conn_client_new",
            ),
        }

        for label, snippet in setup_slices.items():
            self.assertNoScenarioConfigPolicy(label, snippet)

    def test_picoquic_packet_train_config_is_scenario_constant(self):
        source = (ROOT / "perf.picoquic.h").read_text()
        features = source[source.index("static inline const char *benchmarkPicoquicAdapterFeatures") :]
        setup = source[source.index("  void instanceSetup(uint16_t localPort, int argc, char *argv[])") :]

        self.assertNotIn("benchmarkIsLossRecovery", features[: features.index("  snprintf(")])
        self.assertNotIn("benchmarkIsLossRecovery", setup[: setup.index("    this->localPort = localPort;")])

    def test_tquic_sets_max_windows_before_initial_transport_params(self):
        source = (ROOT / "perf.tquic.h").read_text()
        configure = source[source.index("  void configureTransport(void)") :]

        max_conn = configure.index("quic_config_set_max_connection_window")
        max_stream = configure.index("quic_config_set_max_stream_window")
        initial_conn = configure.index("quic_config_set_initial_max_data")
        initial_stream_local = configure.index("quic_config_set_initial_max_stream_data_bidi_local")
        initial_stream_remote = configure.index("quic_config_set_initial_max_stream_data_bidi_remote")
        initial_stream_uni = configure.index("quic_config_set_initial_max_stream_data_uni")

        self.assertLess(max_conn, initial_conn)
        self.assertLess(max_stream, initial_stream_local)
        self.assertLess(max_stream, initial_stream_remote)
        self.assertLess(max_stream, initial_stream_uni)


if __name__ == "__main__":
    unittest.main()
