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

    def test_datagram_payloads_are_bounded_by_effective_frame_limits(self):
        benchmark = (ROOT / "perf.benchmark.h").read_text()
        lsquic = (ROOT / "perf.lsquic.h").read_text()
        xquic = (ROOT / "perf.xquic.h").read_text()
        tquic = (ROOT / "perf.tquic.h").read_text()
        mvfst = (ROOT / "perf.mvfst.h").read_text()
        ngtcp2 = (ROOT / "perf.ngtcp2.h").read_text()
        quiche = (ROOT / "perf.quiche.h").read_text()
        picoquic = (ROOT / "perf.picoquic.h").read_text()
        packet_engine = (ROOT / "perf.packet_engine.h").read_text()

        self.assertIn("benchmarkDatagramPayloadLimitForFrameBytes", benchmark)
        self.assertIn("benchmarkDatagramNoMssApiPayloadBytes", benchmark)
        self.assertIn("benchmarkQuicVarintEncodedBytes", benchmark)
        self.assertIn("quiche_conn_dgram_max_writable_len", quiche)
        self.assertIn("getDatagramSizeLimit()", mvfst)
        self.assertIn("xqc_datagram_get_mss", xquic)
        self.assertIn("ngtcp2_conn_get_remote_transport_params", ngtcp2)
        self.assertIn("benchmarkDatagramPayloadBytesForNoMssApiLimit", tquic)
        self.assertIn("benchmarkDatagramPayloadBytesForNoMssApiLimit", lsquic)
        self.assertIn("benchmarkDatagramPayloadBytesForNoMssApiLimit", picoquic)
        self.assertIn("benchmarkDatagramPayloadBytesForNoMssApiLimit", packet_engine)

    def test_datagram_contract_is_send_budget_not_reliable_delivery(self):
        sources = "\n".join(path.read_text() for path in ROOT.glob("perf.*.h"))
        stats = (ROOT / "tools/quicperf_stats.py").read_text()
        perf = (ROOT / "perf.cpp").read_text()
        docs = (ROOT / "docs/methodology.md").read_text()

        self.assertIn("benchmarkDatagramDrainUs", sources)
        self.assertIn("benchmarkEncodeDatagramSequence", (ROOT / "perf.benchmark.h").read_text())
        self.assertNotIn("DATAGRAM delivery target not reached", sources)
        self.assertNotIn("datagram_delivery_ratio_min", stats)
        self.assertIn("datagramMetricValue", perf)
        self.assertIn("accepted-send budget", docs)
        self.assertNotIn("tquicperf` remains unsupported", docs)

    def test_xquic_post_perf_completion_drain_is_bounded(self):
        xquic = (ROOT / "perf.xquic.h").read_text()
        post = self.slice_source(xquic, "  void postPerfTest(void) override", "  bool supportsZeroRtt")

        self.assertIn("const uint64_t deadlineUs = timeNowUs() + 1'000'000;", post)
        self.assertIn("while (timeNowUs() < deadlineUs", post)
        self.assertNotIn("while (!clientCompletionAckReceived", post)

    def test_xquic_server_accepts_download_done_marker_without_fin(self):
        xquic = (ROOT / "perf.xquic.h").read_text()
        read_server = self.slice_source(
            xquic,
            "  void readFromServerStream(ServerStreamState& state, xqc_stream_t *activeStream)",
            "  void writeToStream(xqc_stream_t *activeStream)",
        )

        self.assertIn("!benchmarkIsUpload() && state.requestParsed && state.bytesInFlight == 0", read_server)
        self.assertIn("consumed < static_cast<size_t>(read)", read_server)
        self.assertIn("state.clientDone = true;", read_server)
        self.assertIn("writeToServerStream(state, activeStream);", read_server)

    def test_xquic_iouring_continues_all_server_connections_after_socket_backpressure(self):
        xquic = (ROOT / "perf.xquic.h").read_text()
        continuation = self.slice_source(
            xquic,
            "  void continueBlockedSocketWrite(void)",
            "  static ssize_t sendOne",
        )
        conn_create = self.slice_source(
            xquic,
            "  static int connCreate(",
            "  static int connClose(",
        )
        conn_close = self.slice_source(
            xquic,
            "  static int connClose(",
            "  static void handshakeDone(",
        )

        self.assertIn("std::vector<xqc_connection_t *> activeConnections;", xquic)
        self.assertIn("rememberConnection(connection);", conn_create)
        self.assertIn("forgetConnection(connection);", conn_close)
        self.assertIn("if constexpr (mode & Mode::server)", continuation)
        self.assertIn("auto connections = activeConnections;", continuation)
        self.assertIn("for (xqc_connection_t *activeConn : connections)", continuation)
        self.assertIn("std::find(activeConnections.begin(), activeConnections.end(), activeConn)", continuation)
        self.assertIn("xqc_conn_continue_send_by_conn(activeConn);", continuation)

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
