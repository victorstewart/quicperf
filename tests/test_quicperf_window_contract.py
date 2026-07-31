from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WindowContractTests(unittest.TestCase):
    def test_packet_engines_share_the_frozen_transport_and_tls_treatment(self) -> None:
        source = (ROOT / "perf.packet_engine.h").read_text(encoding="utf-8")
        setup = self.slice_source(
            source,
            "  void instanceSetup(uint16_t localPort, int argc, char *argv[])",
            "  void connectToServer(struct sockaddr *address)",
        )
        assignments = (
            "config.initial_congestion_window_bytes = 13'500;",
            "config.max_ack_delay_ns = 25'000'000;",
            "config.ack_delay_exponent = 3;",
            "config.ack_frequency = false;",
            "config.active_migration = false;",
            "config.active_connection_id_limit = 2;",
            "config.connection_id_bytes = 8;",
            "config.stream_credit_replenish_below = 32;",
            "config.udp_payload_size = 1'350;",
            "config.datagram_max_frame_size = 1'200;",
            "config.ticket_lifetime_ns = 300'000'000'000;",
            "config.maximum_early_data_bytes = 4'096;",
            "config.one_use_tickets = true;",
            "config.calendar_unix_seconds = benchmarkTlsCalendarUnixSeconds;",
        )
        for assignment in assignments:
            with self.subTest(assignment=assignment):
                self.assertEqual(setup.count(assignment), 1)
        self.assertLess(
            setup.index("config.calendar_unix_seconds = benchmarkTlsCalendarUnixSeconds;"),
            setup.index("config.tls_verify_peer"),
        )

    def test_zero_rtt_servers_share_the_asymmetric_stream_target(self) -> None:
        for name in (
            "perf.ngtcp2.h", "perf.lsquic.h", "perf.tquic.h", "perf.quiche.h",
            "perf.picoquic.h", "perf.xquic.h", "perf.packet_engine.h", "perf.mvfst.h",
        ):
            with self.subTest(name=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("benchmarkGenericServerTargetStreams()", source)

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

    def test_xquic_depofile_pins_receive_window_cap_to_frozen_treatment(self):
        depofile = (ROOT / "depofiles/xquic.DepoFile").read_text()
        self.assertEqual(
            depofile.count("-#define XQC_MAX_RECV_WINDOW (16 * 1024 * 1024)"), 1
        )
        self.assertEqual(
            depofile.count("+#define XQC_MAX_RECV_WINDOW (64 * 1024 * 1024)"), 1
        )

    def test_xquic_tls_and_transport_share_the_frozen_calendar(self):
        source = (ROOT / "perf.xquic.h").read_text(encoding="utf-8")
        self.assertIn(
            "value->tv_sec = static_cast<time_t>(benchmarkTlsCalendarUnixSeconds);",
            source,
        )
        self.assertIn("SSL_CTX_set_current_time_cb(ctx, xquicTlsCurrentTime);", source)
        self.assertIn(
            "return benchmarkTlsCalendarUnixSeconds * 1'000'000ULL;",
            source,
        )
        self.assertIn("engineCallbacks.realtime_ts = realtimeNow;", source)
        self.assertIn("engineCallbacks.monotonic_ts = monotonicNow;", source)

    def test_picoquic_uses_one_post_handshake_ready_predicate(self):
        source = (ROOT / "src/adapters/picoquic_adapter.cpp").read_text(
            encoding="utf-8"
        )
        helper = self.slice_source(
            source,
            "bool postHandshakeReady(picoquic_cnx_t* connection) noexcept",
            "bool disableOpenSslTimedReseeding()",
        )
        self.assertIn("state == picoquic_state_client_ready_start", helper)
        self.assertIn("state == picoquic_state_ready", helper)
        connected = self.slice_source(
            source,
            "bool PicoquicAdapter::isConnected(",
            "bool PicoquicAdapter::connectionIsClosed(",
        )
        snapshot = self.slice_source(
            source,
            "NegotiatedSettings PicoquicAdapter::snapshotNegotiatedSettings()",
            "bool PicoquicAdapter::reset(",
        )
        self.assertIn("postHandshakeReady(connection->native)", connected)
        self.assertEqual(snapshot.count("postHandshakeReady("), 1)
        self.assertIn("const auto activeForEvidence", snapshot)
        self.assertEqual(snapshot.count("activeForEvidence("), 2)

    def test_picoquic_batches_application_flow_control_credit(self):
        source = (ROOT / "src/adapters/picoquic_adapter.cpp").read_text(
            encoding="utf-8"
        )
        consume = self.slice_source(
            source,
            "bool PicoquicAdapter::consumeStreamData(",
            "bool PicoquicAdapter::finishStream(",
        )
        self.assertIn("uint64_t consumedCreditsPending = 0;", source)
        self.assertIn("const uint64_t creditQuantum = config_.streamWindow / 4;", consume)
        self.assertIn(
            "if (stream.consumedCreditsPending >= creditQuantum)", consume
        )
        self.assertIn(
            "stream.consumedCreditsPending % creditQuantum", consume
        )
        self.assertIn("available + grant", consume)
        self.assertIn("stream.consumedCreditsPending -= grant", consume)
        self.assertNotIn(
            "connection->native, streamId, read", consume
        )

    def test_picoquic_never_queues_stream_bytes_beyond_peer_credit(self):
        source = (ROOT / "src/adapters/picoquic_adapter.cpp").read_text(
            encoding="utf-8"
        )
        write = self.slice_source(
            source,
            "bool PicoquicAdapter::writeStream(",
            "bool PicoquicAdapter::consumeStreamData(",
        )
        self.assertIn("uint64_t acceptedSendBytes = 0;", source)
        self.assertIn(
            "nativeStream->maxdata_remote - stream.acceptedSendBytes", write
        )
        self.assertIn(
            "connection->native->maxdata_remote - "
            "connection->acceptedSendBytes",
            write,
        )
        self.assertIn("connection->acceptedSendBytes += written;", write)
        self.assertIn(
            "picoquic accepted stream bytes exceed peer flow-control credit",
            write,
        )

    def test_early_data_waits_for_post_handshake_treatment_evidence(self):
        workload = (ROOT / "src/core/workload_engine.cpp").read_text()
        refresh = self.slice_source(
            workload,
            "  bool refreshNegotiatedSettings(AdapterError& error)",
            "  bool retireClosedConnections(uint64_t now, AdapterError& error)",
        )
        self.assertLess(
            refresh.index("if (!current.available) return true;"),
            refresh.index("negotiatedSettingsMatch(current, config, mismatchReason)"),
        )

        rust = (ROOT / "rust-packet-ffi/src/lib.rs").read_text()
        s2n = rust[rust.index("    impl PacketEngine for S2nEngine {") :]
        snapshot = s2n[
            s2n.index("        fn negotiated_settings(") :
            s2n.index("\n        }\n    }\n\n    fn raw_waker()")
        ]
        self.assertIn("let Some(facts) = negotiated.get(&connection.event_id) else", snapshot)
        self.assertIn("if !facts.handshake_complete", snapshot)
        self.assertIn("let Some(transport) = facts.transport else", snapshot)
        self.assertNotIn("s2n TLS handshake completion is unavailable", snapshot)

    def test_ngtcp2_replenishes_peer_stream_credit_after_native_close(self):
        source = (ROOT / "src/adapters/ngtcp2_adapter.cpp").read_text(
            encoding="utf-8"
        )
        closed = self.slice_source(
            source,
            "int Ngtcp2Adapter::streamClosed(",
            "int Ngtcp2Adapter::streamReset(",
        )
        self.assertIn(
            "remoteInitiated(static_cast<uint64_t>(streamId), "
            "connection.owner.config_.role)",
            closed,
        )
        self.assertIn("ngtcp2_conn_extend_max_streams_bidi(conn, 1);", closed)
        self.assertIn("ngtcp2_conn_extend_max_streams_uni(conn, 1);", closed)

    def test_quiczig_silently_drops_unauthenticated_network_input(self):
        depofile = (ROOT / "depofiles/quiczig.DepoFile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '+                    std.log.debug("AES-128-GCM decryption failed: '
            '{any}", .{err});',
            depofile,
        )
        self.assertIn(
            '+            std.log.debug("Destination CID is too long '
            '({any} bytes)", .{dcid_length});',
            depofile,
        )

    def test_cross_stack_transport_defaults_and_stream_retirement_are_semantic(self):
        picoquic = (ROOT / "src/adapters/picoquic_adapter.cpp").read_text()
        self.assertIn("if (!config_.ackFrequency) parameters.min_ack_delay = 0;", picoquic)
        self.assertIn("result.ackFrequency = remote.min_ack_delay > 0;", picoquic)

        mvfst = (ROOT / "src/adapters/mvfst_adapter.cpp").read_text()
        self.assertIn('"ack_delay_exponent", 3);', mvfst)
        self.assertIn('"active_connection_id_limit", 2);', mvfst)

        xquic = self.slice_source(
            (ROOT / "src/adapters/xquic_adapter.cpp").read_text(),
            "bool XquicAdapter::consumeStreamData(",
            "bool XquicAdapter::finishStream(",
        )
        self.assertNotIn("findStream(", xquic)
        self.assertIn("stream->terminalFacts.fin", xquic)

        packet_engine = (ROOT / "rust-packet-ffi/src/lib.rs").read_text()
        self.assertIn(".pacing(true)", packet_engine)
        self.assertNotIn(".pacing(false)", packet_engine)
        self.assertIn("const APPLICATION_BUFFER_BYTES: u64 = 256 * 1024;", packet_engine)
        self.assertIn(".send_window(APPLICATION_BUFFER_BYTES)", packet_engine)
        self.assertNotIn(".send_window(config.connection_window)", packet_engine)
        self.assertIn("conn.quicperf_flow_control_blocked_events()", packet_engine)

        neqo = self.slice_source(
            packet_engine,
            "fn stream_send_capacity(",
            "fn connection_negotiated_settings(",
        )
        self.assertIn("conn.send_stream_stats", neqo)
        self.assertIn("stats.bytes_written().saturating_sub(stats.bytes_acked())", neqo)
        self.assertIn("APPLICATION_BUFFER_BYTES.saturating_sub(outstanding)", neqo)
        self.assertIn("conn.stream_avail_send_space(stream_id)", neqo)
        self.assertIn("const ANTI_REPLAY_HASHES: usize = 16;", packet_engine)
        self.assertIn("const ANTI_REPLAY_BITS: usize = 20;", packet_engine)
        self.assertIn("retirement_pending: bool", packet_engine)
        self.assertIn("if !self.retirement_pending", packet_engine)

        zig_adapter = (ROOT / "src/adapters/zig_packet_adapter.cpp").read_text()
        self.assertIn("quiczig-97a7bec-clockpatch-v3-common-v7", zig_adapter)
        self.assertIn("constexpr uint64_t applicationBufferBytes = 256 * 1024;", zig_adapter)
        self.assertIn("config.send_backlog_limit = applicationBufferBytes;", zig_adapter)
        zig_engine = (ROOT / "zig-packet-ffi/src/lib.zig").read_text()
        aggregate = self.slice_source(
            zig_engine,
            "    fn pendingAppBytes(conn: *connection.Connection) u64 {",
            "    fn clientConnForDatagram(",
        )
        self.assertIn("conn.streams.streams.valueIterator()", aggregate)
        self.assertIn("conn.streams.send_streams.valueIterator()", aggregate)
        self.assertIn("send.write_offset - send.ack_offset", aggregate)
        self.assertIn("qzf_engine_t.pendingAppBytes(conn)", zig_engine)

        quinn_patch = (ROOT / "depofiles/quinnsource.DepoFile").read_text()
        self.assertIn(
            "pub fn quicperf_flow_control_blocked_events(&self) -> (u64, u64)",
            quinn_patch,
        )
        self.assertIn(
            "self.state.stream_flow_control_blocked_events = self",
            quinn_patch,
        )

    def test_lifecycle_churn_preserves_active_capacity_and_treatment_evidence(self):
        tquic_patch = (ROOT / "depofiles/tquic.DepoFile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            ".filter(|conn| !conn.is_draining() && !conn.is_closed())",
            tquic_patch,
        )
        tquic_adapter = (ROOT / "src/adapters/tquic_adapter.cpp").read_text(
            encoding="utf-8"
        )
        closed = self.slice_source(
            tquic_adapter,
            "bool TquicAdapter::connectionIsClosed(",
            "bool TquicAdapter::peerTerminalFacts(",
        )
        self.assertIn("quic_conn_is_draining(connection.native)", closed)
        retry_finishes = self.slice_source(
            tquic_adapter,
            "bool TquicAdapter::retryPendingFinishes(",
            "void TquicAdapter::reapReleasedConnections()",
        )
        self.assertIn("std::deque<uint64_t> pendingFinishes", tquic_adapter)
        self.assertIn("connection->pendingFinishes.size()", retry_finishes)
        self.assertNotIn("for (auto& [streamId, stream]", retry_finishes)
        workload = (ROOT / "src/core/workload_engine.cpp").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("lifecycleCohortNegotiated", workload)
        self.assertIn("bool superseded = false;", workload)
        self.assertIn("bool logicalCurrent(const Connection& connection)", workload)
        self.assertIn("predecessor->second.superseded = true", workload)
        self.assertIn("std::map<uint32_t, uint64_t> latestLifecycleSequence", workload)
        self.assertIn("operationSequence <= latest->second", workload)
        self.assertIn("2 * sizeof(uint64_t)", workload)
        self.assertIn("bool carriesConnectionIdentity(Scenario scenario)", workload)
        self.assertIn(
            "std::map<uint32_t, uint64_t> retiredValidatedByOrdinal", workload
        )
        self.assertIn("retireValidated(connection, \"cleanup\", error)", workload)
        self.assertIn(
            "retireValidated(connection, \"observed cleanup-close\", error)",
            workload,
        )
        self.assertNotIn("retiredValidatedReconciled", workload)
        self.assertIn("logicalConnectionCount() != connectionCount", workload)
        self.assertIn("if (hasNegotiatedSettings &&", workload)
        self.assertIn("scenario != Scenario::closeResetCleanup ||", workload)
        self.assertIn("item.second.treatmentVerified", workload)
        queue_stops = self.slice_source(
            workload,
            "  bool queueStops(uint64_t now, AdapterError& error)",
            "  bool cleanupOperationsSettled() const",
        )
        reconciled = self.slice_source(
            workload,
            "  bool updateReconciled()",
            "  bool idleEstablished() const noexcept",
        )
        for source in (queue_stops, reconciled):
            self.assertIn("carriesConnectionIdentity(scenario)", source)
            self.assertIn("logicalConnectionCount() != connectionCount", source)
        self.assertIn(
            "client() && !isConnectionOperation(scenario)",
            workload,
        )
        self.assertIn(
            "!client() || !admitting || !hasNegotiatedSettings || now >= window.endRawNs",
            workload,
        )
        self.assertIn("client() && isFreshStreamOperation(scenario)", workload)
        self.assertIn("item.second.operationInFlight != 0", workload)
        self.assertIn(
            "Scenario::closeResetCleanup && connection.hasControlStream",
            workload,
        )
        self.assertIn(
            "completed its handshake without accepted early data",
            workload,
        )
        self.assertEqual(
            workload.count("adapter.releaseConnectionWhenClosed("),
            3,
        )
        quiche_adapter = (ROOT / "src/adapters/quiche_adapter.cpp").read_text(
            encoding="utf-8"
        )
        quiche_closed = self.slice_source(
            quiche_adapter,
            "bool QuicheAdapter::connectionIsClosed(",
            "PrimitiveStatus QuicheAdapter::openStream(",
        )
        self.assertIn("quiche_conn_is_draining(connection->native)", quiche_closed)
        ngtcp2_adapter = (ROOT / "src/adapters/ngtcp2_adapter.cpp").read_text(
            encoding="utf-8"
        )
        active = self.slice_source(
            ngtcp2_adapter,
            "bool Ngtcp2Adapter::active(const Connection& connection) noexcept",
            "Ngtcp2Adapter::Connection* Ngtcp2Adapter::find(",
        )
        self.assertIn("!connection.closePending", active)
        self.assertIn("!ngtcp2_conn_in_closing_period(connection.conn)", active)
        self.assertIn("!ngtcp2_conn_in_draining_period(connection.conn)", active)
        self.assertIn("if (&peer == &connection || !peer.handshakeCompleted) continue;", ngtcp2_adapter)
        self.assertEqual(ngtcp2_adapter.count("activeConnectionCount() >="), 2)
        self.assertIn(
            "activeConnectionCount() >= nativeConnectionLimit", ngtcp2_adapter
        )
        self.assertIn(
            "activeConnectionCount() >= config_.connectionCount", ngtcp2_adapter
        )
        closed = self.slice_source(
            ngtcp2_adapter,
            "bool Ngtcp2Adapter::connectionIsClosed(",
            "PrimitiveStatus Ngtcp2Adapter::openBidirectionalStream(",
        )
        self.assertIn("connection->remoteConnectionClose", closed)
        self.assertIn("ngtcp2_conn_in_draining_period(connection->conn)", closed)
        self.assertIn(
            "!quiche_conn_is_established(owned->native)", quiche_adapter
        )

    def test_quinn_endpoint_response_uses_the_buffer_that_produced_it(self):
        source = (ROOT / "rust-packet-ffi/src/lib.rs").read_text(encoding="utf-8")
        process = self.slice_source(
            source,
            "                fn process_datagram_event(",
            "                fn drive(&mut self, now_us: u64)",
        )
        self.assertIn("buf: &mut Vec<u8>", process)
        self.assertNotIn("let mut buf = Vec::with_capacity", process)
        self.assertIn("if size > buf.len()", process)
        self.assertIn("Err(error) =>", process)
        self.assertIn("if let Some(transmit) = error.response", process)
        self.assertIn("accept response exceeded produced buffer", process)
        self.assertNotIn("map_err(|e| format!(\"accept:", process)
        self.assertIn("retire_when_drained", source)
        self.assertIn("if event.is_drained()", source)
        self.assertIn("self.retired_transport_counters", source)
        self.assertIn("fn retire_connection(", source)
        receive = self.slice_source(
            source,
            "                fn receive(\n",
            "                fn poll_transmit(\n",
        )
        self.assertIn("self.process_datagram_event(event, now, &mut buf)?", receive)

    def test_rust_packet_primitives_publish_new_transport_deadlines(self):
        source = (ROOT / "src/adapters/rust_packet_adapter.cpp").read_text(
            encoding="utf-8"
        )
        completion = self.slice_source(
            source,
            "bool RustPacketAdapter::completeOperation(",
            "bool RustPacketAdapter::onTimeout(",
        )
        self.assertIn(
            "assignScalarError(status, error) && updateTimeout(nowRawNs, error)",
            completion,
        )
        self.assertEqual(source.count("assignScalarError("), 2)
        write = self.slice_source(
            source,
            "bool RustPacketAdapter::writeStream(",
            "bool RustPacketAdapter::consumeStreamData(",
        )
        self.assertIn("return completeOperation(qpf_stream_send(", write)

    def test_fixed_connection_workloads_cache_negotiated_treatment_evidence(self):
        source = (ROOT / "src/core/workload_engine.cpp").read_text(encoding="utf-8")
        refresh = self.slice_source(
            source,
            "  bool refreshNegotiatedSettings(AdapterError& error)",
            "  bool retireClosedConnections(",
        )
        self.assertIn("if (hasNegotiatedSettings &&", refresh)
        self.assertIn("scenario != Scenario::closeResetCleanup ||", refresh)
        self.assertIn("item.second.treatmentVerified", refresh)
        self.assertIn(
            '"established connection set changed negotiated treatment evidence"',
            refresh,
        )

    def test_rust_packet_engine_bounds_cross_connection_transmit_queuing(self):
        source = (ROOT / "rust-packet-ffi/src/lib.rs").read_text(encoding="utf-8")
        drive = self.slice_source(
            source,
            "                fn drive(&mut self, now_us: u64)",
            "            impl PacketEngine for $engine_name",
        )
        self.assertIn("let collect_transmits = self.outbound.is_empty();", drive)
        self.assertIn("if collect_transmits {", drive)
        self.assertIn("if let Some(transmit) =", drive)
        self.assertNotIn("while let Some(transmit) =", drive)
        poll = self.slice_source(
            source,
            "                fn poll_transmit(\n",
            "                fn next_timeout_us(",
        )
        self.assertIn("if self.outbound.is_empty() {", poll)
        self.assertIn("self.drive(now_us)?;", poll)

    def test_rust_packet_stream_primitives_defer_global_drive_to_io_boundary(self):
        source = (ROOT / "rust-packet-ffi/src/lib.rs").read_text(encoding="utf-8")
        sections = (
            ("fn open_bidi(", "fn accept_bidi("),
            ("fn accept_bidi(", "fn open_uni("),
            ("fn open_uni(", "fn accept_uni("),
            ("fn accept_uni(", "fn stream_send("),
            ("fn stream_send(", "fn stream_recv("),
            ("fn stream_recv(", "fn stream_finish("),
            ("fn stream_finish(", "fn stream_reset("),
            ("fn stream_reset(", "fn stream_stop_sending("),
            ("fn stream_stop_sending(", "fn connection_close("),
        )
        packet_engine = source[source.index("            impl PacketEngine for $engine_name") :]
        for start, end in sections:
            with self.subTest(primitive=start):
                primitive = self.slice_source(packet_engine, start, end)
                self.assertNotIn("self.drive(", primitive)

    def test_neqo_engine_bounds_output_to_one_packet_per_connection_round(self):
        source = (ROOT / "rust-packet-ffi/src/lib.rs").read_text(encoding="utf-8")
        drive = self.slice_source(
            source,
            "        fn drive_output(&mut self, now: Instant)",
            "        fn drain_client_events(",
        )
        self.assertEqual(drive.count("process_output(now)"), 2)
        self.assertNotIn("loop {", drive)
        self.assertNotIn("transmit_batch_limit", source)

    def test_picoquic_separates_quic_ticket_wire_value_from_workload_limit(self):
        source = (ROOT / "src/adapters/picoquic_adapter.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "constexpr uint32_t quicEarlyDataTicketLimit = "
            "std::numeric_limits<uint32_t>::max();",
            source,
        )
        self.assertIn("tls->max_early_data_size = quicEarlyDataTicketLimit;", source)
        self.assertIn(
            "result.maximumEarlyDataBytes = config_.tlsMaximumEarlyDataBytes;",
            source,
        )
        capture = self.slice_source(
            source,
            "bool PicoquicAdapter::captureResumptionState(",
            "int PicoquicAdapter::callback(",
        )
        self.assertIn("connection.native->issued_ticket_id", capture)
        self.assertIn("connection.resumptionState.resize", capture)
        receive = self.slice_source(
            source,
            "bool PicoquicAdapter::receiveBatch(",
            "size_t PicoquicAdapter::pollTransmitBatch(",
        )
        self.assertIn("picoquic_incoming_packet_ex", receive)
        self.assertIn("captureResumptionState(*found->second, error)", receive)
        export = self.slice_source(
            source,
            "PrimitiveStatus PicoquicAdapter::exportResumptionState(",
            "PrimitiveStatus PicoquicAdapter::importResumptionState(",
        )
        self.assertIn("c->resumptionState", export)
        self.assertNotIn("picoquic_get_ticket_and_version", export)

    def test_quiche_server_does_not_claim_an_unperformed_retry(self):
        source = (ROOT / "src/adapters/quiche_adapter.cpp").read_text(
            encoding="utf-8"
        )
        create_server = self.slice_source(
            source,
            "QuicheAdapter::Connection* QuicheAdapter::createServer(",
            "bool QuicheAdapter::receiveBatch(",
        )
        self.assertIn(
            "cid.data(), cid.size(), nullptr, 0,",
            create_server,
        )
        self.assertNotIn(
            "cid.data(), cid.size(), header.dcid.data(), header.dcidLength,",
            create_server,
        )

    def test_reset_exercise_waits_for_exact_negotiated_treatment(self):
        source = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
        exercise = self.slice_source(
            source,
            "if (arm.type == MessageType::exercise)",
            "if (arm.type != MessageType::arm",
        )
        self.assertIn(
            "snapshot.liveConnections && snapshot.counters.admitted &&\n"
            "                  snapshot.negotiatedSettingsMatch",
            exercise,
        )

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

    def test_datagram_contract_uses_unique_peer_validated_echoes(self):
        sources = "\n".join(path.read_text() for path in ROOT.glob("perf.*.h"))
        stats = (ROOT / "tools/quicperf_stats.py").read_text()
        perf = (ROOT / "perf.cpp").read_text()
        docs = (ROOT / "docs/methodology.md").read_text()
        workload = (ROOT / "src/core/workload_engine.cpp").read_text()
        endpoint = (ROOT / "src/main.cpp").read_text()

        self.assertIn("benchmarkDatagramDrainUs", sources)
        self.assertIn("benchmarkEncodeDatagramSequence", (ROOT / "perf.benchmark.h").read_text())
        self.assertNotIn("DATAGRAM delivery target not reached", sources)
        self.assertNotIn("datagram_delivery_ratio_min", stats)
        self.assertIn("datagramMetricValue", perf)
        self.assertIn("unique validated 64-byte QUIC DATAGRAM echoes", docs)
        self.assertIn("constexpr uint64_t datagramDrainNs = 100'000'000ULL;", workload)
        self.assertIn("connection.datagramsOutstanding.clear();", workload)
        self.assertIn('\",\\\"unreturned\\\":\"', endpoint)
        self.assertNotIn("accepted-send budget", docs)
        self.assertNotIn("tquicperf` remains unsupported", docs)

    def test_xquic_post_perf_completion_drain_is_bounded(self):
        xquic = (ROOT / "perf.xquic.h").read_text()
        post = self.slice_source(xquic, "  void postPerfTest(void) override", "  bool supportsZeroRtt")

        self.assertIn("const uint64_t deadlineUs = timeNowUs() + 1'000'000;", post)
        self.assertIn("while (timeNowUs() < deadlineUs", post)
        self.assertNotIn("while (!clientCompletionAckReceived", post)

    def test_xquic_server_accepts_download_done_marker_without_fin(self):
        compiler = os.environ.get("CXX", "c++")
        source = ROOT / "tests" / "xquic_download_done_contract.cpp"
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "xquic-download-done-contract"
            compiled = subprocess.run(
                [compiler, "-std=c++20", "-I", str(ROOT), str(source), "-o", str(executable)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout)
            executed = subprocess.run(
                [str(executable)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(executed.returncode, 0, executed.stdout)

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

    def test_static_admission_replaces_only_never_established_connections(self):
        source = (ROOT / "src/adapters/xquic_adapter.cpp").read_text()
        admission = self.slice_source(
            source,
            "size_t XquicAdapter::activeServerConnections() const noexcept",
            "uint64_t XquicAdapter::serverConnectionLimit() const noexcept",
        )
        self.assertIn(
            "if (item.second->closed && !item.second->connected) return false;",
            admission,
        )
        self.assertIn(
            "return !replaceClosing || "
            "(!item.second->closed && !item.second->closing);",
            admission,
        )

        workload = (ROOT / "src/core/workload_engine.cpp").read_text()
        retirement = self.slice_source(
            workload,
            "  bool retireFailedStaticServerConnections(",
            "  bool pumpConnections(",
        )
        pump = self.slice_source(
            workload,
            "  bool pumpConnections(",
            "  bool refreshNegotiatedSettings(",
        )
        self.assertIn("if (client() || isConnectionOperation(scenario) ||", retirement)
        self.assertIn("scenario == Scenario::closeResetCleanup) return true;", retirement)
        self.assertIn(
            "if (connection.retired || connection.connected) continue;",
            retirement,
        )
        self.assertIn("adapter.connectionIsClosed(", retirement)
        self.assertIn("adapter.releaseConnectionWhenClosed(", retirement)
        self.assertLess(
            pump.index("retireFailedStaticServerConnections(now, error)"),
            pump.index("acceptConnections(now, error)"),
        )

    def test_xquic_negotiated_snapshot_excludes_closing_predecessors(self):
        source = (ROOT / "src/adapters/xquic_adapter.cpp").read_text()
        snapshot = self.slice_source(
            source,
            "NegotiatedSettings XquicAdapter::snapshotNegotiatedSettings()",
            "bool XquicAdapter::reset(",
        )
        self.assertIn(
            "if (!connection->conn || connection->closing || "
            "connection->closed) continue;",
            snapshot,
        )

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
