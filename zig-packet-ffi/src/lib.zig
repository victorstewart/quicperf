const std = @import("std");
const quic = @import("quic");

pub const std_options: std.Options = .{ .log_level = .err };

const connection = quic.connection;
const connection_manager = quic.connection_manager;
const net = quic.sockaddr;
const tls13 = quic.tls13;
const posix = std.posix;
const Certificate = std.crypto.Certificate;
const c = std.c;

const ALPN = "qperf/2";
const TLS_HOSTNAME = "server.quicperf.test";
const MAX_PACKET = 1500;

pub const QzfAddr = extern struct {
    ip: [16]u8,
    port: u16,
};

pub const QzfConfig = extern struct {
    is_server: bool,
    local_addr: QzfAddr,
    peer_addr: QzfAddr,
    cert_path: [*:0]const u8,
    key_path: [*:0]const u8,
    chain_path: [*:0]const u8,
    tls_verify_peer: bool,
    use_bbr: bool,
    disable_pacing: bool,
    connection_window: u64,
    stream_window: u64,
    max_bidi_streams: u64,
    max_uni_streams: u64,
    idle_timeout_ms: u64,
    udp_payload_size: u32,
    datagram_max_frame_size: u64,
    send_backlog_limit: u64,
    now_us: u64,
    calendar_unix_seconds: u64,
};

const QZF_PACKET_ABI_VERSION: u32 = 6;
const QZF_PACKET_BATCH_CAPACITY: usize = 64;

pub const QzfReceiveDescriptorV2 = extern struct {
    data: [*]const u8,
    len: usize,
    peer: QzfAddr,
    ecn: u8,
    reserved: [7]u8,
};

pub const QzfTransmitDescriptorV2 = extern struct {
    data: [*]u8,
    capacity: usize,
    len: usize,
    peer: QzfAddr,
    ecn: u8,
    reserved: [7]u8,
    desired_send_raw_ns: u64,
};

pub const QzfAdapterStatusV2 = extern struct {
    code: i32,
    reserved: u32,
    message: [256]u8,
};

pub const QzfTransportCountersV3 = extern struct {
    packets_lost: u64 = 0,
    packets_retransmitted: u64 = 0,
    recovery_wakeups: u64 = 0,
    flow_control_blocked_events: u64 = 0,
    stream_credit_blocked_events: u64 = 0,
};

pub const QzfStreamDebug = extern struct {
    found: bool = false,
    send_write_offset: u64 = 0,
    send_send_offset: u64 = 0,
    send_ack_offset: u64 = 0,
    send_window: u64 = 0,
    send_retransmit_count: u64 = 0,
    send_fin_queued: bool = false,
    send_fin_sent: bool = false,
    send_fin_lost: bool = false,
    send_has_data: bool = false,
    send_has_unacked: bool = false,
    recv_read_pos: u64 = 0,
    recv_highest_buffered: u64 = 0,
    recv_fin_offset: u64 = 0,
    recv_fin_known: bool = false,
    recv_finished: bool = false,
    recv_chunk_count: u64 = 0,
    bytes_in_flight: u64 = 0,
    cwnd: u64 = 0,
    conn_send_window: u64 = 0,
};

pub const QzfPeerTerminalFactsV6 = extern struct {
    available: bool = false,
    fin: bool = false,
    reset_stream: bool = false,
    stop_sending: bool = false,
    connection_close: bool = false,
    reserved: [3]u8 = .{0} ** 3,
    reset_stream_error: u64 = 0,
    stop_sending_error: u64 = 0,
    connection_close_error: u64 = 0,
    connection_close_reason_length: u64 = 0,
};

const PeerCloseFacts = struct {
    error_code: u64,
    reason_length: u64,
};

pub const QzfNegotiated = extern struct {
    available: bool = false,
    peer_certificate_verified: bool = false,
    hostname_verified: bool = false,
    active_migration: bool = false,
    ack_frequency: bool = false,
    reserved: [3]u8 = .{0} ** 3,
    quic_version: u32 = 0,
    tls_cipher_suite: u16 = 0,
    tls_named_group: u16 = 0,
    max_udp_payload_size: u64 = 0,
    max_ack_delay_ns: u64 = 0,
    ack_delay_exponent: u64 = 0,
    active_connection_id_limit: u64 = 0,
    connection_id_bytes: u64 = 0,
    max_idle_timeout_ns: u64 = 0,
    max_bidi_streams: u64 = 0,
    max_uni_streams: u64 = 0,
    connection_window_bytes: u64 = 0,
    stream_window_bytes: u64 = 0,
    datagram_max_frame_size: u64 = 0,
};

const StreamKey = struct {
    conn_id: u64,
    stream_id: u64,
};

const RecvBacklog = struct {
    data: []const u8,
    offset: usize = 0,
};

const Outbound = struct {
    remote: posix.sockaddr.storage,
    data: []u8,
};

const SendSnapshot = struct {
    stream_count: u64 = 0,
    app_pending: u64 = 0,
    app_unsent: u64 = 0,
    app_unacked: u64 = 0,
    write_offset_total: u64 = 0,
    send_offset_total: u64 = 0,
    ack_offset_total: u64 = 0,
    bytes_in_flight: u64 = 0,
    cwnd: u64 = 0,
    conn_send_window: u64 = 0,
    min_stream_send_window: u64 = 0,
    pacer_budget: u64 = 0,
    pacer_bandwidth: u64 = 0,
    pacer_delay_ns: i64 = 0,
    cc_limited: bool = false,
    pacer_delayed: bool = false,
    flow_blocked: bool = false,
    no_app_data: bool = true,
};

const SendTraceStats = struct {
    app_write_calls: u64 = 0,
    app_write_bytes: u64 = 0,
    app_write_blocked: u64 = 0,
    poll_attempts: u64 = 0,
    packets_emitted: u64 = 0,
    bytes_emitted: u64 = 0,
    zero_sends: u64 = 0,
    send_errors: u64 = 0,
    send_advance_events: u64 = 0,
    send_advance_bytes: u64 = 0,
    recv_datagrams: u64 = 0,
    recv_bytes: u64 = 0,
    ack_progress_events: u64 = 0,
    ack_progress_bytes: u64 = 0,
    conn_credit_events: u64 = 0,
    conn_credit_bytes: u64 = 0,
    stream_credit_events: u64 = 0,
    stream_credit_bytes: u64 = 0,
    bif_drop_events: u64 = 0,
    bif_drop_bytes: u64 = 0,
    cwnd_growth_events: u64 = 0,
    cwnd_growth_bytes: u64 = 0,
    cc_limited_polls: u64 = 0,
    pacer_delayed_polls: u64 = 0,
    flow_blocked_polls: u64 = 0,
    no_app_data_polls: u64 = 0,
    waiting_ack_polls: u64 = 0,
    starved_polls: u64 = 0,
    app_pending_max: u64 = 0,
    app_unsent_max: u64 = 0,
    app_unacked_max: u64 = 0,
    bytes_in_flight_max: u64 = 0,
    cwnd_min: u64 = std.math.maxInt(u64),
    cwnd_max: u64 = 0,
    conn_send_window_min: u64 = std.math.maxInt(u64),
    stream_send_window_min: u64 = std.math.maxInt(u64),
    last: SendSnapshot = .{},
};

const TraceConnSnapshot = struct {
    conn_id: u64,
    state: SendSnapshot,
};

pub const qzf_engine_t = struct {
    allocator: std.mem.Allocator,
    is_server: bool,
    tls_verify_peer: bool,
    local_addr: posix.sockaddr.storage,
    remote_addr: ?posix.sockaddr.storage = null,
    tls_config: tls13.TlsConfig,
    imported_session_ticket: tls13.SessionTicket = .{ .psk = .{0} ** 32 },
    has_imported_session_ticket: bool = false,
    imported_zero_rtt: bool = false,
    imported_ticket_digest: [32]u8 = .{0} ** 32,
    consumed_ticket_digests: std.AutoHashMap([32]u8, void),
    zero_rtt_attempted: std.AutoHashMap(u64, bool),
    conn_config: connection.ConnectionConfig,
    private_key: []u8,
    cert_chain: [][]const u8,
    ca_bundle: ?*Certificate.Bundle,
    alpn: []const []const u8,
    udp_payload_size: usize,
    client_conns: std.AutoHashMap(u64, *connection.Connection),
    next_client_conn_id: u64 = 1,
    server: ?connection_manager.ConnectionManager = null,
    server_conns: std.AutoHashMap(u64, *connection.Connection),
    server_conn_ids: std.AutoHashMap(*connection.Connection, u64),
    next_server_conn_id: u64 = 1,
    next_server_send_index: usize,
    accepted_connections: std.ArrayList(u64),
    known_connections: std.AutoHashMap(u64, void),
    peer_closed_connections: std.AutoHashMap(u64, PeerCloseFacts),
    accepted_streams: std.AutoHashMap(StreamKey, void),
    accepted_stream_keys: std.ArrayList(StreamKey),
    recv_backlog: std.AutoHashMap(StreamKey, RecvBacklog),
    recv_backlog_keys: std.ArrayList(StreamKey),
    outbound: std.ArrayList(Outbound),
    send_backlog_limit: u64,
    disable_pacing: bool,
    trace_enabled: bool,
    send_stats: std.AutoHashMap(u64, SendTraceStats),

    fn deinit(self: *qzf_engine_t) void {
        self.printSendTrace();
        self.send_stats.deinit();
        self.zero_rtt_attempted.deinit();
        self.consumed_ticket_digests.deinit();
        var client_it = self.client_conns.valueIterator();
        while (client_it.next()) |conn| {
            conn.*.deinit();
            self.allocator.destroy(conn.*);
        }
        self.client_conns.deinit();
        self.server_conns.deinit();
        self.server_conn_ids.deinit();
        if (self.server) |*server| server.deinit();
        for (self.outbound.items) |out| self.allocator.free(out.data);
        self.outbound.deinit(self.allocator);
        var backlog_it = self.recv_backlog.valueIterator();
        while (backlog_it.next()) |pending| self.allocator.free(pending.data);
        self.recv_backlog.deinit();
        self.recv_backlog_keys.deinit(self.allocator);
        self.accepted_streams.deinit();
        self.accepted_stream_keys.deinit(self.allocator);
        self.known_connections.deinit();
        self.peer_closed_connections.deinit();
        self.accepted_connections.deinit(self.allocator);
        if (self.ca_bundle) |bundle| {
            bundle.deinit(self.allocator);
            self.allocator.destroy(bundle);
        }
        for (self.cert_chain) |cert| self.allocator.free(cert);
        self.allocator.free(self.cert_chain);
        self.allocator.free(self.alpn);
        self.allocator.free(self.private_key);
        self.allocator.destroy(self);
    }

    fn connById(self: *qzf_engine_t, conn_id: u64) ?*connection.Connection {
        return if (self.is_server) self.server_conns.get(conn_id) else self.client_conns.get(conn_id);
    }

    fn pendingAppBytes(conn: *connection.Connection) u64 {
        var total: u64 = 0;
        var bidi = conn.streams.streams.valueIterator();
        while (bidi.next()) |stream_ptr| {
            const send = &stream_ptr.*.send;
            total = total +| (send.write_offset - send.ack_offset);
        }
        var uni = conn.streams.send_streams.valueIterator();
        while (uni.next()) |send_ptr| {
            const send = send_ptr.*;
            total = total +| (send.write_offset - send.ack_offset);
        }
        return total;
    }

    fn clientConnForDatagram(self: *qzf_engine_t, data: []const u8) ?*connection.Connection {
        if (self.client_conns.count() == 1) {
            var only = self.client_conns.valueIterator();
            return only.next().?.*;
        }
        if (data.len < 2) return null;
        const long_header = (data[0] & 0x80) != 0;
        const dcid = if (long_header) blk: {
            if (data.len < 6) return null;
            const len: usize = data[5];
            if (data.len < 6 + len) return null;
            break :blk data[6..][0..len];
        } else data[1..];
        var it = self.client_conns.valueIterator();
        while (it.next()) |conn_ptr| {
            const conn = conn_ptr.*;
            if (conn.ownsLocalConnectionId(dcid, long_header)) return conn;
        }
        return null;
    }

    fn queueResponse(self: *qzf_engine_t, remote: posix.sockaddr.storage, bytes: []const u8) !void {
        const owned = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(owned);
        try self.outbound.append(self.allocator, .{ .remote = remote, .data = owned });
    }

    fn tuneConn(self: *qzf_engine_t, conn: *connection.Connection) void {
        conn.packer.max_packet_size = @min(self.udp_payload_size, MAX_PACKET);
        if (self.disable_pacing) {
            conn.pacer.bandwidth_shifted = 0;
            conn.pacer.budget = conn.pacer.max_burst;
        }
    }

    fn prepareSend(self: *qzf_engine_t, conn: *connection.Connection) void {
        if (self.disable_pacing) {
            conn.pacer.bandwidth_shifted = 0;
            conn.pacer.budget = conn.pacer.max_burst;
        }
    }

    fn sendTraceStats(self: *qzf_engine_t, conn_id: u64) !*SendTraceStats {
        if (self.send_stats.getPtr(conn_id)) |stats| return stats;
        try self.send_stats.put(conn_id, .{});
        return self.send_stats.getPtr(conn_id).?;
    }

    fn pacerDelayNs(conn: *const connection.Connection, now: i64) i64 {
        if (conn.pacer.bandwidth_shifted == 0) return 0;
        var budget = conn.pacer.budget;
        if (conn.pacer.last_sent_time > 0 and now > conn.pacer.last_sent_time) {
            const elapsed = now - conn.pacer.last_sent_time;
            const replenished = (conn.pacer.bandwidth_shifted *| @as(u64, @intCast(elapsed))) >> 20;
            budget = @min(budget + replenished, conn.pacer.max_burst);
        }
        if (budget >= conn.pacer.max_datagram_size) return 0;
        const deficit = conn.pacer.max_datagram_size - budget;
        return @intCast((deficit << 20) / conn.pacer.bandwidth_shifted);
    }

    fn inspectSendState(conn: *connection.Connection) SendSnapshot {
        const now = conn.pacer.last_sent_time;
        var snapshot = SendSnapshot{
            .bytes_in_flight = conn.pkt_handler.bytes_in_flight,
            .cwnd = conn.cc.sendWindow(),
            .conn_send_window = conn.conn_flow_ctrl.sendWindowSize(),
            .pacer_budget = conn.pacer.budget,
            .pacer_bandwidth = conn.pacer.bandwidth_shifted,
            .pacer_delay_ns = pacerDelayNs(conn, now),
        };
        snapshot.cc_limited = snapshot.bytes_in_flight >= snapshot.cwnd and conn.pto_probe_pending == 0;
        snapshot.pacer_delayed = snapshot.pacer_delay_ns > 0 and conn.pto_probe_pending == 0;

        var min_stream_window: u64 = std.math.maxInt(u64);
        var stream_it = conn.streams.streams.valueIterator();
        while (stream_it.next()) |stream_ptr| {
            const stream = stream_ptr.*;
            const send = &stream.send;
            const app_pending = send.write_offset - send.ack_offset;
            const app_unsent = send.write_offset - send.send_offset;
            const app_unacked = send.send_offset - send.ack_offset;
            if (app_pending == 0 and !send.hasData()) continue;

            snapshot.stream_count += 1;
            snapshot.app_pending += app_pending;
            snapshot.app_unsent += app_unsent;
            snapshot.app_unacked += app_unacked;
            snapshot.write_offset_total += send.write_offset;
            snapshot.send_offset_total += send.send_offset;
            snapshot.ack_offset_total += send.ack_offset;

            const stream_window = if (send.send_window > send.send_offset)
                send.send_window - send.send_offset
            else
                0;
            min_stream_window = @min(min_stream_window, stream_window);
            if (send.hasData() and (stream_window == 0 or snapshot.conn_send_window == 0)) {
                snapshot.flow_blocked = true;
            }
        }
        if (min_stream_window != std.math.maxInt(u64)) {
            snapshot.min_stream_send_window = min_stream_window;
        }
        snapshot.no_app_data = snapshot.app_pending == 0 and snapshot.app_unsent == 0;
        if (snapshot.conn_send_window == 0 and snapshot.app_pending > 0) {
            snapshot.flow_blocked = true;
        }
        return snapshot;
    }

    fn updateTraceExtrema(stats: *SendTraceStats, snapshot: SendSnapshot) void {
        stats.app_pending_max = @max(stats.app_pending_max, snapshot.app_pending);
        stats.app_unsent_max = @max(stats.app_unsent_max, snapshot.app_unsent);
        stats.app_unacked_max = @max(stats.app_unacked_max, snapshot.app_unacked);
        stats.bytes_in_flight_max = @max(stats.bytes_in_flight_max, snapshot.bytes_in_flight);
        stats.cwnd_min = @min(stats.cwnd_min, snapshot.cwnd);
        stats.cwnd_max = @max(stats.cwnd_max, snapshot.cwnd);
        stats.conn_send_window_min = @min(stats.conn_send_window_min, snapshot.conn_send_window);
        if (snapshot.min_stream_send_window > 0 or snapshot.stream_count > 0) {
            stats.stream_send_window_min = @min(stats.stream_send_window_min, snapshot.min_stream_send_window);
        }
    }

    fn recordAppWriteTrace(self: *qzf_engine_t, conn_id: u64, written: usize, blocked: bool) void {
        if (!self.trace_enabled or !self.is_server) return;
        const stats = self.sendTraceStats(conn_id) catch return;
        stats.app_write_calls += 1;
        stats.app_write_bytes += written;
        if (blocked) stats.app_write_blocked += 1;
    }

    fn captureServerTrace(self: *qzf_engine_t, snapshots: []TraceConnSnapshot) usize {
        if (!self.trace_enabled or !self.is_server) return 0;
        if (self.server) |*server| {
            var count: usize = 0;
            for (server.entries.items) |entry| {
                if (count == snapshots.len) break;
                const conn_id = self.server_conn_ids.get(entry.conn) orelse continue;
                snapshots[count] = .{
                    .conn_id = conn_id,
                    .state = inspectSendState(entry.conn),
                };
                count += 1;
            }
            return count;
        }
        return 0;
    }

    fn findTraceSnapshot(snapshots: []const TraceConnSnapshot, conn_id: u64) ?SendSnapshot {
        for (snapshots) |snapshot| {
            if (snapshot.conn_id == conn_id) return snapshot.state;
        }
        return null;
    }

    fn recordReceiveTrace(self: *qzf_engine_t, remote: *const posix.sockaddr.storage, recv_len: usize, before: []const TraceConnSnapshot) void {
        if (!self.trace_enabled or !self.is_server) return;
        if (self.server) |*server| {
            for (server.entries.items) |entry| {
                const conn_id = self.server_conn_ids.get(entry.conn) orelse continue;
                const after = inspectSendState(entry.conn);
                const stats = self.sendTraceStats(conn_id) catch continue;
                if (sameEndpoint(entry.conn.peerAddress(), remote)) {
                    stats.recv_datagrams += 1;
                    stats.recv_bytes += recv_len;
                }
                if (findTraceSnapshot(before, conn_id)) |prev| {
                    if (after.ack_offset_total > prev.ack_offset_total) {
                        stats.ack_progress_events += 1;
                        stats.ack_progress_bytes += after.ack_offset_total - prev.ack_offset_total;
                    }
                    if (after.conn_send_window > prev.conn_send_window) {
                        stats.conn_credit_events += 1;
                        stats.conn_credit_bytes += after.conn_send_window - prev.conn_send_window;
                    }
                    if (after.min_stream_send_window > prev.min_stream_send_window and after.stream_count > 0 and prev.stream_count > 0) {
                        stats.stream_credit_events += 1;
                        stats.stream_credit_bytes += after.min_stream_send_window - prev.min_stream_send_window;
                    }
                    if (prev.bytes_in_flight > after.bytes_in_flight) {
                        stats.bif_drop_events += 1;
                        stats.bif_drop_bytes += prev.bytes_in_flight - after.bytes_in_flight;
                    }
                    if (after.cwnd > prev.cwnd) {
                        stats.cwnd_growth_events += 1;
                        stats.cwnd_growth_bytes += after.cwnd - prev.cwnd;
                    }
                }
                updateTraceExtrema(stats, after);
                stats.last = after;
            }
        }
    }

    fn recordSendTrace(self: *qzf_engine_t, conn_id: u64, before: SendSnapshot, after: SendSnapshot, sent_len: usize, failed: bool) void {
        if (!self.trace_enabled or !self.is_server) return;
        const stats = self.sendTraceStats(conn_id) catch return;
        stats.poll_attempts += 1;
        if (sent_len > 0) {
            stats.packets_emitted += 1;
            stats.bytes_emitted += sent_len;
            if (after.send_offset_total > before.send_offset_total) {
                stats.send_advance_events += 1;
                stats.send_advance_bytes += after.send_offset_total - before.send_offset_total;
            }
        } else {
            stats.zero_sends += 1;
        }
        if (failed) stats.send_errors += 1;
        if (before.cc_limited) stats.cc_limited_polls += 1;
        if (before.pacer_delayed) stats.pacer_delayed_polls += 1;
        if (before.flow_blocked) stats.flow_blocked_polls += 1;
        if (before.no_app_data) stats.no_app_data_polls += 1;
        if (sent_len == 0 and !failed and before.app_pending > 0 and before.app_unsent == 0) {
            stats.waiting_ack_polls += 1;
        }
        if (sent_len == 0 and !failed and before.app_unsent > 0 and !before.cc_limited and !before.pacer_delayed and !before.flow_blocked) {
            stats.starved_polls += 1;
        }
        updateTraceExtrema(stats, before);
        updateTraceExtrema(stats, after);
        stats.last = after;
    }

    fn printSendTrace(self: *qzf_engine_t) void {
        if (!self.trace_enabled or !self.is_server) return;
        var total_polls: u64 = 0;
        var total_packets: u64 = 0;
        var total_bytes: u64 = 0;
        var total_recv: u64 = 0;
        var total_ack_bytes: u64 = 0;
        var total_send_advance_bytes: u64 = 0;
        var it = self.send_stats.iterator();
        while (it.next()) |entry| {
            const conn_id = entry.key_ptr.*;
            const stats = entry.value_ptr.*;
            total_polls += stats.poll_attempts;
            total_packets += stats.packets_emitted;
            total_bytes += stats.bytes_emitted;
            total_recv += stats.recv_datagrams;
            total_ack_bytes += stats.ack_progress_bytes;
            total_send_advance_bytes += stats.send_advance_bytes;
            const cwnd_min = if (stats.cwnd_min == std.math.maxInt(u64)) 0 else stats.cwnd_min;
            const conn_window_min = if (stats.conn_send_window_min == std.math.maxInt(u64)) 0 else stats.conn_send_window_min;
            const stream_window_min = if (stats.stream_send_window_min == std.math.maxInt(u64)) 0 else stats.stream_send_window_min;
            std.debug.print(
                "quiczig_ffi_send_trace kind=app conn={d} app_write_calls={d} app_write_bytes={d} app_write_blocked={d} polls={d} packets={d} bytes={d} zero={d} errors={d} send_advance_events={d} send_advance_bytes={d}\n",
                .{
                    conn_id,
                    stats.app_write_calls,
                    stats.app_write_bytes,
                    stats.app_write_blocked,
                    stats.poll_attempts,
                    stats.packets_emitted,
                    stats.bytes_emitted,
                    stats.zero_sends,
                    stats.send_errors,
                    stats.send_advance_events,
                    stats.send_advance_bytes,
                },
            );
            std.debug.print(
                "quiczig_ffi_send_trace kind=recv conn={d} recv_datagrams={d} recv_bytes={d} ack_progress_events={d} ack_progress_bytes={d} conn_credit_events={d} conn_credit_bytes={d} stream_credit_events={d} stream_credit_bytes={d} bif_drop_events={d} bif_drop_bytes={d} cwnd_growth_events={d} cwnd_growth_bytes={d} cc_limited={d} pacer_delayed={d} flow_blocked={d} waiting_ack={d} starved_unsent={d} no_app_data={d}\n",
                .{
                    conn_id,
                    stats.recv_datagrams,
                    stats.recv_bytes,
                    stats.ack_progress_events,
                    stats.ack_progress_bytes,
                    stats.conn_credit_events,
                    stats.conn_credit_bytes,
                    stats.stream_credit_events,
                    stats.stream_credit_bytes,
                    stats.bif_drop_events,
                    stats.bif_drop_bytes,
                    stats.cwnd_growth_events,
                    stats.cwnd_growth_bytes,
                    stats.cc_limited_polls,
                    stats.pacer_delayed_polls,
                    stats.flow_blocked_polls,
                    stats.waiting_ack_polls,
                    stats.starved_polls,
                    stats.no_app_data_polls,
                },
            );
            std.debug.print(
                "quiczig_ffi_send_trace kind=state conn={d} app_pending_max={d} app_unsent_max={d} app_unacked_max={d} bif_max={d} cwnd_min={d} cwnd_max={d} conn_window_min={d} stream_window_min={d} last_streams={d} last_app_pending={d} last_app_unsent={d} last_app_unacked={d} last_bif={d} last_cwnd={d} last_conn_window={d} last_stream_window={d} last_pacer_budget={d} last_pacer_bw={d} last_pacer_delay_ns={d}\n",
                .{
                    conn_id,
                    stats.app_pending_max,
                    stats.app_unsent_max,
                    stats.app_unacked_max,
                    stats.bytes_in_flight_max,
                    cwnd_min,
                    stats.cwnd_max,
                    conn_window_min,
                    stream_window_min,
                    stats.last.stream_count,
                    stats.last.app_pending,
                    stats.last.app_unsent,
                    stats.last.app_unacked,
                    stats.last.bytes_in_flight,
                    stats.last.cwnd,
                    stats.last.conn_send_window,
                    stats.last.min_stream_send_window,
                    stats.last.pacer_budget,
                    stats.last.pacer_bandwidth,
                    stats.last.pacer_delay_ns,
                },
            );
        }
        std.debug.print("quiczig_ffi_send_trace_total conns={d} polls={d} packets={d} bytes={d} recv_datagrams={d} send_advance_bytes={d} ack_progress_bytes={d}\n", .{ self.send_stats.count(), total_polls, total_packets, total_bytes, total_recv, total_send_advance_bytes, total_ack_bytes });
    }

    fn registerServerConnection(self: *qzf_engine_t, entry: *connection_manager.ConnEntry) !void {
        self.tuneConn(entry.conn);
        if (self.server_conn_ids.contains(entry.conn)) return;
        const conn_id = self.next_server_conn_id;
        self.next_server_conn_id = std.math.add(u64, conn_id, 1) catch return error.ConnectionIdExhausted;
        try self.server_conn_ids.put(entry.conn, conn_id);
        errdefer _ = self.server_conn_ids.remove(entry.conn);
        try self.server_conns.put(conn_id, entry.conn);
        errdefer _ = self.server_conns.remove(conn_id);
        try self.known_connections.put(conn_id, {});
        errdefer _ = self.known_connections.remove(conn_id);
        try self.accepted_connections.append(self.allocator, conn_id);
    }

    fn unregisterServerConnection(self: *qzf_engine_t, conn: *connection.Connection) void {
        const conn_id = self.server_conn_ids.get(conn) orelse return;
        _ = self.server_conn_ids.remove(conn);
        _ = self.server_conns.remove(conn_id);
    }

    fn scanServerConnections(self: *qzf_engine_t) !void {
        if (self.server) |*server| {
            for (server.entries.items) |entry| try self.registerServerConnection(entry);
        }
    }

    fn latchPeerCloseFacts(self: *qzf_engine_t) !void {
        var client_it = self.client_conns.iterator();
        while (client_it.next()) |entry| {
            if (entry.value_ptr.*.peerApplicationClose()) |close|
                try self.peer_closed_connections.put(entry.key_ptr.*, .{
                    .error_code = close.error_code,
                    .reason_length = close.reason_length,
                });
        }
        var server_it = self.server_conns.iterator();
        while (server_it.next()) |entry| {
            if (entry.value_ptr.*.peerApplicationClose()) |close|
                try self.peer_closed_connections.put(entry.key_ptr.*, .{
                    .error_code = close.error_code,
                    .reason_length = close.reason_length,
                });
        }
    }

    fn onTimeoutAll(self: *qzf_engine_t) void {
        var closed_clients = std.ArrayList(u64){ .items = &.{}, .capacity = 0 };
        defer closed_clients.deinit(self.allocator);
        var client_it = self.client_conns.iterator();
        while (client_it.next()) |entry| {
            entry.value_ptr.*.onTimeout() catch {};
            if (entry.value_ptr.*.isClosed())
                closed_clients.append(self.allocator, entry.key_ptr.*) catch {};
        }
        for (closed_clients.items) |conn_id| {
            const conn = self.client_conns.fetchRemove(conn_id) orelse continue;
            self.purgeConnectionState(conn_id);
            conn.value.deinit();
            self.allocator.destroy(conn.value);
        }
        if (self.server) |*server| {
            var i: usize = 0;
            while (i < server.entries.items.len) {
                const entry = server.entries.items[i];
                if (!server.tickEntry(entry)) {
                    self.unregisterServerConnection(entry.conn);
                    continue;
                }
                i += 1;
            }
            server.freeDeadEntries();
        }
    }

    fn nextTimeoutRawNs(self: *qzf_engine_t) ?u64 {
        var best: ?i64 = null;
        var client_it = self.client_conns.valueIterator();
        while (client_it.next()) |conn| {
            if (conn.*.nextTimeoutNs()) |deadline| best = deadline;
        }
        if (self.server) |*server| {
            for (server.entries.items) |entry| {
                if (entry.conn.nextTimeoutNs()) |deadline| {
                    if (best == null or deadline < best.?) best = deadline;
                }
            }
        }
        const deadline = best orelse return null;
        if (deadline <= 0) return 1;
        return @intCast(deadline);
    }

    fn nextTimeoutUs(self: *qzf_engine_t, now_ns: u64) ?u64 {
        const deadline = self.nextTimeoutRawNs() orelse return null;
        if (deadline <= now_ns) return 0;
        return (deadline - now_ns) / 1000;
    }

    fn receive(self: *qzf_engine_t, remote: posix.sockaddr.storage, data: []u8) !void {
        if (self.is_server) {
            if (self.server) |*server| {
                var before_buf: [128]TraceConnSnapshot = undefined;
                const before_count = self.captureServerTrace(before_buf[0..]);
                var out: [MAX_PACKET]u8 = undefined;
                switch (server.recvDatagram(data, remote, self.local_addr, 0, &out)) {
                    .processed => |entry| {
                        try self.registerServerConnection(entry);
                    },
                    .send_response => |bytes| try self.queueResponse(remote, bytes),
                    .dropped => {},
                }
                self.recordReceiveTrace(&remote, data.len, before_buf[0..before_count]);
            } else {
                return error.NotServer;
            }
            try self.scanServerConnections();
        } else {
            var conn = self.clientConnForDatagram(data) orelse return;
            conn.handleDatagram(data, .{
                .to = self.local_addr,
                .from = remote,
                .ecn = 0,
                .datagram_size = data.len,
            });
        }
        try self.latchPeerCloseFacts();
    }

    fn pollTransmit(self: *qzf_engine_t, out: []u8) !?struct { remote: posix.sockaddr.storage, len: usize } {
        if (self.outbound.items.len > 0) {
            const queued = self.outbound.orderedRemove(0);
            defer self.allocator.free(queued.data);
            if (queued.data.len > out.len) return error.OutputTooSmall;
            @memcpy(out[0..queued.data.len], queued.data);
            return .{ .remote = queued.remote, .len = queued.data.len };
        }

        var client_it = self.client_conns.valueIterator();
        while (client_it.next()) |conn_ptr| {
            const conn = conn_ptr.*;
            self.prepareSend(conn);
            const len = try conn.send(out);
            if (len > 0) {
                return .{ .remote = self.remote_addr orelse conn.peerAddress().*, .len = len };
            }
        }

        if (self.server) |*server| {
            const entry_count = server.entries.items.len;
            if (entry_count == 0) return null;
            const start = self.next_server_send_index % entry_count;
            var offset: usize = 0;
            while (offset < entry_count) : (offset += 1) {
                const index = (start + offset) % entry_count;
                const entry = server.entries.items[index];
                self.prepareSend(entry.conn);
                const conn_id = self.server_conn_ids.get(entry.conn) orelse continue;
                const should_trace = self.trace_enabled and self.is_server;
                const before = if (should_trace) inspectSendState(entry.conn) else SendSnapshot{};
                const len = entry.conn.send(out) catch {
                    if (should_trace) self.recordSendTrace(conn_id, before, inspectSendState(entry.conn), 0, true);
                    continue;
                };
                if (should_trace) self.recordSendTrace(conn_id, before, inspectSendState(entry.conn), len, false);
                if (len > 0) {
                    self.next_server_send_index = (index + 1) % entry_count;
                    return .{ .remote = entry.conn.peerAddress().*, .len = len };
                }
            }
        }
        return null;
    }

    fn scanAcceptedBidi(self: *qzf_engine_t, conn_id: u64, conn: *connection.Connection) !?u64 {
        var it = conn.streams.streams.iterator();
        while (it.next()) |kv| {
            const stream = kv.value_ptr.*;
            const stream_id = stream.stream_id;
            if (!isBidi(stream_id) or isLocal(stream_id, conn.is_server)) continue;
            const key = StreamKey{ .conn_id = conn_id, .stream_id = stream_id };
            if (self.accepted_streams.get(key) != null) continue;
            try self.accepted_streams.put(key, {});
            errdefer _ = self.accepted_streams.remove(key);
            try self.accepted_stream_keys.append(self.allocator, key);
            return stream_id;
        }
        return null;
    }

    fn scanAcceptedUni(self: *qzf_engine_t, conn_id: u64, conn: *connection.Connection) !?u64 {
        var it = conn.streams.recv_streams.iterator();
        while (it.next()) |kv| {
            const stream_id = kv.key_ptr.*;
            if (isBidi(stream_id) or isLocal(stream_id, conn.is_server)) continue;
            const key = StreamKey{ .conn_id = conn_id, .stream_id = stream_id };
            if (self.accepted_streams.get(key) != null) continue;
            try self.accepted_streams.put(key, {});
            errdefer _ = self.accepted_streams.remove(key);
            try self.accepted_stream_keys.append(self.allocator, key);
            return stream_id;
        }
        return null;
    }

    fn readBacklog(self: *qzf_engine_t, key: StreamKey, data: []u8) ?usize {
        const pending = self.recv_backlog.getPtr(key) orelse return null;
        const remaining = pending.data[pending.offset..];
        const n = @min(data.len, remaining.len);
        if (n > 0) @memcpy(data[0..n], remaining[0..n]);
        pending.offset += n;
        if (pending.offset == pending.data.len) {
            self.allocator.free(pending.data);
            _ = self.recv_backlog.remove(key);
            self.removeTrackedKey(&self.recv_backlog_keys, key);
        }
        return n;
    }

    fn saveBacklog(self: *qzf_engine_t, key: StreamKey, chunk: []const u8, offset: usize) !void {
        if (offset == chunk.len) {
            self.allocator.free(chunk);
            return;
        }
        errdefer self.allocator.free(chunk);
        try self.recv_backlog.put(key, .{ .data = chunk, .offset = offset });
        errdefer _ = self.recv_backlog.remove(key);
        try self.recv_backlog_keys.append(self.allocator, key);
    }

    fn removeTrackedKey(_: *qzf_engine_t, keys: *std.ArrayList(StreamKey), key: StreamKey) void {
        for (keys.items, 0..) |candidate, index| {
            if (candidate.conn_id == key.conn_id and candidate.stream_id == key.stream_id) {
                _ = keys.swapRemove(index);
                return;
            }
        }
    }

    fn purgeConnectionState(self: *qzf_engine_t, conn_id: u64) void {
        var accepted_index: usize = 0;
        while (accepted_index < self.accepted_stream_keys.items.len) {
            const key = self.accepted_stream_keys.items[accepted_index];
            if (key.conn_id != conn_id) {
                accepted_index += 1;
                continue;
            }
            _ = self.accepted_streams.remove(key);
            _ = self.accepted_stream_keys.swapRemove(accepted_index);
        }
        var backlog_index: usize = 0;
        while (backlog_index < self.recv_backlog_keys.items.len) {
            const key = self.recv_backlog_keys.items[backlog_index];
            if (key.conn_id != conn_id) {
                backlog_index += 1;
                continue;
            }
            if (self.recv_backlog.fetchRemove(key)) |removed|
                self.allocator.free(removed.value.data);
            _ = self.recv_backlog_keys.swapRemove(backlog_index);
        }
    }
};

var last_error_buf: [512:0]u8 = [_:0]u8{0} ** 512;

fn isBidi(stream_id: u64) bool {
    return (stream_id & 0x02) == 0;
}

fn isLocal(stream_id: u64, is_server: bool) bool {
    const server_initiated = (stream_id & 0x01) != 0;
    return server_initiated == is_server;
}

fn storeError(comptime fmt: []const u8, args: anytype) c_int {
    const rendered = std.fmt.bufPrintZ(&last_error_buf, fmt, args) catch blk: {
        @memcpy(last_error_buf[0.."zig packet ffi error".len], "zig packet ffi error");
        last_error_buf["zig packet ffi error".len] = 0;
        break :blk last_error_buf[0.."zig packet ffi error".len :0];
    };
    _ = rendered;
    return -1;
}

fn clearError() void {
    last_error_buf[0] = 0;
}

fn setCallerTimeRaw(now_raw_ns: u64) void {
    quic.sys.setCallerTimeNs(@intCast(@min(now_raw_ns, @as(u64, std.math.maxInt(i64)))));
}

fn setCallerTimeUs(now_us: u64) void {
    setCallerTimeRaw(now_us *| 1000);
}

fn cstr(ptr: [*:0]const u8) []const u8 {
    return std.mem.span(ptr);
}

fn envFlag(name: [*:0]const u8) bool {
    const value = quic.sys.getenv(name) orelse return false;
    return value.len > 0 and !std.mem.eql(u8, value, "0") and !std.mem.eql(u8, value, "false");
}

const RESUMPTION_MAGIC = "QZFRTT01";

const ResumptionStateError = error{
    BufferTooSmall,
    InvalidResumptionState,
};

fn writeBytes(out: []u8, pos: *usize, bytes: []const u8) ResumptionStateError!void {
    if (pos.* + bytes.len > out.len) return error.BufferTooSmall;
    @memcpy(out[pos.*..][0..bytes.len], bytes);
    pos.* += bytes.len;
}

fn writeU8(out: []u8, pos: *usize, value: u8) ResumptionStateError!void {
    if (pos.* + 1 > out.len) return error.BufferTooSmall;
    out[pos.*] = value;
    pos.* += 1;
}

fn writeU16(out: []u8, pos: *usize, value: u16) ResumptionStateError!void {
    if (pos.* + 2 > out.len) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[pos.*..][0..2], value, .big);
    pos.* += 2;
}

fn writeU32(out: []u8, pos: *usize, value: u32) ResumptionStateError!void {
    if (pos.* + 4 > out.len) return error.BufferTooSmall;
    std.mem.writeInt(u32, out[pos.*..][0..4], value, .big);
    pos.* += 4;
}

fn writeI64(out: []u8, pos: *usize, value: i64) ResumptionStateError!void {
    if (pos.* + 8 > out.len) return error.BufferTooSmall;
    std.mem.writeInt(i64, out[pos.*..][0..8], value, .big);
    pos.* += 8;
}

fn writeU64(out: []u8, pos: *usize, value: u64) ResumptionStateError!void {
    if (pos.* + 8 > out.len) return error.BufferTooSmall;
    std.mem.writeInt(u64, out[pos.*..][0..8], value, .big);
    pos.* += 8;
}

fn readBytes(data: []const u8, pos: *usize, len: usize) ResumptionStateError![]const u8 {
    if (pos.* + len > data.len) return error.InvalidResumptionState;
    const out = data[pos.*..][0..len];
    pos.* += len;
    return out;
}

fn readU8(data: []const u8, pos: *usize) ResumptionStateError!u8 {
    return (try readBytes(data, pos, 1))[0];
}

fn readU16(data: []const u8, pos: *usize) ResumptionStateError!u16 {
    return std.mem.readInt(u16, (try readBytes(data, pos, 2))[0..2], .big);
}

fn readU32(data: []const u8, pos: *usize) ResumptionStateError!u32 {
    return std.mem.readInt(u32, (try readBytes(data, pos, 4))[0..4], .big);
}

fn readI64(data: []const u8, pos: *usize) ResumptionStateError!i64 {
    return std.mem.readInt(i64, (try readBytes(data, pos, 8))[0..8], .big);
}

fn readU64(data: []const u8, pos: *usize) ResumptionStateError!u64 {
    return std.mem.readInt(u64, (try readBytes(data, pos, 8))[0..8], .big);
}

fn serializeResumptionTicket(ticket: *const tls13.SessionTicket, out: []u8) ResumptionStateError!usize {
    const ticket_len: usize = ticket.ticket_len;
    const alpn_len: usize = ticket.alpn_len;
    if (ticket_len > ticket.ticket.len or alpn_len > ticket.alpn.len) return error.InvalidResumptionState;

    var pos: usize = 0;
    try writeBytes(out, &pos, RESUMPTION_MAGIC);
    try writeBytes(out, &pos, &ticket.psk);
    try writeU16(out, &pos, ticket.ticket_len);
    try writeBytes(out, &pos, ticket.ticket[0..ticket_len]);
    try writeU32(out, &pos, ticket.ticket_age_add);
    try writeI64(out, &pos, ticket.creation_time);
    try writeU32(out, &pos, ticket.lifetime);
    try writeU32(out, &pos, ticket.max_early_data_size);
    try writeU8(out, &pos, ticket.alpn_len);
    try writeBytes(out, &pos, ticket.alpn[0..alpn_len]);
    try writeU64(out, &pos, ticket.initial_max_data);
    try writeU64(out, &pos, ticket.initial_max_stream_data_bidi_local);
    try writeU64(out, &pos, ticket.initial_max_stream_data_bidi_remote);
    try writeU64(out, &pos, ticket.initial_max_stream_data_uni);
    try writeU64(out, &pos, ticket.initial_max_streams_bidi);
    try writeU64(out, &pos, ticket.initial_max_streams_uni);
    try writeU64(out, &pos, ticket.active_connection_id_limit);
    return pos;
}

fn parseResumptionTicket(data: []const u8) ResumptionStateError!tls13.SessionTicket {
    var pos: usize = 0;
    const magic = try readBytes(data, &pos, RESUMPTION_MAGIC.len);
    if (!std.mem.eql(u8, magic, RESUMPTION_MAGIC)) return error.InvalidResumptionState;

    var ticket: tls13.SessionTicket = .{ .psk = .{0} ** 32 };
    @memcpy(&ticket.psk, try readBytes(data, &pos, ticket.psk.len));

    const ticket_len = try readU16(data, &pos);
    if (ticket_len > ticket.ticket.len) return error.InvalidResumptionState;
    @memcpy(ticket.ticket[0..ticket_len], try readBytes(data, &pos, ticket_len));
    ticket.ticket_len = ticket_len;

    ticket.ticket_age_add = try readU32(data, &pos);
    ticket.creation_time = try readI64(data, &pos);
    ticket.lifetime = try readU32(data, &pos);
    ticket.max_early_data_size = try readU32(data, &pos);

    const alpn_len = try readU8(data, &pos);
    if (alpn_len > ticket.alpn.len) return error.InvalidResumptionState;
    @memcpy(ticket.alpn[0..alpn_len], try readBytes(data, &pos, alpn_len));
    ticket.alpn_len = alpn_len;

    ticket.initial_max_data = try readU64(data, &pos);
    ticket.initial_max_stream_data_bidi_local = try readU64(data, &pos);
    ticket.initial_max_stream_data_bidi_remote = try readU64(data, &pos);
    ticket.initial_max_stream_data_uni = try readU64(data, &pos);
    ticket.initial_max_streams_bidi = try readU64(data, &pos);
    ticket.initial_max_streams_uni = try readU64(data, &pos);
    ticket.active_connection_id_limit = try readU64(data, &pos);

    if (pos != data.len) return error.InvalidResumptionState;
    return ticket;
}

fn qzfToSockaddr(addr: *const QzfAddr) posix.sockaddr.storage {
    var parsed = net.Address.parseIp6("::", addr.port) catch unreachable;
    @memcpy(parsed.in6.sa.addr[0..], addr.ip[0..]);
    return connection.sockaddrToStorage(&parsed.any);
}

fn sockaddrToQzf(addr: *const posix.sockaddr.storage) QzfAddr {
    if (addr.family == posix.AF.INET6) {
        const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
        return .{ .ip = in6.addr, .port = std.mem.bigToNative(u16, in6.port) };
    }
    const in4: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
    var ip: [16]u8 = .{0} ** 16;
    ip[10] = 0xff;
    ip[11] = 0xff;
    const bytes = std.mem.asBytes(&in4.addr);
    @memcpy(ip[12..16], bytes[0..4]);
    return .{ .ip = ip, .port = std.mem.bigToNative(u16, in4.port) };
}

fn sameEndpoint(a: *const posix.sockaddr.storage, b: *const posix.sockaddr.storage) bool {
    const qa = sockaddrToQzf(a);
    const qb = sockaddrToQzf(b);
    return qa.port == qb.port and std.mem.eql(u8, qa.ip[0..], qb.ip[0..]);
}

fn loadFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return quic.sys.readFileAlloc(allocator, path, 1 << 20);
}

fn makeEngine(config: *const QzfConfig) !*qzf_engine_t {
    const allocator = std.heap.c_allocator;
    if (config.calendar_unix_seconds == 0 or
        config.calendar_unix_seconds > std.math.maxInt(i64))
        return error.InvalidCalendarTime;
    const calendar_unix_seconds: i64 = @intCast(config.calendar_unix_seconds);
    const cert_pem = try loadFile(allocator, cstr(config.cert_path));
    defer allocator.free(cert_pem);
    const key_pem = try loadFile(allocator, cstr(config.key_path));
    defer allocator.free(key_pem);
    const chain_pem = try loadFile(allocator, cstr(config.chain_path));
    defer allocator.free(chain_pem);
    const served_chain_pem = try std.mem.concat(allocator, u8, &.{ cert_pem, "\n", chain_pem });
    defer allocator.free(served_chain_pem);

    const cert_chain = try tls13.parsePemCertChain(allocator, served_chain_pem);
    errdefer {
        for (cert_chain) |cert| allocator.free(cert);
        allocator.free(cert_chain);
    }

    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(key_pem, &key_der_buf);
    var private_key_algorithm: tls13.PrivateKeyAlgorithm = .ecdsa_p256_sha256;
    const key = tls13.extractEcPrivateKey(key_der) catch tls13.extractPkcs8EcPrivateKey(key_der) catch blk: {
        private_key_algorithm = .ed25519;
        break :blk try tls13.extractEd25519PrivateKey(key_der);
    };
    const private_key = try allocator.dupe(u8, key);
    errdefer allocator.free(private_key);

    var ca_bundle: ?*Certificate.Bundle = null;
    errdefer if (ca_bundle) |bundle| {
        bundle.deinit(allocator);
        allocator.destroy(bundle);
    };
    if (!config.is_server and config.tls_verify_peer) {
        const trusted_chain = try tls13.parsePemCertChain(allocator, chain_pem);
        defer {
            for (trusted_chain) |cert| allocator.free(cert);
            allocator.free(trusted_chain);
        }
        const bundle = try allocator.create(Certificate.Bundle);
        bundle.* = Certificate.Bundle.empty;
        ca_bundle = bundle;
        for (trusted_chain) |cert| {
            const decoded_start: u32 = @intCast(bundle.bytes.items.len);
            try bundle.bytes.appendSlice(allocator, cert);
            try bundle.parseCert(allocator, decoded_start, calendar_unix_seconds);
        }
    }

    const alpn = try allocator.alloc([]const u8, 1);
    errdefer allocator.free(alpn);
    alpn[0] = ALPN;

    var ticket_key: [16]u8 = undefined;
    quic.sys.randomBytes(&ticket_key);
    var retry_token_key: [16]u8 = undefined;
    quic.sys.randomBytes(&retry_token_key);
    var static_reset_key: [16]u8 = undefined;
    quic.sys.randomBytes(&static_reset_key);

    const tls_config = tls13.TlsConfig{
        .cert_chain_der = cert_chain,
        .private_key_bytes = private_key,
        .private_key_algorithm = private_key_algorithm,
        .alpn = alpn,
        .server_name = TLS_HOSTNAME,
        .skip_cert_verify = !config.tls_verify_peer,
        .ca_bundle = ca_bundle,
        .ticket_key = ticket_key,
        .calendar_unix_seconds = calendar_unix_seconds,
    };
    const send_backlog_limit = if (config.send_backlog_limit == 0)
        @as(u64, 1024 * 1024)
    else
        config.send_backlog_limit;
    const conn_config = connection.ConnectionConfig{
        .max_idle_timeout = config.idle_timeout_ms,
        .max_udp_payload_size = config.udp_payload_size,
        .ack_delay_exponent = 3,
        .max_ack_delay = 25,
        .disable_active_migration = true,
        .active_connection_id_limit = 2,
        .ack_frequency = false,
        .initial_max_data = config.connection_window,
        .initial_max_stream_data_bidi_local = config.stream_window,
        .initial_max_stream_data_bidi_remote = config.stream_window,
        .initial_max_stream_data_uni = config.stream_window,
        .initial_max_streams_bidi = config.max_bidi_streams,
        .initial_max_streams_uni = config.max_uni_streams,
        .max_datagram_frame_size = config.datagram_max_frame_size,
        .datagram_queue_capacity = 1024,
        .disable_pmtud = true,
        .token_key = retry_token_key,
    };

    const engine = try allocator.create(qzf_engine_t);
    errdefer allocator.destroy(engine);
    engine.* = .{
        .allocator = allocator,
        .is_server = config.is_server,
        .tls_verify_peer = config.tls_verify_peer,
        .local_addr = qzfToSockaddr(&config.local_addr),
        .tls_config = tls_config,
        .conn_config = conn_config,
        .private_key = private_key,
        .cert_chain = cert_chain,
        .ca_bundle = ca_bundle,
        .alpn = alpn,
        .udp_payload_size = @max(@as(usize, 1200), @min(@as(usize, config.udp_payload_size), @as(usize, MAX_PACKET))),
        .client_conns = std.AutoHashMap(u64, *connection.Connection).init(allocator),
        .server = null,
        .server_conns = std.AutoHashMap(u64, *connection.Connection).init(allocator),
        .server_conn_ids = std.AutoHashMap(*connection.Connection, u64).init(allocator),
        .next_server_send_index = 0,
        .accepted_connections = .{ .items = &.{}, .capacity = 0 },
        .known_connections = std.AutoHashMap(u64, void).init(allocator),
        .peer_closed_connections = std.AutoHashMap(u64, PeerCloseFacts).init(allocator),
        .consumed_ticket_digests = std.AutoHashMap([32]u8, void).init(allocator),
        .zero_rtt_attempted = std.AutoHashMap(u64, bool).init(allocator),
        .accepted_streams = std.AutoHashMap(StreamKey, void).init(allocator),
        .accepted_stream_keys = .{ .items = &.{}, .capacity = 0 },
        .recv_backlog = std.AutoHashMap(StreamKey, RecvBacklog).init(allocator),
        .recv_backlog_keys = .{ .items = &.{}, .capacity = 0 },
        .outbound = .{ .items = &.{}, .capacity = 0 },
        .send_backlog_limit = send_backlog_limit,
        .disable_pacing = config.disable_pacing,
        .trace_enabled = envFlag("QUICPERF_ZIG_TRACE"),
        .send_stats = std.AutoHashMap(u64, SendTraceStats).init(allocator),
    };
    if (config.is_server) {
        engine.server = connection_manager.ConnectionManager.init(
            allocator,
            tls_config,
            conn_config,
            retry_token_key,
            static_reset_key,
        );
    }
    return engine;
}

export fn qzf_engine_new(config: *const QzfConfig) ?*qzf_engine_t {
    clearError();
    setCallerTimeUs(config.now_us);
    return makeEngine(config) catch |err| {
        _ = storeError("new: {s}", .{@errorName(err)});
        return null;
    };
}

export fn qzf_engine_free(engine: ?*qzf_engine_t) void {
    if (engine) |e| e.deinit();
}

export fn qzf_engine_connect(engine: *qzf_engine_t, remote: *const QzfAddr, now_us: u64, conn_id: *u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    if (engine.is_server) return storeError("connect called on server", .{});
    const remote_addr = qzfToSockaddr(remote);
    engine.remote_addr = remote_addr;
    var tls_config = engine.tls_config;
    if (engine.has_imported_session_ticket) {
        tls_config.session_ticket = &engine.imported_session_ticket;
    }
    const conn = engine.allocator.create(connection.Connection) catch |err| {
        return storeError("connect allocate: {s}", .{@errorName(err)});
    };
    conn.* = connection.connect(engine.allocator, TLS_HOSTNAME, engine.conn_config, tls_config, null) catch |err| {
        engine.allocator.destroy(conn);
        return storeError("connect: {s}", .{@errorName(err)});
    };
    engine.tuneConn(conn);
    const id = engine.next_client_conn_id;
    engine.next_client_conn_id +|= 1;
    engine.client_conns.put(id, conn) catch |err| {
        conn.deinit();
        engine.allocator.destroy(conn);
        return storeError("connect store: {s}", .{@errorName(err)});
    };
    const attempted = engine.has_imported_session_ticket and engine.imported_zero_rtt;
    engine.zero_rtt_attempted.put(id, attempted) catch |err| {
        _ = engine.client_conns.remove(id);
        conn.deinit();
        engine.allocator.destroy(conn);
        return storeError("connect zero-rtt state: {s}", .{@errorName(err)});
    };
    if (engine.has_imported_session_ticket) {
        engine.consumed_ticket_digests.put(engine.imported_ticket_digest, {}) catch |err| {
            _ = engine.zero_rtt_attempted.remove(id);
            _ = engine.client_conns.remove(id);
            conn.deinit();
            engine.allocator.destroy(conn);
            return storeError("connect consumed ticket: {s}", .{@errorName(err)});
        };
        engine.has_imported_session_ticket = false;
        engine.imported_zero_rtt = false;
        engine.tls_config.session_ticket = null;
    }
    conn_id.* = id;
    return 0;
}

export fn qzf_engine_accept_connection(engine: *qzf_engine_t, conn_id: *u64) c_int {
    clearError();
    if (engine.accepted_connections.items.len == 0) return 0;
    conn_id.* = engine.accepted_connections.orderedRemove(0);
    return 1;
}

export fn qzf_engine_is_connected(engine: *qzf_engine_t, conn_id: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return 0;
    if (!conn.isEstablished()) return 0;
    if (!conn.is_server) {
        if (conn.peer_params == null) return 0;
        if (conn.streams.max_bidi_streams == 0) return 0;
        if (conn.streams.peer_initial_max_stream_data_bidi_remote == 0) return 0;
    }
    return 1;
}

export fn qzf_connection_is_closed(engine: *qzf_engine_t, conn_id: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    if (!engine.is_server) {
        const conn = engine.client_conns.get(conn_id) orelse
            return storeError("unknown connection {d}", .{conn_id});
        if (!conn.isClosed()) return 0;
        _ = engine.client_conns.remove(conn_id);
        engine.purgeConnectionState(conn_id);
        conn.deinit();
        engine.allocator.destroy(conn);
        return 1;
    }
    if (engine.server_conns.get(conn_id)) |conn| return if (conn.isClosed()) 1 else 0;
    if (engine.known_connections.remove(conn_id)) {
        engine.purgeConnectionState(conn_id);
        return 1;
    }
    return storeError("unknown connection {d}", .{conn_id});
}

export fn qzf_engine_receive(engine: *qzf_engine_t, remote: *const QzfAddr, data: [*]u8, len: usize, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    engine.receive(qzfToSockaddr(remote), data[0..len]) catch |err| {
        return storeError("receive: {s}", .{@errorName(err)});
    };
    return 0;
}

export fn qzf_engine_poll_transmit(engine: *qzf_engine_t, remote: *QzfAddr, data: [*]u8, capacity: usize, len: *usize, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const packet = engine.pollTransmit(data[0..capacity]) catch |err| {
        return storeError("poll_transmit: {s}", .{@errorName(err)});
    };
    if (packet) |p| {
        remote.* = sockaddrToQzf(&p.remote);
        len.* = p.len;
        return 1;
    }
    len.* = 0;
    return 0;
}

export fn qzf_engine_next_timeout_us(engine: *qzf_engine_t, now_us: u64, timeout_us: *u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    timeout_us.* = engine.nextTimeoutUs(now_us *| 1000) orelse std.math.maxInt(u64);
    return 0;
}

export fn qzf_engine_on_timeout(engine: *qzf_engine_t, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    engine.onTimeoutAll();
    return 0;
}

fn writeAdapterStatus(status: *QzfAdapterStatusV2, code: c_int) void {
    status.code = code;
    status.reserved = 0;
    @memset(&status.message, 0);
    if (code == 0) return;
    const message = std.mem.sliceTo(&last_error_buf, 0);
    const count = @min(message.len, status.message.len - 1);
    @memcpy(status.message[0..count], message[0..count]);
}

export fn qzf_packet_abi_version() u32 {
    return QZF_PACKET_ABI_VERSION;
}

export fn qzf_engine_receive_batch(engine: *qzf_engine_t, packets: [*]const QzfReceiveDescriptorV2, count: usize, now_raw_ns: u64, status: *QzfAdapterStatusV2) c_int {
    clearError();
    setCallerTimeRaw(now_raw_ns);
    if (count > QZF_PACKET_BATCH_CAPACITY) {
        const code = storeError("receive batch exceeds {d}", .{QZF_PACKET_BATCH_CAPACITY});
        writeAdapterStatus(status, code);
        return code;
    }
    for (packets[0..count]) |packet| {
        if (packet.ecn > 3 or std.mem.indexOfNone(u8, &packet.reserved, &.{0}) != null) {
            const code = storeError("invalid receive descriptor metadata", .{});
            writeAdapterStatus(status, code);
            return code;
        }
        engine.receive(qzfToSockaddr(&packet.peer), @constCast(packet.data[0..packet.len])) catch |err| {
            const code = storeError("receive batch: {s}", .{@errorName(err)});
            writeAdapterStatus(status, code);
            return code;
        };
    }
    writeAdapterStatus(status, 0);
    return 0;
}

export fn qzf_engine_poll_transmit_batch(engine: *qzf_engine_t, packets: [*]QzfTransmitDescriptorV2, capacity: usize, count: *usize, now_raw_ns: u64, status: *QzfAdapterStatusV2) c_int {
    clearError();
    setCallerTimeRaw(now_raw_ns);
    count.* = 0;
    if (capacity > QZF_PACKET_BATCH_CAPACITY) {
        const code = storeError("transmit batch exceeds {d}", .{QZF_PACKET_BATCH_CAPACITY});
        writeAdapterStatus(status, code);
        return code;
    }
    for (packets[0..capacity]) |*packet| {
        packet.len = 0;
        packet.ecn = 0;
        @memset(&packet.reserved, 0);
        packet.desired_send_raw_ns = now_raw_ns;
        const result = engine.pollTransmit(packet.data[0..packet.capacity]) catch |err| {
            const code = storeError("poll transmit batch: {s}", .{@errorName(err)});
            writeAdapterStatus(status, code);
            return code;
        };
        const emitted = result orelse break;
        packet.peer = sockaddrToQzf(&emitted.remote);
        packet.len = emitted.len;
        count.* += 1;
    }
    writeAdapterStatus(status, 0);
    return 0;
}

export fn qzf_engine_next_timeout_raw_ns(engine: *qzf_engine_t, now_raw_ns: u64, deadline_raw_ns: *u64, status: *QzfAdapterStatusV2) c_int {
    clearError();
    setCallerTimeRaw(now_raw_ns);
    deadline_raw_ns.* = engine.nextTimeoutRawNs() orelse 0;
    writeAdapterStatus(status, 0);
    return 0;
}

export fn qzf_engine_on_timeout_raw_ns(engine: *qzf_engine_t, now_raw_ns: u64, status: *QzfAdapterStatusV2) c_int {
    clearError();
    setCallerTimeRaw(now_raw_ns);
    engine.onTimeoutAll();
    writeAdapterStatus(status, 0);
    return 0;
}

fn addTransportCounters(total: *QzfTransportCountersV3, conn: *const connection.Connection) !void {
    const current = conn.getTransportCounters();
    total.packets_lost = try std.math.add(u64, total.packets_lost, current.packets_lost);
    total.flow_control_blocked_events = try std.math.add(
        u64,
        total.flow_control_blocked_events,
        current.data_blocked_sent,
    );
    total.stream_credit_blocked_events = try std.math.add(
        u64,
        total.stream_credit_blocked_events,
        current.stream_data_blocked_sent,
    );
}

export fn qzf_engine_transport_counters_v3(engine: *qzf_engine_t, counters: *QzfTransportCountersV3, status: *QzfAdapterStatusV2) c_int {
    clearError();
    var result: QzfTransportCountersV3 = .{};
    var client_it = engine.client_conns.valueIterator();
    while (client_it.next()) |conn| {
        addTransportCounters(&result, conn.*) catch {
            const code = storeError("transport counter overflow", .{});
            writeAdapterStatus(status, code);
            return code;
        };
    }
    if (engine.server) |*server| {
        for (server.entries.items) |entry| {
            addTransportCounters(&result, entry.conn) catch {
                const code = storeError("transport counter overflow", .{});
                writeAdapterStatus(status, code);
                return code;
            };
        }
    }
    counters.* = result;
    writeAdapterStatus(status, 0);
    return 0;
}

export fn qzf_engine_has_pending_app_data(engine: *qzf_engine_t) c_int {
    clearError();
    if (engine.server) |*server| {
        for (server.entries.items) |entry| {
            const snapshot = qzf_engine_t.inspectSendState(entry.conn);
            if (snapshot.app_pending > 0 or snapshot.app_unsent > 0) return 1;
        }
    }
    var client_it = engine.client_conns.valueIterator();
    while (client_it.next()) |conn| {
        const snapshot = qzf_engine_t.inspectSendState(conn.*);
        if (snapshot.app_pending > 0 or snapshot.app_unsent > 0) return 1;
    }
    return 0;
}

export fn qzf_engine_export_resumption_state(engine: *qzf_engine_t, conn_id: u64, data: [*]u8, capacity: usize, len: *usize, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    len.* = 0;
    if (engine.is_server) return storeError("export resumption called on server", .{});
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const ticket = conn.session_ticket orelse return 0;
    if (ticket.isExpired(engine.tls_config.calendar_unix_seconds)) return 0;
    const serialized_len = serializeResumptionTicket(&ticket, data[0..capacity]) catch |err| {
        return storeError("export resumption: {s}", .{@errorName(err)});
    };
    len.* = serialized_len;
    return 1;
}

export fn qzf_engine_import_resumption_state(engine: *qzf_engine_t, data: [*]const u8, len: usize, use_zero_rtt: bool, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    if (engine.is_server) return storeError("import resumption called on server", .{});
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data[0..len], &digest, .{});
    if (engine.has_imported_session_ticket or engine.consumed_ticket_digests.contains(digest))
        return storeError("resumption ticket is overlapping or already consumed", .{});
    const ticket = parseResumptionTicket(data[0..len]) catch |err| {
        return storeError("import resumption: {s}", .{@errorName(err)});
    };
    if (ticket.isExpired(engine.tls_config.calendar_unix_seconds)) return 0;
    engine.imported_session_ticket = ticket;
    engine.has_imported_session_ticket = true;
    engine.imported_zero_rtt = use_zero_rtt;
    engine.imported_ticket_digest = digest;
    engine.tls_config.session_ticket = &engine.imported_session_ticket;
    return 1;
}

export fn qzf_connection_resumed(engine: *qzf_engine_t, conn_id: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    if (!conn.isEstablished()) return 0;
    if (conn.tls13_hs) |*hs| {
        return if (hs.using_psk) 1 else 0;
    }
    return 0;
}

export fn qzf_connection_zero_rtt_attempted(engine: *qzf_engine_t, conn_id: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    _ = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    return if (engine.zero_rtt_attempted.get(conn_id) orelse false) 1 else 0;
}

export fn qzf_connection_zero_rtt_accepted(engine: *qzf_engine_t, conn_id: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    if (conn.tls13_hs) |*hs| {
        return if (hs.zero_rtt_accepted) 1 else 0;
    }
    return 0;
}

export fn qzf_connection_zero_rtt_rejected(engine: *qzf_engine_t, conn_id: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    if (!(engine.zero_rtt_attempted.get(conn_id) orelse false)) return 0;
    if (!conn.isEstablished()) return 0;
    if (conn.tls13_hs) |*hs| {
        return if (!hs.zero_rtt_accepted) 1 else 0;
    }
    return 0;
}

export fn qzf_connection_negotiated(engine: *qzf_engine_t, conn_id: u64, settings: *QzfNegotiated, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    settings.* = .{};
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    if (!conn.isEstablished()) return 0;
    const peer = conn.peer_params orelse return 0;
    const hs = &(conn.tls13_hs orelse return 0);
    const verified = !conn.is_server and engine.tls_verify_peer;
    settings.* = .{
        .available = true,
        .peer_certificate_verified = verified,
        .hostname_verified = verified,
        .active_migration = !peer.disable_active_migration,
        .ack_frequency = conn.peer_supports_ack_freq,
        .quic_version = conn.version,
        .tls_cipher_suite = @intFromEnum(hs.negotiated_cipher_suite),
        .tls_named_group = @intFromEnum(hs.negotiated_group),
        .max_udp_payload_size = peer.max_udp_payload_size,
        .max_ack_delay_ns = peer.max_ack_delay *| 1_000_000,
        .ack_delay_exponent = peer.ack_delay_exponent,
        .active_connection_id_limit = peer.active_connection_id_limit,
        .connection_id_bytes = conn.dcid_len,
        .max_idle_timeout_ns = peer.max_idle_timeout *| 1_000_000,
        .max_bidi_streams = peer.initial_max_streams_bidi,
        .max_uni_streams = peer.initial_max_streams_uni,
        .connection_window_bytes = peer.initial_max_data,
        .stream_window_bytes = peer.initial_max_stream_data_bidi_remote,
        .datagram_max_frame_size = peer.max_datagram_frame_size orelse 0,
    };
    return 1;
}

export fn qzf_connection_open_bidi(engine: *qzf_engine_t, conn_id: u64, stream_id: *u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const stream = conn.openStream() catch |err| switch (err) {
        error.StreamLimitError => return 0,
        else => return storeError("open_bidi: {s}", .{@errorName(err)}),
    };
    stream_id.* = stream.stream_id;
    return 1;
}

export fn qzf_connection_accept_bidi(engine: *qzf_engine_t, conn_id: u64, stream_id: *u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const accepted = engine.scanAcceptedBidi(conn_id, conn) catch |err| {
        return storeError("accept_bidi: {s}", .{@errorName(err)});
    };
    if (accepted) |sid| {
        stream_id.* = sid;
        return 1;
    }
    return 0;
}

export fn qzf_connection_open_uni(engine: *qzf_engine_t, conn_id: u64, stream_id: *u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const stream = conn.openUniStream() catch |err| switch (err) {
        error.StreamLimitError => return 0,
        else => return storeError("open_uni: {s}", .{@errorName(err)}),
    };
    stream_id.* = stream.stream_id;
    return 1;
}

export fn qzf_connection_accept_uni(engine: *qzf_engine_t, conn_id: u64, stream_id: *u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const accepted = engine.scanAcceptedUni(conn_id, conn) catch |err| {
        return storeError("accept_uni: {s}", .{@errorName(err)});
    };
    if (accepted) |sid| {
        stream_id.* = sid;
        return 1;
    }
    return 0;
}

export fn qzf_stream_send(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, data: [*]const u8, len: usize, written: *usize, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const send = if (isBidi(stream_id))
        if (conn.streams.getStream(stream_id)) |stream| &stream.send else null
    else
        conn.streams.send_streams.get(stream_id);
    const stream = send orelse return storeError("unknown send stream {d}", .{stream_id});
    const pending = qzf_engine_t.pendingAppBytes(conn);
    if (pending >= engine.send_backlog_limit) {
        written.* = 0;
        engine.recordAppWriteTrace(conn_id, 0, true);
        return 0;
    }
    const room = engine.send_backlog_limit - pending;
    const allowed_u64 = @min(@as(u64, @intCast(len)), room);
    const allowed: usize = @intCast(allowed_u64);
    if (allowed == 0) {
        written.* = 0;
        engine.recordAppWriteTrace(conn_id, 0, true);
        return 0;
    }
    stream.writeData(data[0..allowed]) catch |err| {
        written.* = 0;
        return storeError("stream_send: {s}", .{@errorName(err)});
    };
    written.* = allowed;
    engine.recordAppWriteTrace(conn_id, allowed, false);
    return 0;
}

export fn qzf_stream_recv(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, data: [*]u8, capacity: usize, read: *usize, fin: *bool, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const key = StreamKey{ .conn_id = conn_id, .stream_id = stream_id };
    var total: usize = 0;
    while (total < capacity) {
        const n = engine.readBacklog(key, data[total..capacity]) orelse break;
        total += n;
        if (n == 0) break;
    }
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const recv = if (isBidi(stream_id))
        if (conn.streams.getStream(stream_id)) |stream| &stream.recv else null
    else
        conn.streams.recv_streams.get(stream_id);
    const stream = recv orelse {
        read.* = total;
        fin.* = false;
        return 0;
    };
    while (total < capacity) {
        const chunk = stream.read() orelse break;
        const n = @min(capacity - total, chunk.len);
        if (n > 0) @memcpy(data[total..][0..n], chunk[0..n]);
        engine.saveBacklog(key, chunk, n) catch |err| {
            return storeError("stream_recv backlog: {s}", .{@errorName(err)});
        };
        total += n;
        if (n == 0) break;
    }
    if (stream.sorter.isComplete()) stream.finished = true;
    read.* = total;
    fin.* = stream.finished;
    return 0;
}

export fn qzf_stream_finish(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const send = if (isBidi(stream_id))
        if (conn.streams.getStream(stream_id)) |stream| &stream.send else null
    else
        conn.streams.send_streams.get(stream_id);
    const stream = send orelse return storeError("unknown send stream {d}", .{stream_id});
    stream.close();
    return 0;
}

export fn qzf_stream_reset(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, error_code: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const send = if (isBidi(stream_id))
        if (conn.streams.getStream(stream_id)) |stream| &stream.send else null
    else
        conn.streams.send_streams.get(stream_id);
    const stream = send orelse return storeError("unknown send stream {d}", .{stream_id});
    stream.reset(error_code);
    return 0;
}

export fn qzf_stream_stop_sending(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, error_code: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const recv = if (isBidi(stream_id))
        if (conn.streams.getStream(stream_id)) |stream| &stream.recv else null
    else
        conn.streams.recv_streams.get(stream_id);
    const stream = recv orelse return storeError("unknown receive stream {d}", .{stream_id});
    stream.stopSending(error_code);
    return 0;
}

export fn qzf_connection_close(engine: *qzf_engine_t, conn_id: u64, error_code: u64, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    conn.close(error_code, "");
    return 0;
}

export fn qzf_peer_terminal_facts_v6(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, facts: *QzfPeerTerminalFactsV6, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    facts.* = .{};
    facts.available = true;
    const latched_close = engine.peer_closed_connections.get(conn_id);
    facts.connection_close = latched_close != null;
    if (latched_close) |close| {
        facts.connection_close_error = close.error_code;
        facts.connection_close_reason_length = close.reason_length;
    }
    const conn = engine.connById(conn_id) orelse {
        if (facts.connection_close) {
            _ = engine.peer_closed_connections.remove(conn_id);
            return 0;
        }
        return storeError("unknown connection {d}", .{conn_id});
    };
    if (conn.peerApplicationClose()) |close| {
        facts.connection_close = true;
        facts.connection_close_error = close.error_code;
        facts.connection_close_reason_length = close.reason_length;
    }
    if (facts.connection_close) {
        _ = engine.peer_closed_connections.remove(conn_id);
    }
    const stream = conn.streams.getStream(stream_id) orelse return 0;
    facts.fin = stream.recv.fin_received;
    if (stream.recv.reset_err) |code| {
        facts.reset_stream = true;
        facts.reset_stream_error = code;
    }
    if (stream.send.reset_err) |code| {
        facts.stop_sending = true;
        facts.stop_sending_error = code;
    }
    return 0;
}

export fn qzf_stream_debug(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, debug: *QzfStreamDebug) c_int {
    clearError();
    debug.* = .{};
    const conn = engine.connById(conn_id) orelse return 0;
    const stream = conn.streams.getStream(stream_id) orelse return 0;
    debug.* = .{
        .found = true,
        .send_write_offset = stream.send.write_offset,
        .send_send_offset = stream.send.send_offset,
        .send_ack_offset = stream.send.ack_offset,
        .send_window = stream.send.send_window,
        .send_retransmit_count = stream.send.retransmit_count,
        .send_fin_queued = stream.send.fin_queued,
        .send_fin_sent = stream.send.fin_sent,
        .send_fin_lost = stream.send.fin_lost,
        .send_has_data = stream.send.hasData(),
        .send_has_unacked = stream.send.hasUnackedData(),
        .recv_read_pos = stream.recv.sorter.read_pos,
        .recv_highest_buffered = stream.recv.sorter.highest_buffered,
        .recv_fin_offset = stream.recv.sorter.fin_offset orelse 0,
        .recv_fin_known = stream.recv.sorter.fin_offset != null,
        .recv_finished = stream.recv.finished,
        .recv_chunk_count = stream.recv.sorter.chunks.count(),
        .bytes_in_flight = conn.pkt_handler.bytes_in_flight,
        .cwnd = conn.cc.sendWindow(),
        .conn_send_window = conn.conn_flow_ctrl.sendWindowSize(),
    };
    return 1;
}

export fn qzf_datagram_send(engine: *qzf_engine_t, conn_id: u64, data: [*]const u8, len: usize, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    conn.sendDatagram(data[0..len]) catch |err| switch (err) {
        error.DatagramQueueFull => return 0,
        else => return storeError("datagram_send: {s}", .{@errorName(err)}),
    };
    return 1;
}

export fn qzf_datagram_recv(engine: *qzf_engine_t, conn_id: u64, data: [*]u8, capacity: usize, read: *usize, now_us: u64) c_int {
    clearError();
    setCallerTimeUs(now_us);
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    if (conn.recvDatagram(data[0..capacity])) |n| {
        read.* = n;
        return 1;
    }
    read.* = 0;
    return 0;
}

export fn qzf_last_error() [*:0]const u8 {
    return last_error_buf[0.. :0].ptr;
}
