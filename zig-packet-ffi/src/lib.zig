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

const ALPN = "perf";
const MAX_PACKET = 1500;

pub const QzfAddr = extern struct {
    ip: [16]u8,
    port: u16,
};

pub const QzfConfig = extern struct {
    is_server: bool,
    local_addr: QzfAddr,
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
    send_backlog_limit: u64,
    now_us: u64,
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
    local_addr: posix.sockaddr.storage,
    remote_addr: ?posix.sockaddr.storage = null,
    tls_config: tls13.TlsConfig,
    conn_config: connection.ConnectionConfig,
    private_key: []u8,
    cert_chain: [][]const u8,
    ca_bundle: ?*Certificate.Bundle,
    alpn: []const []const u8,
    udp_payload_size: usize,
    client_conn: ?connection.Connection = null,
    server: ?connection_manager.ConnectionManager = null,
    next_server_send_index: usize,
    accepted_connections: std.ArrayList(u64),
    known_connections: std.AutoHashMap(u64, void),
    accepted_streams: std.AutoHashMap(StreamKey, void),
    recv_backlog: std.AutoHashMap(StreamKey, RecvBacklog),
    outbound: std.ArrayList(Outbound),
    send_backlog_limit: u64,
    disable_pacing: bool,
    trace_enabled: bool,
    send_stats: std.AutoHashMap(u64, SendTraceStats),

    fn deinit(self: *qzf_engine_t) void {
        self.printSendTrace();
        self.send_stats.deinit();
        if (self.client_conn) |*conn| conn.deinit();
        if (self.server) |*server| server.deinit();
        for (self.outbound.items) |out| self.allocator.free(out.data);
        self.outbound.deinit(self.allocator);
        var backlog_it = self.recv_backlog.valueIterator();
        while (backlog_it.next()) |pending| self.allocator.free(pending.data);
        self.recv_backlog.deinit();
        self.accepted_streams.deinit();
        self.known_connections.deinit();
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
        if (self.is_server) {
            if (self.server) |*server| {
                for (server.entries.items) |entry| {
                    if (@as(u64, @intCast(@intFromPtr(entry.conn))) == conn_id) return entry.conn;
                }
            }
            return null;
        }
        if (conn_id == 1) {
            if (self.client_conn) |*conn| return conn;
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
        const now: i64 = @intCast(quic.sys.nanoTimestamp());
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
                snapshots[count] = .{
                    .conn_id = @intCast(@intFromPtr(entry.conn)),
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
                const conn_id: u64 = @intCast(@intFromPtr(entry.conn));
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
        const conn_id: u64 = @intCast(@intFromPtr(entry.conn));
        if (self.known_connections.get(conn_id) == null) {
            try self.known_connections.put(conn_id, {});
            try self.accepted_connections.append(self.allocator, conn_id);
        }
    }

    fn scanServerConnections(self: *qzf_engine_t) !void {
        if (self.server) |*server| {
            for (server.entries.items) |entry| try self.registerServerConnection(entry);
        }
    }

    fn onTimeoutAll(self: *qzf_engine_t) void {
        if (self.client_conn) |*conn| conn.onTimeout() catch {};
        if (self.server) |*server| {
            var i: usize = 0;
            while (i < server.entries.items.len) {
                if (!server.tickEntry(server.entries.items[i])) continue;
                i += 1;
            }
            server.freeDeadEntries();
        }
    }

    fn nextTimeoutUs(self: *qzf_engine_t) ?u64 {
        const now_ns: i64 = @intCast(quic.sys.nanoTimestamp());
        var best: ?i64 = null;
        if (self.client_conn) |*conn| {
            if (conn.nextTimeoutNs()) |deadline| best = deadline;
        }
        if (self.server) |*server| {
            for (server.entries.items) |entry| {
                if (entry.conn.nextTimeoutNs()) |deadline| {
                    if (best == null or deadline < best.?) best = deadline;
                }
            }
        }
        const deadline = best orelse return null;
        if (deadline <= now_ns) return 0;
        return @intCast(@divTrunc(deadline - now_ns, 1000));
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
            var conn = &(self.client_conn orelse return error.NotClient);
            conn.handleDatagram(data, .{
                .to = self.local_addr,
                .from = remote,
                .ecn = 0,
                .datagram_size = data.len,
            });
        }
    }

    fn pollTransmit(self: *qzf_engine_t, out: []u8) !?struct { remote: posix.sockaddr.storage, len: usize } {
        if (self.outbound.items.len > 0) {
            const queued = self.outbound.orderedRemove(0);
            defer self.allocator.free(queued.data);
            if (queued.data.len > out.len) return error.OutputTooSmall;
            @memcpy(out[0..queued.data.len], queued.data);
            return .{ .remote = queued.remote, .len = queued.data.len };
        }

        if (self.client_conn) |*conn| {
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
                const conn_id: u64 = @intCast(@intFromPtr(entry.conn));
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

fn cstr(ptr: [*:0]const u8) []const u8 {
    return std.mem.span(ptr);
}

fn envFlag(name: [*:0]const u8) bool {
    const value = quic.sys.getenv(name) orelse return false;
    return value.len > 0 and !std.mem.eql(u8, value, "0") and !std.mem.eql(u8, value, "false");
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

fn unixNowSeconds() i64 {
    var ts: posix.timespec = undefined;
    if (c.clock_gettime(posix.CLOCK.REALTIME, &ts) != 0) return 0;
    return @as(i64, ts.sec);
}

fn makeEngine(config: *const QzfConfig) !*qzf_engine_t {
    const allocator = std.heap.c_allocator;
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
        const now_sec = unixNowSeconds();
        for (trusted_chain) |cert| {
            const decoded_start: u32 = @intCast(bundle.bytes.items.len);
            try bundle.bytes.appendSlice(allocator, cert);
            try bundle.parseCert(allocator, decoded_start, now_sec);
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
        .server_name = "localhost",
        .skip_cert_verify = !config.tls_verify_peer,
        .ca_bundle = ca_bundle,
        .ticket_key = ticket_key,
    };
    const send_backlog_limit = if (config.send_backlog_limit == 0)
        @as(u64, 1024 * 1024)
    else
        config.send_backlog_limit;
    const conn_config = connection.ConnectionConfig{
        .max_idle_timeout = config.idle_timeout_ms,
        .initial_max_data = config.connection_window,
        .initial_max_stream_data_bidi_local = config.stream_window,
        .initial_max_stream_data_bidi_remote = config.stream_window,
        .initial_max_stream_data_uni = config.stream_window,
        .initial_max_streams_bidi = config.max_bidi_streams,
        .initial_max_streams_uni = config.max_uni_streams,
        .max_datagram_frame_size = config.udp_payload_size,
        .datagram_queue_capacity = 1024,
        .disable_pmtud = true,
        .token_key = retry_token_key,
    };

    const engine = try allocator.create(qzf_engine_t);
    errdefer allocator.destroy(engine);
    engine.* = .{
        .allocator = allocator,
        .is_server = config.is_server,
        .local_addr = qzfToSockaddr(&config.local_addr),
        .tls_config = tls_config,
        .conn_config = conn_config,
        .private_key = private_key,
        .cert_chain = cert_chain,
        .ca_bundle = ca_bundle,
        .alpn = alpn,
        .udp_payload_size = @max(@as(usize, 1200), @min(@as(usize, config.udp_payload_size), @as(usize, MAX_PACKET))),
        .server = null,
        .next_server_send_index = 0,
        .accepted_connections = .{ .items = &.{}, .capacity = 0 },
        .known_connections = std.AutoHashMap(u64, void).init(allocator),
        .accepted_streams = std.AutoHashMap(StreamKey, void).init(allocator),
        .recv_backlog = std.AutoHashMap(StreamKey, RecvBacklog).init(allocator),
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
    return makeEngine(config) catch |err| {
        _ = storeError("new: {s}", .{@errorName(err)});
        return null;
    };
}

export fn qzf_engine_free(engine: ?*qzf_engine_t) void {
    if (engine) |e| e.deinit();
}

export fn qzf_engine_connect(engine: *qzf_engine_t, remote: *const QzfAddr, now_us: u64, conn_id: *u64) c_int {
    _ = now_us;
    clearError();
    if (engine.is_server) return storeError("connect called on server", .{});
    const remote_addr = qzfToSockaddr(remote);
    engine.remote_addr = remote_addr;
    var conn = connection.connect(engine.allocator, "localhost", engine.conn_config, engine.tls_config, null) catch |err| {
        return storeError("connect: {s}", .{@errorName(err)});
    };
    engine.tuneConn(&conn);
    engine.client_conn = conn;
    conn_id.* = 1;
    return 0;
}

export fn qzf_engine_accept_connection(engine: *qzf_engine_t, conn_id: *u64) c_int {
    clearError();
    if (engine.accepted_connections.items.len == 0) return 0;
    conn_id.* = engine.accepted_connections.orderedRemove(0);
    return 1;
}

export fn qzf_engine_is_connected(engine: *qzf_engine_t, conn_id: u64, now_us: u64) c_int {
    _ = now_us;
    clearError();
    const conn = engine.connById(conn_id) orelse return 0;
    if (!conn.isEstablished()) return 0;
    if (!conn.is_server) {
        if (conn.peer_params == null) return 0;
        if (conn.streams.max_bidi_streams == 0) return 0;
        if (conn.streams.peer_initial_max_stream_data_bidi_remote == 0) return 0;
    }
    return 1;
}

export fn qzf_engine_receive(engine: *qzf_engine_t, remote: *const QzfAddr, data: [*]u8, len: usize, now_us: u64) c_int {
    _ = now_us;
    clearError();
    engine.receive(qzfToSockaddr(remote), data[0..len]) catch |err| {
        return storeError("receive: {s}", .{@errorName(err)});
    };
    return 0;
}

export fn qzf_engine_poll_transmit(engine: *qzf_engine_t, remote: *QzfAddr, data: [*]u8, capacity: usize, len: *usize, now_us: u64) c_int {
    _ = now_us;
    clearError();
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
    _ = now_us;
    clearError();
    if (engine.nextTimeoutUs()) |timeout| timeout_us.* = timeout;
    return 0;
}

export fn qzf_engine_on_timeout(engine: *qzf_engine_t, now_us: u64) c_int {
    _ = now_us;
    clearError();
    engine.onTimeoutAll();
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
	if (engine.client_conn) |*conn| {
		const snapshot = qzf_engine_t.inspectSendState(conn);
		if (snapshot.app_pending > 0 or snapshot.app_unsent > 0) return 1;
	}
    return 0;
}

export fn qzf_connection_open_bidi(engine: *qzf_engine_t, conn_id: u64, stream_id: *u64, now_us: u64) c_int {
    _ = now_us;
    clearError();
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const stream = conn.openStream() catch |err| switch (err) {
        error.StreamLimitError => return 0,
        else => return storeError("open_bidi: {s}", .{@errorName(err)}),
    };
    stream_id.* = stream.stream_id;
    return 1;
}

export fn qzf_connection_accept_bidi(engine: *qzf_engine_t, conn_id: u64, stream_id: *u64, now_us: u64) c_int {
    _ = now_us;
    clearError();
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

export fn qzf_stream_send(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, data: [*]const u8, len: usize, written: *usize, now_us: u64) c_int {
    _ = now_us;
    clearError();
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const stream = conn.streams.getStream(stream_id) orelse return storeError("unknown stream {d}", .{stream_id});
    const pending = stream.send.write_offset - stream.send.ack_offset;
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
    stream.send.writeData(data[0..allowed]) catch |err| {
        written.* = 0;
        return storeError("stream_send: {s}", .{@errorName(err)});
    };
    written.* = allowed;
    engine.recordAppWriteTrace(conn_id, allowed, false);
    return 0;
}

export fn qzf_stream_recv(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, data: [*]u8, capacity: usize, read: *usize, fin: *bool, now_us: u64) c_int {
    _ = now_us;
    clearError();
    const key = StreamKey{ .conn_id = conn_id, .stream_id = stream_id };
    var total: usize = 0;
    while (total < capacity) {
        const n = engine.readBacklog(key, data[total..capacity]) orelse break;
        total += n;
        if (n == 0) break;
    }
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const stream = conn.streams.getStream(stream_id) orelse {
        read.* = total;
        fin.* = false;
        return 0;
    };
    while (total < capacity) {
        const chunk = stream.recv.read() orelse break;
        const n = @min(capacity - total, chunk.len);
        if (n > 0) @memcpy(data[total..][0..n], chunk[0..n]);
        engine.saveBacklog(key, chunk, n) catch |err| {
            return storeError("stream_recv backlog: {s}", .{@errorName(err)});
        };
        total += n;
        if (n == 0) break;
    }
    read.* = total;
    fin.* = total == 0 and stream.recv.finished;
    return 0;
}

export fn qzf_stream_finish(engine: *qzf_engine_t, conn_id: u64, stream_id: u64, now_us: u64) c_int {
    _ = now_us;
    clearError();
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    const stream = conn.streams.getStream(stream_id) orelse return storeError("unknown stream {d}", .{stream_id});
    stream.send.close();
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
    _ = now_us;
    clearError();
    const conn = engine.connById(conn_id) orelse return storeError("unknown connection {d}", .{conn_id});
    conn.sendDatagram(data[0..len]) catch |err| switch (err) {
        error.DatagramQueueFull => return 0,
        else => return storeError("datagram_send: {s}", .{@errorName(err)}),
    };
    return 1;
}

export fn qzf_datagram_recv(engine: *qzf_engine_t, conn_id: u64, data: [*]u8, capacity: usize, read: *usize, now_us: u64) c_int {
    _ = now_us;
    clearError();
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
