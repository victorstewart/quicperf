use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    ffi::{c_char, CStr, CString},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime},
};

use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    DigitallySignedStruct, NamedGroup, SignatureScheme,
};

#[global_allocator]
static GLOBAL_ALLOCATOR: std::alloc::System = std::alloc::System;

const QPF_LIBRARY_QUINN: u32 = 1;
const QPF_LIBRARY_NOQ: u32 = 2;
const QPF_LIBRARY_NEQO: u32 = 3;
const QPF_LIBRARY_S2N: u32 = 4;
const ALPN: &[u8] = b"qperf/2";
const ALPN_STR: &[&str] = &["qperf/2"];
const MAX_DATAGRAMS: usize = 1;
const MAX_PROTO_DRIVE_PASSES: usize = 256;
const APPLICATION_BUFFER_BYTES: u64 = 256 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QpfAddr {
    ip: [u8; 16],
    port: u16,
}

#[repr(C)]
pub struct QpfConfig {
    library: u32,
    is_server: bool,
    local_addr: QpfAddr,
    peer_addr: QpfAddr,
    cert_path: *const c_char,
    key_path: *const c_char,
    chain_path: *const c_char,
    tls_hostname: *const c_char,
    tls_verify_peer: bool,
    use_bbr: bool,
    initial_congestion_window_bytes: u64,
    max_ack_delay_ns: u64,
    ack_delay_exponent: u64,
    ack_frequency: bool,
    active_migration: bool,
    active_connection_id_limit: u64,
    connection_id_bytes: u64,
    connection_window: u64,
    stream_window: u64,
    stream_credit_replenish_below: u64,
    max_bidi_streams: u64,
    max_uni_streams: u64,
    idle_timeout_ms: u64,
    udp_payload_size: u32,
    datagram_max_frame_size: u64,
    datagram_max_unreturned_per_connection: u64,
    ticket_lifetime_ns: u64,
    maximum_early_data_bytes: u64,
    one_use_tickets: bool,
    now_us: u64,
    calendar_unix_seconds: u64,
}

const QPF_PACKET_ABI_VERSION: u32 = 8;
const QPF_PACKET_BATCH_CAPACITY: usize = 64;

#[repr(C)]
pub struct QpfReceiveDescriptorV2 {
    data: *const u8,
    len: usize,
    peer: QpfAddr,
    ecn: u8,
    reserved: [u8; 7],
}

#[repr(C)]
pub struct QpfTransmitDescriptorV2 {
    data: *mut u8,
    capacity: usize,
    len: usize,
    peer: QpfAddr,
    ecn: u8,
    reserved: [u8; 7],
    desired_send_raw_ns: u64,
}

#[repr(C)]
pub struct QpfAdapterStatusV2 {
    code: i32,
    reserved: u32,
    message: [c_char; 256],
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct QpfTransportCountersV3 {
    packets_lost: u64,
    packets_retransmitted: u64,
    recovery_wakeups: u64,
    flow_control_blocked_events: u64,
    stream_credit_blocked_events: u64,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct QpfPeerTerminalFactsV6 {
    available: bool,
    fin: bool,
    reset_stream: bool,
    stop_sending: bool,
    connection_close: bool,
    reserved: [u8; 3],
    reset_stream_error: u64,
    stop_sending_error: u64,
    connection_close_error: u64,
    connection_close_reason_length: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct QpfNegotiatedSettingsV7 {
    available: u8,
    alpn_qperf_2: u8,
    peer_certificate_present: u8,
    peer_certificate_verified: u8,
    hostname_verified: u8,
    tls_leaf_ed25519: u8,
    use_bbr: u8,
    ack_frequency: u8,
    active_migration: u8,
    one_use_tickets: u8,
    reserved8: [u8; 6],
    quic_version: u32,
    tls_version: u16,
    tls_cipher_suite: u16,
    tls_key_exchange_group: u16,
    tls_leaf_signature_algorithm: u16,
    reserved32: u32,
    initial_congestion_window_bytes: u64,
    max_udp_payload_size: u64,
    max_ack_delay_ns: u64,
    ack_delay_exponent: u64,
    active_connection_id_limit: u64,
    connection_id_bytes: u64,
    max_idle_timeout_ns: u64,
    max_bidi_streams: u64,
    max_uni_streams: u64,
    stream_credit_replenish_below: u64,
    connection_window_bytes: u64,
    stream_window_bytes: u64,
    datagram_max_frame_size: u64,
    ticket_lifetime_ns: u64,
    maximum_early_data_bytes: u64,
}

#[allow(non_camel_case_types)]
pub struct qpf_engine_t {
    engine: Engine,
}

enum Engine {
    Quinn(quinn_engine::QuinnEngine),
    Noq(noq_engine::NoqEngine),
    Neqo(neqo_engine::NeqoEngine),
    S2n(s2n_engine::S2nEngine),
}

trait PacketEngine {
    fn connect(&mut self, remote: SocketAddr, now_us: u64) -> Result<u64, String>;
    fn accept_connection(&mut self) -> Option<u64>;
    fn is_connected(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String>;
    fn connection_is_closed(&mut self, _conn_id: u64, _now_us: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn retire_connection(&mut self, _conn_id: u64, _now_us: u64) -> Result<(), String> {
        Ok(())
    }
    fn receive(&mut self, remote: SocketAddr, data: &[u8], now_us: u64) -> Result<(), String>;
    fn receive_batch(
        &mut self,
        packets: &[QpfReceiveDescriptorV2],
        now_us: u64,
    ) -> Result<(), String> {
        for packet in packets {
            let (remote, data) = receive_descriptor(packet)?;
            self.receive(remote, data, now_us)?;
        }
        Ok(())
    }
    fn poll_transmit(
        &mut self,
        now_us: u64,
        out: &mut [u8],
    ) -> Result<Option<(SocketAddr, usize)>, String>;
    fn next_timeout_us(&mut self, now_us: u64) -> Result<Option<u64>, String>;
    fn on_timeout(&mut self, now_us: u64) -> Result<(), String>;
    fn export_resumption_state(
        &mut self,
        _conn_id: u64,
        _now_us: u64,
        _out: &mut Vec<u8>,
    ) -> Result<bool, String> {
        Ok(true)
    }
    fn import_resumption_state(
        &mut self,
        _data: &[u8],
        _use_zero_rtt: bool,
        _now_us: u64,
    ) -> Result<bool, String> {
        Ok(true)
    }
    fn connection_resumed(&mut self, _conn_id: u64, _now_us: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn zero_rtt_attempted(&mut self, _conn_id: u64, _now_us: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn zero_rtt_accepted(&mut self, _conn_id: u64, _now_us: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn zero_rtt_rejected(&mut self, _conn_id: u64, _now_us: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn open_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String>;
    fn accept_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String>;
    fn open_uni(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String>;
    fn accept_uni(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String>;
    fn stream_send(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        data: &[u8],
        now_us: u64,
    ) -> Result<usize, String>;
    fn stream_recv(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        out: &mut [u8],
        now_us: u64,
    ) -> Result<(usize, bool), String>;
    fn stream_finish(&mut self, conn_id: u64, stream_id: u64, now_us: u64) -> Result<(), String>;
    fn stream_reset(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        application_error: u64,
        now_us: u64,
    ) -> Result<(), String>;
    fn stream_stop_sending(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        application_error: u64,
        now_us: u64,
    ) -> Result<(), String>;
    fn connection_close(
        &mut self,
        conn_id: u64,
        application_error: u64,
        now_us: u64,
    ) -> Result<(), String>;
    fn datagram_send(&mut self, _conn_id: u64, _data: &[u8], _now_us: u64) -> Result<bool, String> {
        Err("QUIC DATAGRAM is not exposed by this packet engine".into())
    }
    fn datagram_recv(
        &mut self,
        _conn_id: u64,
        _out: &mut [u8],
        _now_us: u64,
    ) -> Result<Option<usize>, String> {
        Err("QUIC DATAGRAM is not exposed by this packet engine".into())
    }
    fn transport_counters(&mut self) -> QpfTransportCountersV3 {
        QpfTransportCountersV3::default()
    }
    fn peer_terminal_facts(
        &mut self,
        _conn_id: u64,
        _stream_id: u64,
        _now_us: u64,
    ) -> Result<QpfPeerTerminalFactsV6, String> {
        Ok(QpfPeerTerminalFactsV6::default())
    }
    fn negotiated_settings(&mut self) -> Result<QpfNegotiatedSettingsV7, String> {
        Ok(QpfNegotiatedSettingsV7::default())
    }
}

impl PacketEngine for Engine {
    fn connect(&mut self, remote: SocketAddr, now_us: u64) -> Result<u64, String> {
        match self {
            Self::Quinn(engine) => engine.connect(remote, now_us),
            Self::Noq(engine) => engine.connect(remote, now_us),
            Self::Neqo(engine) => engine.connect(remote, now_us),
            Self::S2n(engine) => engine.connect(remote, now_us),
        }
    }

    fn accept_connection(&mut self) -> Option<u64> {
        match self {
            Self::Quinn(engine) => engine.accept_connection(),
            Self::Noq(engine) => engine.accept_connection(),
            Self::Neqo(engine) => engine.accept_connection(),
            Self::S2n(engine) => engine.accept_connection(),
        }
    }

    fn is_connected(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
        match self {
            Self::Quinn(engine) => engine.is_connected(conn_id, now_us),
            Self::Noq(engine) => engine.is_connected(conn_id, now_us),
            Self::Neqo(engine) => engine.is_connected(conn_id, now_us),
            Self::S2n(engine) => engine.is_connected(conn_id, now_us),
        }
    }

    fn connection_is_closed(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
        match self {
            Self::Quinn(engine) => engine.connection_is_closed(conn_id, now_us),
            Self::Noq(engine) => engine.connection_is_closed(conn_id, now_us),
            Self::Neqo(engine) => engine.connection_is_closed(conn_id, now_us),
            Self::S2n(engine) => engine.connection_is_closed(conn_id, now_us),
        }
    }

    fn retire_connection(&mut self, conn_id: u64, now_us: u64) -> Result<(), String> {
        match self {
            Self::Quinn(engine) => engine.retire_connection(conn_id, now_us),
            Self::Noq(engine) => engine.retire_connection(conn_id, now_us),
            Self::Neqo(engine) => engine.retire_connection(conn_id, now_us),
            Self::S2n(engine) => engine.retire_connection(conn_id, now_us),
        }
    }

    fn receive(&mut self, remote: SocketAddr, data: &[u8], now_us: u64) -> Result<(), String> {
        match self {
            Self::Quinn(engine) => engine.receive(remote, data, now_us),
            Self::Noq(engine) => engine.receive(remote, data, now_us),
            Self::Neqo(engine) => engine.receive(remote, data, now_us),
            Self::S2n(engine) => engine.receive(remote, data, now_us),
        }
    }

    fn receive_batch(
        &mut self,
        packets: &[QpfReceiveDescriptorV2],
        now_us: u64,
    ) -> Result<(), String> {
        match self {
            Self::Quinn(engine) => engine.receive_batch(packets, now_us),
            Self::Noq(engine) => engine.receive_batch(packets, now_us),
            Self::Neqo(engine) => engine.receive_batch(packets, now_us),
            Self::S2n(engine) => engine.receive_batch(packets, now_us),
        }
    }

    fn poll_transmit(
        &mut self,
        now_us: u64,
        out: &mut [u8],
    ) -> Result<Option<(SocketAddr, usize)>, String> {
        match self {
            Self::Quinn(engine) => engine.poll_transmit(now_us, out),
            Self::Noq(engine) => engine.poll_transmit(now_us, out),
            Self::Neqo(engine) => engine.poll_transmit(now_us, out),
            Self::S2n(engine) => engine.poll_transmit(now_us, out),
        }
    }

    fn next_timeout_us(&mut self, now_us: u64) -> Result<Option<u64>, String> {
        match self {
            Self::Quinn(engine) => engine.next_timeout_us(now_us),
            Self::Noq(engine) => engine.next_timeout_us(now_us),
            Self::Neqo(engine) => engine.next_timeout_us(now_us),
            Self::S2n(engine) => engine.next_timeout_us(now_us),
        }
    }

    fn on_timeout(&mut self, now_us: u64) -> Result<(), String> {
        match self {
            Self::Quinn(engine) => engine.on_timeout(now_us),
            Self::Noq(engine) => engine.on_timeout(now_us),
            Self::Neqo(engine) => engine.on_timeout(now_us),
            Self::S2n(engine) => engine.on_timeout(now_us),
        }
    }

    fn export_resumption_state(
        &mut self,
        conn_id: u64,
        now_us: u64,
        out: &mut Vec<u8>,
    ) -> Result<bool, String> {
        match self {
            Self::Quinn(engine) => engine.export_resumption_state(conn_id, now_us, out),
            Self::Noq(engine) => engine.export_resumption_state(conn_id, now_us, out),
            Self::Neqo(engine) => engine.export_resumption_state(conn_id, now_us, out),
            Self::S2n(engine) => engine.export_resumption_state(conn_id, now_us, out),
        }
    }

    fn import_resumption_state(
        &mut self,
        data: &[u8],
        use_zero_rtt: bool,
        now_us: u64,
    ) -> Result<bool, String> {
        match self {
            Self::Quinn(engine) => engine.import_resumption_state(data, use_zero_rtt, now_us),
            Self::Noq(engine) => engine.import_resumption_state(data, use_zero_rtt, now_us),
            Self::Neqo(engine) => engine.import_resumption_state(data, use_zero_rtt, now_us),
            Self::S2n(engine) => engine.import_resumption_state(data, use_zero_rtt, now_us),
        }
    }

    fn connection_resumed(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
        match self {
            Self::Quinn(engine) => engine.connection_resumed(conn_id, now_us),
            Self::Noq(engine) => engine.connection_resumed(conn_id, now_us),
            Self::Neqo(engine) => engine.connection_resumed(conn_id, now_us),
            Self::S2n(engine) => engine.connection_resumed(conn_id, now_us),
        }
    }

    fn zero_rtt_attempted(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
        match self {
            Self::Quinn(engine) => engine.zero_rtt_attempted(conn_id, now_us),
            Self::Noq(engine) => engine.zero_rtt_attempted(conn_id, now_us),
            Self::Neqo(engine) => engine.zero_rtt_attempted(conn_id, now_us),
            Self::S2n(engine) => engine.zero_rtt_attempted(conn_id, now_us),
        }
    }

    fn zero_rtt_accepted(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
        match self {
            Self::Quinn(engine) => engine.zero_rtt_accepted(conn_id, now_us),
            Self::Noq(engine) => engine.zero_rtt_accepted(conn_id, now_us),
            Self::Neqo(engine) => engine.zero_rtt_accepted(conn_id, now_us),
            Self::S2n(engine) => engine.zero_rtt_accepted(conn_id, now_us),
        }
    }

    fn zero_rtt_rejected(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
        match self {
            Self::Quinn(engine) => engine.zero_rtt_rejected(conn_id, now_us),
            Self::Noq(engine) => engine.zero_rtt_rejected(conn_id, now_us),
            Self::Neqo(engine) => engine.zero_rtt_rejected(conn_id, now_us),
            Self::S2n(engine) => engine.zero_rtt_rejected(conn_id, now_us),
        }
    }

    fn open_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
        match self {
            Self::Quinn(engine) => engine.open_bidi(conn_id, now_us),
            Self::Noq(engine) => engine.open_bidi(conn_id, now_us),
            Self::Neqo(engine) => engine.open_bidi(conn_id, now_us),
            Self::S2n(engine) => engine.open_bidi(conn_id, now_us),
        }
    }

    fn accept_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
        match self {
            Self::Quinn(engine) => engine.accept_bidi(conn_id, now_us),
            Self::Noq(engine) => engine.accept_bidi(conn_id, now_us),
            Self::Neqo(engine) => engine.accept_bidi(conn_id, now_us),
            Self::S2n(engine) => engine.accept_bidi(conn_id, now_us),
        }
    }

    fn open_uni(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
        match self {
            Self::Quinn(engine) => engine.open_uni(conn_id, now_us),
            Self::Noq(engine) => engine.open_uni(conn_id, now_us),
            Self::Neqo(engine) => engine.open_uni(conn_id, now_us),
            Self::S2n(engine) => engine.open_uni(conn_id, now_us),
        }
    }

    fn accept_uni(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
        match self {
            Self::Quinn(engine) => engine.accept_uni(conn_id, now_us),
            Self::Noq(engine) => engine.accept_uni(conn_id, now_us),
            Self::Neqo(engine) => engine.accept_uni(conn_id, now_us),
            Self::S2n(engine) => engine.accept_uni(conn_id, now_us),
        }
    }

    fn stream_send(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        data: &[u8],
        now_us: u64,
    ) -> Result<usize, String> {
        match self {
            Self::Quinn(engine) => engine.stream_send(conn_id, stream_id, data, now_us),
            Self::Noq(engine) => engine.stream_send(conn_id, stream_id, data, now_us),
            Self::Neqo(engine) => engine.stream_send(conn_id, stream_id, data, now_us),
            Self::S2n(engine) => engine.stream_send(conn_id, stream_id, data, now_us),
        }
    }

    fn stream_recv(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        out: &mut [u8],
        now_us: u64,
    ) -> Result<(usize, bool), String> {
        match self {
            Self::Quinn(engine) => engine.stream_recv(conn_id, stream_id, out, now_us),
            Self::Noq(engine) => engine.stream_recv(conn_id, stream_id, out, now_us),
            Self::Neqo(engine) => engine.stream_recv(conn_id, stream_id, out, now_us),
            Self::S2n(engine) => engine.stream_recv(conn_id, stream_id, out, now_us),
        }
    }

    fn stream_finish(&mut self, conn_id: u64, stream_id: u64, now_us: u64) -> Result<(), String> {
        match self {
            Self::Quinn(engine) => engine.stream_finish(conn_id, stream_id, now_us),
            Self::Noq(engine) => engine.stream_finish(conn_id, stream_id, now_us),
            Self::Neqo(engine) => engine.stream_finish(conn_id, stream_id, now_us),
            Self::S2n(engine) => engine.stream_finish(conn_id, stream_id, now_us),
        }
    }

    fn stream_reset(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        application_error: u64,
        now_us: u64,
    ) -> Result<(), String> {
        match self {
            Self::Quinn(engine) => {
                engine.stream_reset(conn_id, stream_id, application_error, now_us)
            }
            Self::Noq(engine) => engine.stream_reset(conn_id, stream_id, application_error, now_us),
            Self::Neqo(engine) => {
                engine.stream_reset(conn_id, stream_id, application_error, now_us)
            }
            Self::S2n(engine) => engine.stream_reset(conn_id, stream_id, application_error, now_us),
        }
    }

    fn stream_stop_sending(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        application_error: u64,
        now_us: u64,
    ) -> Result<(), String> {
        match self {
            Self::Quinn(engine) => {
                engine.stream_stop_sending(conn_id, stream_id, application_error, now_us)
            }
            Self::Noq(engine) => {
                engine.stream_stop_sending(conn_id, stream_id, application_error, now_us)
            }
            Self::Neqo(engine) => {
                engine.stream_stop_sending(conn_id, stream_id, application_error, now_us)
            }
            Self::S2n(engine) => {
                engine.stream_stop_sending(conn_id, stream_id, application_error, now_us)
            }
        }
    }

    fn connection_close(
        &mut self,
        conn_id: u64,
        application_error: u64,
        now_us: u64,
    ) -> Result<(), String> {
        match self {
            Self::Quinn(engine) => engine.connection_close(conn_id, application_error, now_us),
            Self::Noq(engine) => engine.connection_close(conn_id, application_error, now_us),
            Self::Neqo(engine) => engine.connection_close(conn_id, application_error, now_us),
            Self::S2n(engine) => engine.connection_close(conn_id, application_error, now_us),
        }
    }

    fn peer_terminal_facts(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        now_us: u64,
    ) -> Result<QpfPeerTerminalFactsV6, String> {
        match self {
            Self::Quinn(engine) => engine.peer_terminal_facts(conn_id, stream_id, now_us),
            Self::Noq(engine) => engine.peer_terminal_facts(conn_id, stream_id, now_us),
            Self::Neqo(engine) => engine.peer_terminal_facts(conn_id, stream_id, now_us),
            Self::S2n(engine) => engine.peer_terminal_facts(conn_id, stream_id, now_us),
        }
    }

    fn datagram_send(&mut self, conn_id: u64, data: &[u8], now_us: u64) -> Result<bool, String> {
        match self {
            Self::Quinn(engine) => engine.datagram_send(conn_id, data, now_us),
            Self::Noq(engine) => engine.datagram_send(conn_id, data, now_us),
            Self::Neqo(engine) => engine.datagram_send(conn_id, data, now_us),
            Self::S2n(engine) => engine.datagram_send(conn_id, data, now_us),
        }
    }

    fn datagram_recv(
        &mut self,
        conn_id: u64,
        out: &mut [u8],
        now_us: u64,
    ) -> Result<Option<usize>, String> {
        match self {
            Self::Quinn(engine) => engine.datagram_recv(conn_id, out, now_us),
            Self::Noq(engine) => engine.datagram_recv(conn_id, out, now_us),
            Self::Neqo(engine) => engine.datagram_recv(conn_id, out, now_us),
            Self::S2n(engine) => engine.datagram_recv(conn_id, out, now_us),
        }
    }

    fn transport_counters(&mut self) -> QpfTransportCountersV3 {
        match self {
            Self::Quinn(engine) => engine.transport_counters(),
            Self::Noq(engine) => engine.transport_counters(),
            Self::Neqo(engine) => engine.transport_counters(),
            Self::S2n(engine) => engine.transport_counters(),
        }
    }

    fn negotiated_settings(&mut self) -> Result<QpfNegotiatedSettingsV7, String> {
        match self {
            Self::Quinn(engine) => engine.negotiated_settings(),
            Self::Noq(engine) => engine.negotiated_settings(),
            Self::Neqo(engine) => engine.negotiated_settings(),
            Self::S2n(engine) => engine.negotiated_settings(),
        }
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
    static SESSION_TICKET_TAKE_ALLOWED: Cell<bool> = const { Cell::new(false) };
}

struct SessionTicketTakeScope;

impl SessionTicketTakeScope {
    fn new(allowed: bool) -> Self {
        SESSION_TICKET_TAKE_ALLOWED.set(allowed);
        Self
    }
}

impl Drop for SessionTicketTakeScope {
    fn drop(&mut self) {
        SESSION_TICKET_TAKE_ALLOWED.set(false);
    }
}

static RUSTLS_PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
static NO_VERIFIER: OnceLock<Arc<NoVerifier>> = OnceLock::new();
static RUSTLS_NO_VERIFY_RESUMPTION: OnceLock<Arc<ObservedClientSessionStore>> = OnceLock::new();
static RUSTLS_VERIFY_RESUMPTION: OnceLock<Arc<ObservedClientSessionStore>> = OnceLock::new();
static RUSTLS_CLIENT_CONFIGS: OnceLock<
    Mutex<HashMap<ClientTlsConfigKey, Arc<rustls::ClientConfig>>>,
> = OnceLock::new();
static NEXT_RUST_ENGINE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_RESUMPTION_HANDLE_ID: AtomicU64 = AtomicU64::new(1);
static RESUMPTION_HANDLES: OnceLock<Mutex<HashMap<u64, ResumptionHandle>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumptionHandleState {
    Available,
    Reserved(u64),
    Consumed,
}

#[derive(Debug)]
struct ResumptionHandle {
    hostname: String,
    verify: bool,
    issued_us: u64,
    early_data: bool,
    opaque_state: Option<Vec<u8>>,
    state: ResumptionHandleState,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ClientTlsConfigKey {
    verify: bool,
    certs: Vec<Vec<u8>>,
    calendar_unix_seconds: u64,
}

#[derive(Debug)]
struct FrozenRustlsTime {
    unix_seconds: u64,
}

impl rustls::time_provider::TimeProvider for FrozenRustlsTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            self.unix_seconds,
        )))
    }
}

#[derive(Debug)]
struct ObservedClientSessionStore {
    capacity: usize,
    kx_hints: Mutex<HashMap<ServerName<'static>, NamedGroup>>,
    tls12_sessions: Mutex<HashMap<ServerName<'static>, Tls12ClientSessionValue>>,
    tls13_tickets: Mutex<HashMap<ServerName<'static>, VecDeque<Tls13ClientSessionValue>>>,
    tls13_inserted: AtomicU64,
    tls13_early_inserted: AtomicU64,
    tls13_taken: AtomicU64,
    tls13_early_taken: AtomicU64,
}

impl ObservedClientSessionStore {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            kx_hints: Mutex::new(HashMap::new()),
            tls12_sessions: Mutex::new(HashMap::new()),
            tls13_tickets: Mutex::new(HashMap::new()),
            tls13_inserted: AtomicU64::new(0),
            tls13_early_inserted: AtomicU64::new(0),
            tls13_taken: AtomicU64::new(0),
            tls13_early_taken: AtomicU64::new(0),
        }
    }

    fn inserted(&self) -> u64 {
        self.tls13_inserted.load(Ordering::Relaxed)
    }

    fn early_inserted(&self) -> u64 {
        self.tls13_early_inserted.load(Ordering::Relaxed)
    }

    fn taken(&self) -> u64 {
        self.tls13_taken.load(Ordering::Relaxed)
    }

    fn early_taken(&self) -> u64 {
        self.tls13_early_taken.load(Ordering::Relaxed)
    }

    fn ticket_count_for(&self, server_name: &str) -> usize {
        let Ok(server_name) = ServerName::try_from(server_name.to_owned()) else {
            return 0;
        };
        self.tls13_tickets
            .lock()
            .expect("rustls ticket cache poisoned")
            .get(&server_name)
            .map_or(0, VecDeque::len)
    }

    fn early_ticket_count_for(&self, server_name: &str) -> usize {
        let Ok(server_name) = ServerName::try_from(server_name.to_owned()) else {
            return 0;
        };
        self.tls13_tickets
            .lock()
            .expect("rustls ticket cache poisoned")
            .get(&server_name)
            .map_or(0, |tickets| {
                tickets
                    .iter()
                    .filter(|ticket| ticket.max_early_data_size() > 0)
                    .count()
            })
    }
}

impl ClientSessionStore for ObservedClientSessionStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.kx_hints
            .lock()
            .expect("rustls kx hint cache poisoned")
            .insert(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.kx_hints
            .lock()
            .expect("rustls kx hint cache poisoned")
            .get(server_name)
            .cloned()
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.tls12_sessions
            .lock()
            .expect("rustls tls12 cache poisoned")
            .insert(server_name, value);
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.tls12_sessions
            .lock()
            .expect("rustls tls12 cache poisoned")
            .get(server_name)
            .cloned()
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.tls12_sessions
            .lock()
            .expect("rustls tls12 cache poisoned")
            .remove(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        self.tls13_inserted.fetch_add(1, Ordering::Relaxed);
        if value.max_early_data_size() > 0 {
            self.tls13_early_inserted.fetch_add(1, Ordering::Relaxed);
        }
        let mut tickets = self
            .tls13_tickets
            .lock()
            .expect("rustls ticket cache poisoned");
        let queue = tickets.entry(server_name).or_default();
        if queue.len() == self.capacity {
            queue.pop_front();
        }
        queue.push_back(value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        if !SESSION_TICKET_TAKE_ALLOWED.get() {
            return None;
        }
        let ticket = self
            .tls13_tickets
            .lock()
            .expect("rustls ticket cache poisoned")
            .get_mut(server_name)
            .and_then(VecDeque::pop_back);
        if let Some(value) = ticket.as_ref() {
            self.tls13_taken.fetch_add(1, Ordering::Relaxed);
            if value.max_early_data_size() > 0 {
                self.tls13_early_taken.fetch_add(1, Ordering::Relaxed);
            }
        }
        ticket
    }
}

fn quicperf_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    RUSTLS_PROVIDER
        .get_or_init(|| {
            let mut provider = rustls::crypto::ring::default_provider();
            provider
                .cipher_suites
                .retain(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
            provider
                .kx_groups
                .retain(|group| group.name() == rustls::NamedGroup::X25519);
            assert_eq!(provider.cipher_suites.len(), 1);
            assert_eq!(provider.kx_groups.len(), 1);
            Arc::new(provider)
        })
        .clone()
}

fn init_crypto_provider() {
    let _ = quicperf_crypto_provider()
        .as_ref()
        .clone()
        .install_default();
}

fn no_verifier() -> Arc<NoVerifier> {
    NO_VERIFIER.get_or_init(|| Arc::new(NoVerifier)).clone()
}

fn shared_client_resumption(verify: bool) -> rustls::client::Resumption {
    rustls::client::Resumption::store(shared_session_store(verify))
}

fn shared_session_store(verify: bool) -> Arc<ObservedClientSessionStore> {
    let slot = if verify {
        &RUSTLS_VERIFY_RESUMPTION
    } else {
        &RUSTLS_NO_VERIFY_RESUMPTION
    };
    slot.get_or_init(|| Arc::new(ObservedClientSessionStore::new(4096)))
        .clone()
}

fn shared_session_store_inserted(verify: bool) -> u64 {
    shared_session_store(verify).inserted()
}

fn shared_session_store_early_inserted(verify: bool) -> u64 {
    shared_session_store(verify).early_inserted()
}

fn shared_session_store_taken(verify: bool) -> u64 {
    shared_session_store(verify).taken()
}

fn shared_session_store_early_taken(verify: bool) -> u64 {
    shared_session_store(verify).early_taken()
}

fn shared_session_store_ticket_count(verify: bool, server_name: &str) -> usize {
    shared_session_store(verify).ticket_count_for(server_name)
}

fn shared_session_store_early_ticket_count(verify: bool, server_name: &str) -> usize {
    shared_session_store(verify).early_ticket_count_for(server_name)
}

fn resumption_handles() -> &'static Mutex<HashMap<u64, ResumptionHandle>> {
    RESUMPTION_HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn export_resumption_handle(verify: bool, hostname: &str, now_us: u64, out: &mut Vec<u8>) -> bool {
    let ticket_count = shared_session_store_ticket_count(verify, hostname);
    let early_ticket_count = shared_session_store_early_ticket_count(verify, hostname);
    let mut handles = resumption_handles()
        .lock()
        .expect("resumption handle store poisoned");
    let outstanding = handles
        .values()
        .filter(|handle| {
            handle.verify == verify
                && handle.hostname == hostname
                && handle.opaque_state.is_none()
                && handle.state != ResumptionHandleState::Consumed
        })
        .count();
    if outstanding >= ticket_count {
        return false;
    }
    let outstanding_early = handles
        .values()
        .filter(|handle| {
            handle.verify == verify
                && handle.hostname == hostname
                && handle.early_data
                && handle.opaque_state.is_none()
                && handle.state != ResumptionHandleState::Consumed
        })
        .count();
    let id = NEXT_RESUMPTION_HANDLE_ID.fetch_add(1, Ordering::Relaxed);
    handles.insert(
        id,
        ResumptionHandle {
            hostname: hostname.to_owned(),
            verify,
            issued_us: now_us,
            early_data: outstanding_early < early_ticket_count,
            opaque_state: None,
            state: ResumptionHandleState::Available,
        },
    );
    out.extend_from_slice(b"RUSTRTT4");
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&now_us.to_le_bytes());
    true
}

fn reserve_resumption_handle(
    engine_id: u64,
    verify: bool,
    hostname: &str,
    data: &[u8],
    use_zero_rtt: bool,
    now_us: u64,
    ticket_lifetime_ns: u64,
    opaque: bool,
) -> Result<Option<u64>, String> {
    const ENCODED_LENGTH: usize = 24;
    if data.len() != ENCODED_LENGTH || !data.starts_with(b"RUSTRTT4") {
        return Ok(None);
    }
    let id = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let encoded_issued_us = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let mut handles = resumption_handles()
        .lock()
        .map_err(|_| "resumption handle store poisoned".to_string())?;
    let Some(handle) = handles.get_mut(&id) else {
        return Ok(None);
    };
    if handle.hostname != hostname
        || handle.verify != verify
        || handle.issued_us != encoded_issued_us
        || (use_zero_rtt && !handle.early_data)
        || handle.opaque_state.is_some() != opaque
    {
        return Ok(None);
    }
    if handle.state != ResumptionHandleState::Available {
        return Err("resumption handle is already reserved or consumed".into());
    }
    let lifetime_us = ticket_lifetime_ns / 1_000;
    if lifetime_us == 0 || now_us < handle.issued_us || now_us - handle.issued_us > lifetime_us {
        return Ok(None);
    }
    handle.state = ResumptionHandleState::Reserved(engine_id);
    Ok(Some(id))
}

fn export_opaque_resumption_handle(
    verify: bool,
    hostname: &str,
    now_us: u64,
    early_data: bool,
    state: Vec<u8>,
    out: &mut Vec<u8>,
) {
    let id = NEXT_RESUMPTION_HANDLE_ID.fetch_add(1, Ordering::Relaxed);
    resumption_handles()
        .lock()
        .expect("resumption handle store poisoned")
        .insert(
            id,
            ResumptionHandle {
                hostname: hostname.to_owned(),
                verify,
                issued_us: now_us,
                early_data,
                opaque_state: Some(state),
                state: ResumptionHandleState::Available,
            },
        );
    out.extend_from_slice(b"RUSTRTT4");
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&now_us.to_le_bytes());
}

fn reserved_opaque_resumption_state(engine_id: u64, id: u64) -> Result<Vec<u8>, String> {
    let handles = resumption_handles()
        .lock()
        .map_err(|_| "resumption handle store poisoned".to_string())?;
    let handle = handles
        .get(&id)
        .ok_or_else(|| "resumption handle disappeared".to_string())?;
    if handle.state != ResumptionHandleState::Reserved(engine_id) {
        return Err("resumption handle reservation changed".into());
    }
    handle
        .opaque_state
        .clone()
        .ok_or_else(|| "resumption handle has no opaque transport state".to_string())
}

fn release_resumption_handle(engine_id: u64, id: u64) {
    let mut handles = resumption_handles()
        .lock()
        .expect("resumption handle store poisoned");
    if let Some(handle) = handles.get_mut(&id) {
        if handle.state == ResumptionHandleState::Reserved(engine_id) {
            handle.state = ResumptionHandleState::Available;
        }
    }
}

fn consume_resumption_handle(engine_id: u64, id: u64) -> Result<(), String> {
    let mut handles = resumption_handles()
        .lock()
        .map_err(|_| "resumption handle store poisoned".to_string())?;
    let handle = handles
        .get_mut(&id)
        .ok_or_else(|| "resumption handle disappeared".to_string())?;
    if handle.state != ResumptionHandleState::Reserved(engine_id) {
        return Err("resumption handle reservation changed".into());
    }
    handle.state = ResumptionHandleState::Consumed;
    Ok(())
}

fn store_error(message: impl Into<String>) -> i32 {
    let message = message.into().replace('\0', " ");
    let c_string =
        CString::new(message).unwrap_or_else(|_| CString::new("rust packet ffi error").unwrap());
    LAST_ERROR.with(|last_error| *last_error.borrow_mut() = Some(c_string));
    -1
}

fn clear_error() {
    LAST_ERROR.with(|last_error| *last_error.borrow_mut() = None);
}

fn ffi_result<T, F>(f: F) -> Result<T, i32>
where
    F: FnOnce() -> Result<T, String>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => {
            clear_error();
            Ok(value)
        }
        Ok(Err(error)) => Err(store_error(error)),
        Err(_) => Err(store_error("panic in rust packet ffi")),
    }
}

fn write_adapter_status(status: *mut QpfAdapterStatusV2, code: i32) {
    let Some(status) = (unsafe { status.as_mut() }) else {
        return;
    };
    status.code = code;
    status.reserved = 0;
    status.message.fill(0);
    if code == 0 {
        return;
    }
    LAST_ERROR.with(|last_error| {
        let borrowed = last_error.borrow();
        let Some(message) = borrowed.as_ref().map(|value| value.as_bytes()) else {
            return;
        };
        let count = message.len().min(status.message.len() - 1);
        for (out, byte) in status.message[..count].iter_mut().zip(&message[..count]) {
            *out = *byte as c_char;
        }
    });
}

fn batch_result<T>(
    status: *mut QpfAdapterStatusV2,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, i32> {
    let result = ffi_result(f);
    write_adapter_status(status, result.as_ref().err().copied().unwrap_or(0));
    result
}

unsafe fn cstr(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null string pointer".into());
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|e| e.to_string())
}

fn socket_from_qpf(addr: &QpfAddr) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr.ip)), addr.port)
}

fn qpf_from_socket(addr: SocketAddr) -> QpfAddr {
    match addr {
        SocketAddr::V6(v6) => QpfAddr {
            ip: v6.ip().octets(),
            port: v6.port(),
        },
        SocketAddr::V4(v4) => QpfAddr {
            ip: v4.ip().to_ipv6_mapped().octets(),
            port: v4.port(),
        },
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open cert {path}: {e}"))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse cert {path}: {e}"))
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open key {path}: {e}"))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse key {path}: {e}"))?
        .ok_or_else(|| format!("no private key in {path}"))
}

fn der_tlv<'a>(input: &'a [u8], cursor: &mut usize) -> Result<(u8, &'a [u8]), String> {
    let tag = *input
        .get(*cursor)
        .ok_or_else(|| "truncated DER tag".to_string())?;
    *cursor += 1;
    let first = *input
        .get(*cursor)
        .ok_or_else(|| "truncated DER length".to_string())?;
    *cursor += 1;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err("invalid DER length".into());
        }
        let end = (*cursor)
            .checked_add(count)
            .ok_or_else(|| "overflowing DER long length".to_string())?;
        let length_bytes = input
            .get(*cursor..end)
            .ok_or_else(|| "truncated DER long length".to_string())?;
        if length_bytes.first() == Some(&0) {
            return Err("non-canonical DER length".into());
        }
        *cursor = end;
        length_bytes.iter().try_fold(0usize, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| "overflowing DER length".to_string())
        })?
    };
    let end = (*cursor)
        .checked_add(length)
        .ok_or_else(|| "overflowing DER value length".to_string())?;
    let value = input
        .get(*cursor..end)
        .ok_or_else(|| "truncated DER value".to_string())?;
    *cursor = end;
    Ok((tag, value))
}

fn certificate_signature_is_ed25519(cert: &CertificateDer<'_>) -> bool {
    const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];
    let mut certificate_cursor = 0;
    let Ok((0x30, certificate)) = der_tlv(cert.as_ref(), &mut certificate_cursor) else {
        return false;
    };
    if certificate_cursor != cert.as_ref().len() {
        return false;
    }
    let mut cursor = 0;
    let Ok((0x30, _tbs_certificate)) = der_tlv(certificate, &mut cursor) else {
        return false;
    };
    let Ok((0x30, signature_algorithm)) = der_tlv(certificate, &mut cursor) else {
        return false;
    };
    let Ok((0x03, _signature)) = der_tlv(certificate, &mut cursor) else {
        return false;
    };
    if cursor != certificate.len() {
        return false;
    }
    let mut algorithm_cursor = 0;
    let Ok((0x06, oid)) = der_tlv(signature_algorithm, &mut algorithm_cursor) else {
        return false;
    };
    oid == ED25519_OID && algorithm_cursor == signature_algorithm.len()
}

fn client_tls_config(
    certs: Vec<CertificateDer<'static>>,
    verify: bool,
    calendar_unix_seconds: u64,
) -> Arc<rustls::ClientConfig> {
    let key = ClientTlsConfigKey {
        verify,
        certs: certs
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect::<Vec<_>>(),
        calendar_unix_seconds,
    };
    let cache = RUSTLS_CLIENT_CONFIGS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(config) = cache
        .lock()
        .expect("rustls client config cache poisoned")
        .get(&key)
        .cloned()
    {
        return config;
    }

    let builder = rustls::ClientConfig::builder_with_details(
        quicperf_crypto_provider(),
        Arc::new(FrozenRustlsTime {
            unix_seconds: calendar_unix_seconds,
        }),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("ring provider supports TLS 1.3");

    let mut config = if verify {
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots
                .add(cert)
                .expect("benchmark root certificate is valid");
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(no_verifier())
            .with_no_client_auth()
    };
    config.enable_early_data = true;
    config.resumption = shared_client_resumption(verify);
    config.alpn_protocols = vec![ALPN.to_vec()];
    let config = Arc::new(config);
    cache
        .lock()
        .expect("rustls client config cache poisoned")
        .insert(key, config.clone());
    config
}

fn server_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    calendar_unix_seconds: u64,
) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder_with_details(
        quicperf_crypto_provider(),
        Arc::new(FrozenRustlsTime {
            unix_seconds: calendar_unix_seconds,
        }),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("ring provider supports TLS 1.3")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("benchmark certificate/key pair is valid");
    config.max_early_data_size = u32::MAX;
    config.send_tls13_tickets = 1;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config
}

fn checked_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() && len != 0 {
        return Err("null data pointer".into());
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

fn checked_mut_slice<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8], String> {
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() && len != 0 {
        return Err("null mutable data pointer".into());
    }
    Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

#[derive(Clone, Copy)]
struct CallerTimeEpoch {
    raw_epoch_us: u64,
    instant_epoch: Instant,
}

impl CallerTimeEpoch {
    fn initialize(raw_epoch_us: u64) -> Self {
        // This is the sole permitted production opaque-Instant epoch read. It occurs
        // while the worker is initializing, before READY. All transport time
        // after READY is constructed from caller CLOCK_MONOTONIC_RAW values.
        Self {
            raw_epoch_us,
            instant_epoch: Instant::now(), // QUICPERF_PRE_READY_INSTANT_EPOCH
        }
    }

    fn instant_at(self, raw_us: u64) -> Result<Instant, String> {
        let delta = raw_us
            .checked_sub(self.raw_epoch_us)
            .ok_or_else(|| "caller raw time precedes the transport epoch".to_string())?;
        self.instant_epoch
            .checked_add(Duration::from_micros(delta))
            .ok_or_else(|| "caller raw time exceeds the representable transport epoch".to_string())
    }

    fn raw_us_at(self, instant: Instant) -> Result<u64, String> {
        let delta = instant
            .checked_duration_since(self.instant_epoch)
            .ok_or_else(|| "transport deadline precedes its synthetic epoch".to_string())?
            .as_micros();
        let delta = u64::try_from(delta)
            .map_err(|_| "transport deadline delta exceeds u64 microseconds".to_string())?;
        self.raw_epoch_us
            .checked_add(delta)
            .ok_or_else(|| "transport deadline overflows caller raw time".to_string())
    }

    fn delay_until_us(self, now_us: u64, deadline: Instant) -> Result<u64, String> {
        self.instant_at(now_us)?;
        Ok(self.raw_us_at(deadline)?.saturating_sub(now_us))
    }

    #[cfg(test)]
    fn from_parts(raw_epoch_us: u64, instant_epoch: Instant) -> Self {
        Self {
            raw_epoch_us,
            instant_epoch,
        }
    }
}

#[cfg(test)]
mod caller_time_tests {
    use super::*;
    use rustls::time_provider::TimeProvider as _;

    #[test]
    fn caller_time_round_trips_fake_clock_jumps() {
        let instant_epoch = Instant::now(); // QUICPERF_TEST_ONLY_INSTANT
        let epoch = CallerTimeEpoch::from_parts(7_000_000, instant_epoch);
        for offset in [0, 1, 999, 1_000_000, 86_400_000_000] {
            let raw = epoch.raw_epoch_us + offset;
            let instant = epoch.instant_at(raw).unwrap();
            assert_eq!(epoch.raw_us_at(instant).unwrap(), raw);
            assert_eq!(
                epoch.delay_until_us(epoch.raw_epoch_us, instant).unwrap(),
                offset
            );
        }
    }

    #[test]
    fn caller_time_rejects_regression_and_unrepresentable_deadlines() {
        let instant_epoch = Instant::now(); // QUICPERF_TEST_ONLY_INSTANT
        let epoch = CallerTimeEpoch::from_parts(1, instant_epoch);
        assert!(epoch.instant_at(0).is_err());
        assert!(epoch
            .raw_us_at(instant_epoch.checked_sub(Duration::from_micros(1)).unwrap())
            .is_err());
        let beyond_raw_range = instant_epoch
            .checked_add(Duration::from_micros(u64::MAX))
            .unwrap();
        assert!(epoch.raw_us_at(beyond_raw_range).is_err());
    }

    #[test]
    fn rustls_calendar_time_is_frozen_and_separate() {
        let provider = FrozenRustlsTime {
            unix_seconds: 1_784_376_000,
        };
        assert_eq!(provider.current_time().unwrap().as_secs(), 1_784_376_000);
    }
}

macro_rules! proto_engine {
    (
        $mod_name:ident,
        $engine_name:ident,
        $proto:path,
        $bbr_factory:expr,
        $poll_datagrams:expr,
        $handle_datagram:expr,
        $transport_counters:expr
    ) => {
        mod $mod_name {
            use super::*;
            use bytes::{Bytes, BytesMut};
            use $proto as proto;

            struct ConnState {
                conn: proto::Connection,
                connected: bool,
                accepted_bidi_streams: VecDeque<u64>,
                accepted_uni_streams: VecDeque<u64>,
                closed: bool,
                pending_rx: HashMap<u64, VecDeque<Bytes>>,
                peer_terminal: HashMap<u64, QpfPeerTerminalFactsV6>,
                peer_connection_close: Option<(u64, u64)>,
                retire_when_drained: bool,
                drained: bool,
            }

            struct Outbound {
                destination: SocketAddr,
                bytes: Vec<u8>,
            }

            pub struct $engine_name {
                endpoint: proto::Endpoint,
                client_config: Option<proto::ClientConfig>,
                server_config: Option<Arc<proto::ServerConfig>>,
                connections: HashMap<proto::ConnectionHandle, ConnState>,
                accepted_connections: VecDeque<u64>,
                outbound: VecDeque<Outbound>,
                caller_time: CallerTimeEpoch,
                local_addr: SocketAddr,
                tls_hostname: String,
                tls_verify_peer: bool,
                resumption_take_baseline: u64,
                resumption_early_take_baseline: u64,
                engine_id: u64,
                pending_resumption_handle: Option<u64>,
                local_settings: QpfNegotiatedSettingsV7,
                retired_transport_counters: QpfTransportCountersV3,
            }

            impl $engine_name {
                pub fn new(config: &QpfConfig) -> Result<Self, String> {
                    let caller_time = CallerTimeEpoch::initialize(config.now_us);
                    init_crypto_provider();
                    let cert_path = unsafe { cstr(config.cert_path)? };
                    let chain_path = unsafe { cstr(config.chain_path)? };
                    let tls_hostname = unsafe { cstr(config.tls_hostname)? };
                    let certs = load_certs(&cert_path)?;
                    let local_leaf_ed25519 = certs
                        .first()
                        .is_some_and(certificate_signature_is_ed25519);
                    if !local_leaf_ed25519 {
                        return Err("configured leaf certificate is not signed with Ed25519".into());
                    }
                    let connection_window = u32::try_from(config.connection_window)
                        .map_err(|_| "connection window exceeds packet-engine limit".to_string())?;
                    let stream_window = u32::try_from(config.stream_window)
                        .map_err(|_| "stream window exceeds packet-engine limit".to_string())?;
                    let max_bidi_streams = u32::try_from(config.max_bidi_streams)
                        .map_err(|_| "bidirectional stream limit exceeds packet-engine limit".to_string())?;
                    let max_uni_streams = u32::try_from(config.max_uni_streams)
                        .map_err(|_| "unidirectional stream limit exceeds packet-engine limit".to_string())?;
                    let udp_payload_size = u16::try_from(config.udp_payload_size)
                        .map_err(|_| "UDP payload size exceeds packet-engine limit".to_string())?;
                    let datagram_max_frame_size = usize::try_from(config.datagram_max_frame_size)
                        .map_err(|_| "DATAGRAM frame size exceeds packet-engine limit".to_string())?;
                    let connection_id_bytes = usize::try_from(config.connection_id_bytes)
                        .map_err(|_| "connection ID size exceeds packet-engine limit".to_string())?;
                    if config.max_ack_delay_ns != 25_000_000
                        || config.ack_delay_exponent != 3
                        || config.ack_frequency
                        || config.active_migration
                        || config.active_connection_id_limit != 2
                        || connection_id_bytes != 8
                        || udp_payload_size != 1_350
                        || datagram_max_frame_size != 1_200
                        || config.ticket_lifetime_ns != 300_000_000_000
                        || config.maximum_early_data_bytes != 4_096
                        || !config.one_use_tickets
                    {
                        return Err("Rust packet engine requires the frozen exact treatment".into());
                    }
                    let mut transport = proto::TransportConfig::default();
                    transport
                        .receive_window(proto::VarInt::from_u32(connection_window))
                        .stream_receive_window(proto::VarInt::from_u32(stream_window))
                        .send_window(APPLICATION_BUFFER_BYTES)
                        .max_concurrent_bidi_streams(proto::VarInt::from_u32(max_bidi_streams))
                        .max_concurrent_uni_streams(proto::VarInt::from_u32(max_uni_streams))
                        .max_idle_timeout(Some(
                            proto::IdleTimeout::try_from(Duration::from_millis(
                                config.idle_timeout_ms,
                            ))
                            .map_err(|e| format!("{e:?}"))?,
                        ))
                        .datagram_receive_buffer_size(Some(datagram_max_frame_size))
                        .datagram_send_buffer_size(datagram_max_frame_size)
                        .initial_mtu(udp_payload_size)
                        .min_mtu(udp_payload_size)
                        .mtu_discovery_config(None)
                        .ack_frequency_config(None)
                        .quicperf_active_connection_id_limit(
                            proto::VarInt::from_u64(config.active_connection_id_limit)
                                .map_err(|e| format!("active connection ID limit: {e:?}"))?,
                        )
                        .quicperf_disable_active_migration(!config.active_migration)
                        .enable_segmentation_offload(false);
                    if config.use_bbr {
                        transport.congestion_controller_factory(
                            ($bbr_factory)(config.initial_congestion_window_bytes),
                        );
                    } else {
                        let mut cubic = proto::congestion::CubicConfig::default();
                        cubic.initial_window(config.initial_congestion_window_bytes);
                        transport.congestion_controller_factory(Arc::new(cubic));
                    }
                    let transport = Arc::new(transport);

                    let mut endpoint_config = proto::EndpointConfig::default();
                    endpoint_config
                        .max_udp_payload_size(udp_payload_size)
                        .map_err(|e| format!("{e:?}"))?
                        .cid_generator(Arc::new(move || {
                            Box::new(proto::RandomConnectionIdGenerator::new(connection_id_bytes))
                        }));
                    let endpoint_config = Arc::new(endpoint_config);
                    let (server_config, client_config) = if config.is_server {
                        let key_path = unsafe { cstr(config.key_path)? };
                        let key = load_key(&key_path)?;
                        let mut tls = rustls::ServerConfig::builder_with_details(
                            quicperf_crypto_provider(),
                            Arc::new(FrozenRustlsTime {
                                unix_seconds: config.calendar_unix_seconds,
                            }),
                        )
                        .with_protocol_versions(&[&rustls::version::TLS13])
                        .map_err(|e| format!("server tls versions: {e:?}"))?
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .map_err(|e| format!("server tls cert: {e}"))?;
                        tls.max_early_data_size = u32::MAX;
                        tls.send_tls13_tickets = 1;
                        tls.alpn_protocols = vec![ALPN.to_vec()];
                        let quic_tls = proto::crypto::rustls::QuicServerConfig::try_from(tls)
                            .map_err(|e| format!("server quic tls config: {e:?}"))?;
                        let mut server = proto::ServerConfig::with_crypto(Arc::new(quic_tls));
                        #[derive(Debug)]
                        struct FrozenProtoTime(SystemTime);
                        impl proto::TimeSource for FrozenProtoTime {
                            fn now(&self) -> SystemTime {
                                self.0
                            }
                        }
                        server.time_source(Arc::new(FrozenProtoTime(
                            SystemTime::UNIX_EPOCH
                                .checked_add(Duration::from_secs(config.calendar_unix_seconds))
                                .ok_or_else(|| "calendar Unix time is not representable".to_string())?,
                        )));
                        server.migration(config.active_migration);
                        server.transport_config(transport.clone());
                        (Some(Arc::new(server)), None)
                    } else {
                        let roots = if config.tls_verify_peer {
                            load_certs(&chain_path)?
                        } else {
                            certs
                        };
                        let tls = client_tls_config(
                            roots,
                            config.tls_verify_peer,
                            config.calendar_unix_seconds,
                        );
                        let quic_tls = proto::crypto::rustls::QuicClientConfig::try_from(tls)
                            .map_err(|e| format!("client tls config: {e:?}"))?;
                        let mut client = proto::ClientConfig::new(Arc::new(quic_tls));
                        client.initial_dst_cid_provider(Arc::new(move || {
                            let mut generator =
                                proto::RandomConnectionIdGenerator::new(connection_id_bytes);
                            proto::ConnectionIdGenerator::generate_cid(&mut generator)
                        }));
                        client.transport_config(transport.clone());
                        (None, Some(client))
                    };

                    Ok(Self {
                        endpoint: proto::Endpoint::new(
                            endpoint_config,
                            server_config.clone(),
                            false,
                        ),
                        client_config,
                        server_config,
                        connections: HashMap::new(),
                        accepted_connections: VecDeque::new(),
                        outbound: VecDeque::new(),
                        caller_time,
                        local_addr: socket_from_qpf(&config.local_addr),
                        tls_hostname,
                        tls_verify_peer: config.tls_verify_peer,
                        resumption_take_baseline: 0,
                        resumption_early_take_baseline: 0,
                        engine_id: NEXT_RUST_ENGINE_ID.fetch_add(1, Ordering::Relaxed),
                        pending_resumption_handle: None,
                        retired_transport_counters: QpfTransportCountersV3::default(),
                        local_settings: QpfNegotiatedSettingsV7 {
                            tls_leaf_ed25519: u8::from(local_leaf_ed25519),
                            use_bbr: u8::from(config.use_bbr),
                            ack_frequency: u8::from(config.ack_frequency),
                            active_migration: u8::from(config.active_migration),
                            one_use_tickets: u8::from(config.one_use_tickets),
                            initial_congestion_window_bytes: config.initial_congestion_window_bytes,
                            stream_credit_replenish_below: config.stream_credit_replenish_below,
                            ticket_lifetime_ns: config.ticket_lifetime_ns,
                            maximum_early_data_bytes: config.maximum_early_data_bytes,
                            ..QpfNegotiatedSettingsV7::default()
                        },
                    })
                }

                fn connection_negotiated_settings(
                    &self,
                    state: &ConnState,
                ) -> Result<QpfNegotiatedSettingsV7, String> {
                    if !state.connected {
                        return Err("connection has no completed handshake".into());
                    }
                    let transport = state.conn.quicperf_negotiated_transport();
                    if transport.initial_max_stream_data_bidi_local
                        != transport.initial_max_stream_data_bidi_remote
                        || transport.initial_max_stream_data_bidi_local
                            != transport.initial_max_stream_data_uni
                    {
                        return Err("peer stream windows differ".into());
                    }
                    let handshake = state
                        .conn
                        .crypto_session()
                        .handshake_data()
                        .ok_or_else(|| "TLS handshake data is unavailable".to_string())?
                        .downcast::<proto::crypto::rustls::HandshakeData>()
                        .map_err(|_| "TLS handshake data has an unexpected type".to_string())?;
                    let peer_certs = state
                        .conn
                        .crypto_session()
                        .peer_identity()
                        .map(|identity| {
                            identity
                                .downcast::<Vec<CertificateDer<'static>>>()
                                .map(|certs| *certs)
                                .map_err(|_| "TLS peer identity has an unexpected type".to_string())
                        })
                        .transpose()?;
                    let peer_certificate_present =
                        peer_certs.as_ref().is_some_and(|certs| !certs.is_empty());
                    let leaf_ed25519 = peer_certs
                        .as_ref()
                        .and_then(|certs| certs.first())
                        .map_or(self.local_settings.tls_leaf_ed25519 != 0, |cert| {
                            certificate_signature_is_ed25519(cert)
                        });
                    let max_idle_timeout_ns = transport
                        .max_idle_timeout
                        .checked_mul(1_000_000)
                        .ok_or_else(|| "peer idle timeout overflows nanoseconds".to_string())?;
                    let max_ack_delay_ns = transport
                        .max_ack_delay
                        .checked_mul(1_000_000)
                        .ok_or_else(|| "peer ACK delay overflows nanoseconds".to_string())?;
                    let mut settings = self.local_settings;
                    settings.available = 1;
                    settings.alpn_qperf_2 =
                        u8::from(handshake.protocol.as_deref() == Some(ALPN));
                    settings.peer_certificate_present = u8::from(peer_certificate_present);
                    settings.peer_certificate_verified =
                        u8::from(self.tls_verify_peer && peer_certificate_present);
                    settings.hostname_verified = settings.peer_certificate_verified;
                    settings.tls_leaf_ed25519 = u8::from(leaf_ed25519);
                    settings.quic_version = transport.quic_version;
                    settings.tls_version = match handshake.protocol_version {
                        Some(rustls::ProtocolVersion::TLSv1_3) => 0x0304,
                        _ => 0,
                    };
                    settings.tls_cipher_suite = match handshake.cipher_suite {
                        Some(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256) => 0x1301,
                        _ => 0,
                    };
                    settings.tls_key_exchange_group = match handshake.negotiated_key_exchange_group {
                        Some(rustls::NamedGroup::X25519) => 0x001d,
                        _ => 0,
                    };
                    settings.tls_leaf_signature_algorithm =
                        if leaf_ed25519 { 0x0807 } else { 0 };
                    settings.max_udp_payload_size = transport.max_udp_payload_size;
                    settings.max_ack_delay_ns = max_ack_delay_ns;
                    settings.ack_delay_exponent = transport.ack_delay_exponent;
                    settings.ack_frequency = u8::from(transport.ack_frequency);
                    settings.active_migration = u8::from(!transport.disable_active_migration);
                    settings.active_connection_id_limit = transport.active_connection_id_limit;
                    settings.connection_id_bytes = u64::try_from(transport.connection_id_len)
                        .map_err(|_| "peer connection ID length does not fit u64".to_string())?;
                    settings.max_idle_timeout_ns = max_idle_timeout_ns;
                    settings.max_bidi_streams = transport.initial_max_streams_bidi;
                    settings.max_uni_streams = transport.initial_max_streams_uni;
                    settings.connection_window_bytes = transport.initial_max_data;
                    settings.stream_window_bytes =
                        transport.initial_max_stream_data_bidi_local;
                    settings.datagram_max_frame_size = transport.max_datagram_frame_size;
                    Ok(settings)
                }

                fn now(&self, now_us: u64) -> Result<Instant, String> {
                    self.caller_time.instant_at(now_us)
                }

                fn stream_id(raw: u64) -> proto::StreamId {
                    proto::StreamId::new(
                        if raw & 1 == 0 {
                            proto::Side::Client
                        } else {
                            proto::Side::Server
                        },
                        if raw & 2 == 0 {
                            proto::Dir::Bi
                        } else {
                            proto::Dir::Uni
                        },
                        raw >> 2,
                    )
                }

                fn queue_transmit(&mut self, transmit: proto::Transmit, buf: &[u8]) {
                    if let Some(segment_size) = transmit.segment_size {
                        for chunk in buf.chunks(segment_size) {
                            self.outbound.push_back(Outbound {
                                destination: transmit.destination,
                                bytes: chunk.to_vec(),
                            });
                        }
                    } else {
                        self.outbound.push_back(Outbound {
                            destination: transmit.destination,
                            bytes: buf.to_vec(),
                        });
                    }
                }

                fn add_transport_counters(
                    total: &mut QpfTransportCountersV3,
                    value: QpfTransportCountersV3,
                ) {
                    total.packets_lost = total.packets_lost.saturating_add(value.packets_lost);
                    total.packets_retransmitted = total
                        .packets_retransmitted
                        .saturating_add(value.packets_retransmitted);
                    total.recovery_wakeups = total
                        .recovery_wakeups
                        .saturating_add(value.recovery_wakeups);
                    total.flow_control_blocked_events = total
                        .flow_control_blocked_events
                        .saturating_add(value.flow_control_blocked_events);
                    total.stream_credit_blocked_events = total
                        .stream_credit_blocked_events
                        .saturating_add(value.stream_credit_blocked_events);
                }

                fn process_datagram_event(
                    &mut self,
                    event: proto::DatagramEvent,
                    now: Instant,
                    buf: &mut Vec<u8>,
                ) -> Result<(), String> {
                    match event {
                        proto::DatagramEvent::NewConnection(incoming) => {
                            buf.clear();
                            let (ch, conn) = match self.endpoint.accept(
                                incoming,
                                now,
                                buf,
                                self.server_config.clone(),
                            ) {
                                Ok(accepted) => accepted,
                                Err(error) => {
                                    if let Some(transmit) = error.response {
                                        let size = transmit.size;
                                        if size > buf.len() {
                                            return Err(format!(
                                                "accept response exceeded produced buffer: {size} > {}",
                                                buf.len()
                                            ));
                                        }
                                        self.queue_transmit(transmit, &buf[..size]);
                                    }
                                    return Ok(());
                                }
                            };
                            self.connections.insert(
                                ch,
                                ConnState {
                                    conn,
                                    connected: false,
                                    accepted_bidi_streams: VecDeque::new(),
                                    accepted_uni_streams: VecDeque::new(),
                                    closed: false,
                                    pending_rx: HashMap::new(),
                                    peer_terminal: HashMap::new(),
                                    peer_connection_close: None,
                                    retire_when_drained: false,
                                    drained: false,
                                },
                            );
                            self.accepted_connections.push_back(ch.0 as u64);
                        }
                        proto::DatagramEvent::ConnectionEvent(ch, event) => {
                            if let Some(state) = self.connections.get_mut(&ch) {
                                state.conn.handle_event(event);
                            }
                        }
                        proto::DatagramEvent::Response(transmit) => {
                            let size = transmit.size;
                            if size > buf.len() {
                                return Err(format!(
                                    "endpoint response exceeded produced buffer: {size} > {}",
                                    buf.len()
                                ));
                            }
                            self.queue_transmit(transmit, &buf[..size]);
                        }
                    }
                    Ok(())
                }

                fn drive(&mut self, now_us: u64) -> Result<(), String> {
                    let now = self.now(now_us)?;
                    for state in self.connections.values_mut() {
                        if state
                            .conn
                            .poll_timeout()
                            .is_some_and(|deadline| deadline <= now)
                        {
                            state.conn.handle_timeout(now);
                        }
                    }

                    for _ in 0..MAX_PROTO_DRIVE_PASSES {
                        let mut endpoint_events = Vec::new();
                        let mut transmits = Vec::new();
                        let mut app_events = Vec::new();
                        let collect_transmits = self.outbound.is_empty();

                        for (ch, state) in self.connections.iter_mut() {
                            while let Some(event) = state.conn.poll_endpoint_events() {
                                if event.is_drained() {
                                    state.drained = true;
                                }
                                endpoint_events.push((*ch, event));
                            }
                            while let Some(event) = state.conn.poll() {
                                app_events.push((*ch, event));
                            }
                            if collect_transmits {
                                let mut buf = Vec::with_capacity(usize::from(
                                    self.endpoint.config().get_max_udp_payload_size() as usize,
                                ));
                                if let Some(transmit) =
                                    state.conn.poll_transmit(now, $poll_datagrams, &mut buf)
                                {
                                    let size = transmit.size;
                                    if size > buf.len() {
                                        return Err(format!(
                                            "connection transmit exceeded produced buffer: {size} > {}",
                                            buf.len()
                                        ));
                                    }
                                    transmits.push((transmit, buf[..size].to_vec()));
                                }
                            }
                        }

                        let mut had_progress = !endpoint_events.is_empty() || !transmits.is_empty();

                        for (ch, event) in endpoint_events {
                            if let Some(event) = self.endpoint.handle_event(ch, event) {
                                if let Some(state) = self.connections.get_mut(&ch) {
                                    state.conn.handle_event(event);
                                }
                            }
                        }

                        for (ch, event) in app_events {
                            if let Some(state) = self.connections.get_mut(&ch) {
                                #[allow(unreachable_patterns)]
                                match event {
                                    proto::Event::Connected => {
                                        state.connected = true;
                                        had_progress = true;
                                    }
                                    proto::Event::ConnectionLost { reason } => {
                                        if let proto::ConnectionError::ApplicationClosed(close) = reason {
                                            state.peer_connection_close = Some((
                                                close.error_code.into_inner(),
                                                close.reason.len() as u64,
                                            ));
                                        }
                                        state.closed = true;
                                        had_progress = true;
                                    }
                                    proto::Event::Stream(proto::StreamEvent::Opened { dir })
                                        if dir == proto::Dir::Bi =>
                                    {
                                        let before = state.accepted_bidi_streams.len();
                                        while let Some(stream_id) =
                                            state.conn.streams().accept(proto::Dir::Bi)
                                        {
                                            state.accepted_bidi_streams.push_back(u64::from(stream_id));
                                        }
                                        if state.accepted_bidi_streams.len() != before {
                                            had_progress = true;
                                        }
                                    }
                                    proto::Event::Stream(proto::StreamEvent::Opened { dir })
                                        if dir == proto::Dir::Uni =>
                                    {
                                        let before = state.accepted_uni_streams.len();
                                        while let Some(stream_id) =
                                            state.conn.streams().accept(proto::Dir::Uni)
                                        {
                                            state.accepted_uni_streams.push_back(u64::from(stream_id));
                                        }
                                        if state.accepted_uni_streams.len() != before {
                                            had_progress = true;
                                        }
                                    }
                                    proto::Event::Stream(proto::StreamEvent::Stopped {
                                        id,
                                        error_code,
                                    }) => {
                                        let terminal = state
                                            .peer_terminal
                                            .entry(u64::from(id))
                                            .or_default();
                                        terminal.available = true;
                                        terminal.stop_sending = true;
                                        terminal.stop_sending_error = error_code.into_inner();
                                        had_progress = true;
                                    }
                                    proto::Event::Stream(proto::StreamEvent::Opened { .. })
                                    | proto::Event::Stream(proto::StreamEvent::Readable {
                                        ..
                                    })
                                    | proto::Event::Stream(proto::StreamEvent::Writable {
                                        ..
                                    })
                                    | proto::Event::Stream(proto::StreamEvent::Finished {
                                        ..
                                    })
                                    | proto::Event::Stream(proto::StreamEvent::Available {
                                        ..
                                    })
                                    | proto::Event::HandshakeDataReady
                                    | proto::Event::HandshakeConfirmed
                                    | proto::Event::DatagramReceived
                                    | proto::Event::DatagramsUnblocked => {}
                                    _ => {}
                                }
                            }
                        }

                        for (transmit, bytes) in transmits {
                            self.queue_transmit(transmit, &bytes);
                        }

                        if !had_progress || !self.outbound.is_empty() {
                            break;
                        }
                    }
                    let retired: Vec<_> = self
                        .connections
                        .iter()
                        .filter_map(|(ch, state)| {
                            (state.retire_when_drained && state.drained).then_some(*ch)
                        })
                        .collect();
                    for ch in retired {
                        if let Some(mut state) = self.connections.remove(&ch) {
                            let counters = ($transport_counters)(&mut state.conn);
                            Self::add_transport_counters(
                                &mut self.retired_transport_counters,
                                counters,
                            );
                        }
                    }
                    Ok(())
                }
            }

            impl PacketEngine for $engine_name {
                fn connect(&mut self, remote: SocketAddr, now_us: u64) -> Result<u64, String> {
                    let now = self.now(now_us)?;
                    let config = self
                        .client_config
                        .clone()
                        .ok_or_else(|| "connect called on server endpoint".to_string())?;
                    let pending_resumption_handle = self.pending_resumption_handle;
                    let ticket_scope =
                        SessionTicketTakeScope::new(pending_resumption_handle.is_some());
                    let (ch, conn) = self
                        .endpoint
                        .connect(now, config, remote, &self.tls_hostname)
                        .map_err(|e| format!("connect: {e:?}"))?;
                    drop(ticket_scope);
                    if let Some(handle_id) = pending_resumption_handle {
                        self.pending_resumption_handle = None;
                        if shared_session_store_taken(self.tls_verify_peer)
                            <= self.resumption_take_baseline
                        {
                            release_resumption_handle(self.engine_id, handle_id);
                            return Err("reserved resumption handle did not supply a TLS ticket".into());
                        }
                        consume_resumption_handle(self.engine_id, handle_id)?;
                    }
                    if std::env::var_os("QUICPERF_PACKET_RESUMPTION_DEBUG").is_some() {
                        let early_crypto = conn.crypto_session().early_crypto().is_some();
                        let transport_parameters = conn.crypto_session().transport_parameters();
                        eprintln!(
                            "{} connect conn={} has_0rtt={} early_crypto={} transport_parameters={:?} taken={} early_taken={}",
                            stringify!($engine_name),
                            ch.0,
                            conn.has_0rtt(),
                            early_crypto,
                            transport_parameters,
                            shared_session_store_taken(self.tls_verify_peer),
                            shared_session_store_early_taken(self.tls_verify_peer)
                        );
                    }
                    self.connections.insert(
                        ch,
                        ConnState {
                            conn,
                            connected: false,
                            accepted_bidi_streams: VecDeque::new(),
                            accepted_uni_streams: VecDeque::new(),
                            closed: false,
                            pending_rx: HashMap::new(),
                            peer_terminal: HashMap::new(),
                            peer_connection_close: None,
                            retire_when_drained: false,
                            drained: false,
                        },
                    );
                    Ok(ch.0 as u64)
                }

                fn accept_connection(&mut self) -> Option<u64> {
                    self.accepted_connections.pop_front()
                }

                fn is_connected(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
                    self.drive(now_us)?;
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    Ok(self
                        .connections
                        .get(&ch)
                        .is_some_and(|state| state.connected))
                }

                fn connection_is_closed(
                    &mut self,
                    conn_id: u64,
                    now_us: u64,
                ) -> Result<bool, String> {
                    self.drive(now_us)?;
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    self.connections
                        .get(&ch)
                        .map(|state| state.closed)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))
                }

                fn retire_connection(
                    &mut self,
                    conn_id: u64,
                    now_us: u64,
                ) -> Result<(), String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    self.connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?
                        .retire_when_drained = true;
                    self.drive(now_us)
                }

                fn receive(
                    &mut self,
                    remote: SocketAddr,
                    data: &[u8],
                    now_us: u64,
                ) -> Result<(), String> {
                    let now = self.now(now_us)?;
                    let mut buf = Vec::with_capacity(usize::from(
                        self.endpoint.config().get_max_udp_payload_size() as usize,
                    ));
                    if let Some(event) = ($handle_datagram)(
                        &mut self.endpoint,
                        now,
                        self.local_addr,
                        remote,
                        BytesMut::from(data),
                        &mut buf,
                    ) {
                        self.process_datagram_event(event, now, &mut buf)?;
                    }
                    self.drive(now_us)
                }

                fn poll_transmit(
                    &mut self,
                    now_us: u64,
                    out: &mut [u8],
                ) -> Result<Option<(SocketAddr, usize)>, String> {
                    if self.outbound.is_empty() {
                        self.drive(now_us)?;
                    }
                    if let Some(next) = self.outbound.pop_front() {
                        if next.bytes.len() > out.len() {
                            return Err("transmit buffer too small".into());
                        }
                        out[..next.bytes.len()].copy_from_slice(&next.bytes);
                        Ok(Some((next.destination, next.bytes.len())))
                    } else {
                        Ok(None)
                    }
                }

                fn next_timeout_us(&mut self, now_us: u64) -> Result<Option<u64>, String> {
                    self.now(now_us)?;
                    let timeout = self
                        .connections
                        .values_mut()
                        .filter_map(|state| state.conn.poll_timeout())
                        .min();
                    timeout
                        .map(|deadline| self.caller_time.delay_until_us(now_us, deadline))
                        .transpose()
                }

                fn on_timeout(&mut self, now_us: u64) -> Result<(), String> {
                    self.drive(now_us)
                }

                fn export_resumption_state(
                    &mut self,
                    _conn_id: u64,
                    now_us: u64,
                    out: &mut Vec<u8>,
                ) -> Result<bool, String> {
                    self.drive(now_us)?;
                    if std::env::var_os("QUICPERF_PACKET_RESUMPTION_DEBUG").is_some() {
                        eprintln!(
                            "{} resumption export inserted={} early_inserted={} taken={} early_taken={}",
                            stringify!($engine_name),
                            shared_session_store_inserted(self.tls_verify_peer),
                            shared_session_store_early_inserted(self.tls_verify_peer),
                            shared_session_store_taken(self.tls_verify_peer),
                            shared_session_store_early_taken(self.tls_verify_peer)
                        );
                    }
                    Ok(export_resumption_handle(
                        self.tls_verify_peer,
                        &self.tls_hostname,
                        now_us,
                        out,
                    ))
                }

                fn import_resumption_state(
                    &mut self,
                    data: &[u8],
                    use_zero_rtt: bool,
                    now_us: u64,
                ) -> Result<bool, String> {
                    if self.pending_resumption_handle.is_some() {
                        return Ok(false);
                    }
                    let Some(handle_id) = reserve_resumption_handle(
                        self.engine_id,
                        self.tls_verify_peer,
                        &self.tls_hostname,
                        data,
                        use_zero_rtt,
                        now_us,
                        self.local_settings.ticket_lifetime_ns,
                        false,
                    )? else {
                        return Ok(false);
                    };
                    self.pending_resumption_handle = Some(handle_id);
                    self.resumption_take_baseline =
                        shared_session_store_taken(self.tls_verify_peer);
                    self.resumption_early_take_baseline =
                        shared_session_store_early_taken(self.tls_verify_peer);
                    if std::env::var_os("QUICPERF_PACKET_RESUMPTION_DEBUG").is_some() {
                        eprintln!(
                            "{} resumption import inserted={} early_inserted={} taken={} early_taken={}",
                            stringify!($engine_name),
                            shared_session_store_inserted(self.tls_verify_peer),
                            shared_session_store_early_inserted(self.tls_verify_peer),
                            self.resumption_take_baseline,
                            self.resumption_early_take_baseline
                        );
                    }
                    Ok(true)
                }

                fn connection_resumed(
                    &mut self,
                    conn_id: u64,
                    now_us: u64,
                ) -> Result<bool, String> {
                    self.drive(now_us)?;
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    if std::env::var_os("QUICPERF_PACKET_RESUMPTION_DEBUG").is_some() {
                        eprintln!(
                            "{} connection_resumed conn={} connected={} has_0rtt={} accepted_0rtt={} taken={} early_taken={} baseline={} early_baseline={}",
                            stringify!($engine_name),
                            conn_id,
                            state.connected,
                            state.conn.has_0rtt(),
                            state.conn.accepted_0rtt(),
                            shared_session_store_taken(self.tls_verify_peer),
                            shared_session_store_early_taken(self.tls_verify_peer),
                            self.resumption_take_baseline,
                            self.resumption_early_take_baseline
                        );
                    }
                    Ok(state.connected
                        && (shared_session_store_taken(self.tls_verify_peer)
                            > self.resumption_take_baseline
                            || state.conn.accepted_0rtt()
                            || (state.conn.has_0rtt()
                                && shared_session_store_early_taken(self.tls_verify_peer)
                                    > self.resumption_early_take_baseline)))
                }

                fn zero_rtt_attempted(
                    &mut self,
                    conn_id: u64,
                    now_us: u64,
                ) -> Result<bool, String> {
                    self.drive(now_us)?;
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    if std::env::var_os("QUICPERF_PACKET_RESUMPTION_DEBUG").is_some() {
                        eprintln!(
                            "{} zero_rtt_attempted conn={} connected={} has_0rtt={} accepted_0rtt={} taken={} early_taken={} baseline={} early_baseline={}",
                            stringify!($engine_name),
                            conn_id,
                            state.connected,
                            state.conn.has_0rtt(),
                            state.conn.accepted_0rtt(),
                            shared_session_store_taken(self.tls_verify_peer),
                            shared_session_store_early_taken(self.tls_verify_peer),
                            self.resumption_take_baseline,
                            self.resumption_early_take_baseline
                        );
                    }
                    Ok(state.conn.has_0rtt())
                }

                fn zero_rtt_accepted(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
                    self.drive(now_us)?;
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    Ok(state.conn.accepted_0rtt())
                }

                fn zero_rtt_rejected(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
                    self.drive(now_us)?;
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    Ok(state.connected && state.conn.has_0rtt() && !state.conn.accepted_0rtt())
                }

                fn open_bidi(&mut self, conn_id: u64, _now_us: u64) -> Result<Option<u64>, String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    Ok(state.conn.streams().open(proto::Dir::Bi).map(u64::from))
                }

                fn accept_bidi(
                    &mut self,
                    conn_id: u64,
                    _now_us: u64,
                ) -> Result<Option<u64>, String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    if state.accepted_bidi_streams.is_empty() {
                        while let Some(stream_id) = state.conn.streams().accept(proto::Dir::Bi) {
                            state.accepted_bidi_streams.push_back(u64::from(stream_id));
                        }
                    }
                    Ok(state.accepted_bidi_streams.pop_front())
                }

                fn open_uni(&mut self, conn_id: u64, _now_us: u64) -> Result<Option<u64>, String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    Ok(state.conn.streams().open(proto::Dir::Uni).map(u64::from))
                }

                fn accept_uni(
                    &mut self,
                    conn_id: u64,
                    _now_us: u64,
                ) -> Result<Option<u64>, String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    if state.accepted_uni_streams.is_empty() {
                        while let Some(stream_id) = state.conn.streams().accept(proto::Dir::Uni) {
                            state.accepted_uni_streams.push_back(u64::from(stream_id));
                        }
                    }
                    Ok(state.accepted_uni_streams.pop_front())
                }

                fn stream_send(
                    &mut self,
                    conn_id: u64,
                    stream_id: u64,
                    data: &[u8],
                    _now_us: u64,
                ) -> Result<usize, String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let sid = Self::stream_id(stream_id);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    let written = match state.conn.send_stream(sid).write(data) {
                        Ok(written) => written,
                        Err(proto::WriteError::Blocked) => 0,
                        Err(error) => return Err(format!("stream_send: {error:?}")),
                    };
                    Ok(written)
                }

                fn stream_recv(
                    &mut self,
                    conn_id: u64,
                    stream_id: u64,
                    out: &mut [u8],
                    _now_us: u64,
                ) -> Result<(usize, bool), String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let sid = Self::stream_id(stream_id);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    if let Some(pending) = state.pending_rx.get_mut(&stream_id) {
                        if let Some(mut chunk) = pending.pop_front() {
                            let len = chunk.len().min(out.len());
                            out[..len].copy_from_slice(&chunk[..len]);
                            if len < chunk.len() {
                                let rest = chunk.split_off(len);
                                pending.push_front(rest);
                            }
                            if pending.is_empty() {
                                state.pending_rx.remove(&stream_id);
                            }
                            return Ok((len, false));
                        }
                    }
                    let result = match state.conn.recv_stream(sid).read(true) {
                        Ok(mut chunks) => match chunks.next(out.len()) {
                            Ok(Some(chunk)) => {
                                let len = chunk.bytes.len();
                                out[..len].copy_from_slice(&chunk.bytes);
                                let _ = chunks.finalize();
                                Ok((len, false))
                            }
                            Ok(None) => {
                                let _ = chunks.finalize();
                                let terminal = state.peer_terminal.entry(stream_id).or_default();
                                terminal.available = true;
                                terminal.fin = true;
                                Ok((0, true))
                            }
                            Err(proto::ReadError::Blocked) => {
                                let _ = chunks.finalize();
                                Ok((0, false))
                            }
                            Err(proto::ReadError::Reset(error)) => {
                                let _ = chunks.finalize();
                                let terminal = state.peer_terminal.entry(stream_id).or_default();
                                terminal.available = true;
                                terminal.reset_stream = true;
                                terminal.reset_stream_error = error.into_inner();
                                Ok((0, false))
                            }
                        },
                        Err(proto::ReadableError::ClosedStream) => Ok((
                            0,
                            state
                                .peer_terminal
                                .get(&stream_id)
                                .is_some_and(|terminal| terminal.fin),
                        )),
                        Err(error) => Err(format!("stream_recv: {error:?}")),
                    }?;
                    Ok(result)
                }

                fn stream_finish(
                    &mut self,
                    conn_id: u64,
                    stream_id: u64,
                    _now_us: u64,
                ) -> Result<(), String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let sid = Self::stream_id(stream_id);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    match state.conn.send_stream(sid).finish() {
                        Ok(()) | Err(proto::FinishError::Stopped(_)) => {}
                        Err(error) => return Err(format!("stream_finish: {error:?}")),
                    }
                    Ok(())
                }

                fn stream_reset(
                    &mut self,
                    conn_id: u64,
                    stream_id: u64,
                    application_error: u64,
                    _now_us: u64,
                ) -> Result<(), String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let sid = Self::stream_id(stream_id);
                    let error = proto::VarInt::from_u64(application_error)
                        .map_err(|e| format!("stream reset application error: {e:?}"))?;
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    let _ = state.conn.send_stream(sid).reset(error);
                    Ok(())
                }

                fn stream_stop_sending(
                    &mut self,
                    conn_id: u64,
                    stream_id: u64,
                    application_error: u64,
                    _now_us: u64,
                ) -> Result<(), String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let sid = Self::stream_id(stream_id);
                    let error = proto::VarInt::from_u64(application_error)
                        .map_err(|e| format!("stream stop application error: {e:?}"))?;
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    let _ = state.conn.recv_stream(sid).stop(error);
                    Ok(())
                }

                fn connection_close(
                    &mut self,
                    conn_id: u64,
                    application_error: u64,
                    now_us: u64,
                ) -> Result<(), String> {
                    let now = self.now(now_us)?;
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let error = proto::VarInt::from_u64(application_error)
                        .map_err(|e| format!("connection close application error: {e:?}"))?;
                    self.connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?
                        .conn
                        .close(now, error, Bytes::new());
                    self.drive(now_us)
                }

                fn peer_terminal_facts(
                    &mut self,
                    conn_id: u64,
                    stream_id: u64,
                    now_us: u64,
                ) -> Result<QpfPeerTerminalFactsV6, String> {
                    self.drive(now_us)?;
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    let terminal_known = state
                        .peer_terminal
                        .get(&stream_id)
                        .is_some_and(|facts| facts.fin || facts.reset_stream);
                    if !terminal_known {
                        enum Probe {
                            Data(Bytes),
                            Fin,
                            Reset(u64),
                            Pending,
                        }
                        let sid = Self::stream_id(stream_id);
                        let probe = match state.conn.recv_stream(sid).read(true) {
                            Ok(mut chunks) => match chunks.next(usize::MAX) {
                                Ok(Some(chunk)) => {
                                    let bytes = chunk.bytes;
                                    let _ = chunks.finalize();
                                    Probe::Data(bytes)
                                }
                                Ok(None) => {
                                    let _ = chunks.finalize();
                                    Probe::Fin
                                }
                                Err(proto::ReadError::Reset(error)) => {
                                    let _ = chunks.finalize();
                                    Probe::Reset(error.into_inner())
                                }
                                Err(proto::ReadError::Blocked) => {
                                    let _ = chunks.finalize();
                                    Probe::Pending
                                }
                            },
                            Err(proto::ReadableError::ClosedStream) => Probe::Pending,
                            Err(error) => {
                                return Err(format!("peer terminal receive probe: {error:?}"));
                            }
                        };
                        match probe {
                            Probe::Data(bytes) => state
                                .pending_rx
                                .entry(stream_id)
                                .or_default()
                                .push_back(bytes),
                            Probe::Fin => {
                                let terminal = state.peer_terminal.entry(stream_id).or_default();
                                terminal.available = true;
                                terminal.fin = true;
                            }
                            Probe::Reset(error) => {
                                let terminal = state.peer_terminal.entry(stream_id).or_default();
                                terminal.available = true;
                                terminal.reset_stream = true;
                                terminal.reset_stream_error = error;
                            }
                            Probe::Pending => {}
                        }
                    }
                    let mut facts = state
                        .peer_terminal
                        .get(&stream_id)
                        .copied()
                        .unwrap_or_default();
                    facts.available = true;
                    if let Some((error, reason_length)) = state.peer_connection_close {
                        facts.connection_close = true;
                        facts.connection_close_error = error;
                        facts.connection_close_reason_length = reason_length;
                    }
                    Ok(facts)
                }

                fn datagram_send(
                    &mut self,
                    conn_id: u64,
                    data: &[u8],
                    _now_us: u64,
                ) -> Result<bool, String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    let sent = match state
                        .conn
                        .datagrams()
                        .send(Bytes::copy_from_slice(data), false)
                    {
                        Ok(()) => true,
                        Err(proto::SendDatagramError::Blocked(_)) => false,
                        Err(error) => return Err(format!("datagram_send: {error:?}")),
                    };
                    Ok(sent)
                }

                fn datagram_recv(
                    &mut self,
                    conn_id: u64,
                    out: &mut [u8],
                    _now_us: u64,
                ) -> Result<Option<usize>, String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    let Some(datagram) = state.conn.datagrams().recv() else {
                        return Ok(None);
                    };
                    if datagram.len() > out.len() {
                        return Err(format!(
                            "datagram_recv buffer too small: {} > {}",
                            datagram.len(),
                            out.len()
                        ));
                    }
                    let len = datagram.len();
                    out[..len].copy_from_slice(&datagram);
                    Ok(Some(len))
                }

                fn transport_counters(&mut self) -> QpfTransportCountersV3 {
                    let mut result = self.retired_transport_counters;
                    for state in self.connections.values_mut() {
                        let counters = ($transport_counters)(&mut state.conn);
                        Self::add_transport_counters(&mut result, counters);
                    }
                    result
                }

                fn negotiated_settings(&mut self) -> Result<QpfNegotiatedSettingsV7, String> {
                    let mut aggregate: Option<QpfNegotiatedSettingsV7> = None;
                    for state in self.connections.values() {
                        let settings = self.connection_negotiated_settings(state)?;
                        if aggregate.is_some_and(|value| value != settings) {
                            return Err("connections negotiated different treatments".into());
                        }
                        aggregate = Some(settings);
                    }
                    aggregate.ok_or_else(|| "no connections are available for treatment audit".into())
                }
            }
        }
    };
}

proto_engine!(
    quinn_engine,
    QuinnEngine,
    quinn_proto,
    |initial_window| {
        let mut config = quinn_proto::congestion::BbrConfig::default();
        config.initial_window(initial_window);
        Arc::new(config)
    },
    MAX_DATAGRAMS,
    |endpoint: &mut quinn_proto::Endpoint,
     now,
     local: SocketAddr,
     remote,
     data,
     buf: &mut Vec<u8>| endpoint.handle(now, remote, Some(local.ip()), None, data, buf),
    |conn: &mut quinn_proto::Connection| {
        let stats = conn.stats();
        let (flow_control_blocked_events, stream_credit_blocked_events) =
            conn.quicperf_flow_control_blocked_events();
        QpfTransportCountersV3 {
            packets_lost: stats.path.lost_packets,
            packets_retransmitted: 0,
            recovery_wakeups: stats.recovery_wakeups,
            flow_control_blocked_events,
            stream_credit_blocked_events,
        }
    }
);

proto_engine!(
    noq_engine,
    NoqEngine,
    noq_proto,
    |initial_window| {
        let mut config = noq_proto::congestion::Bbr3Config::default();
        config.initial_window(initial_window);
        Arc::new(config)
    },
    std::num::NonZeroUsize::new(MAX_DATAGRAMS).unwrap(),
    |endpoint: &mut noq_proto::Endpoint,
     now,
     local: SocketAddr,
     remote,
     data,
     buf: &mut Vec<u8>| endpoint.handle(
        now,
        noq_proto::FourTuple::new(remote, Some(local.ip())),
        None,
        data,
        buf
    ),
    |conn: &mut noq_proto::Connection| {
        let stats = conn.stats();
        QpfTransportCountersV3 {
            packets_lost: stats.lost_packets,
            packets_retransmitted: 0,
            recovery_wakeups: stats.recovery_wakeups,
            flow_control_blocked_events: stats.frame_tx.data_blocked,
            stream_credit_blocked_events: stats.frame_tx.stream_data_blocked,
        }
    }
);

mod neqo_engine {
    use super::*;
    use neqo_common::{event::Provider as _, Datagram, Tos};
    use neqo_transport::{
        server::Server, CloseReason, CongestionControl, Connection, ConnectionEvent,
        ConnectionParameters, Error, Output, RandomConnectionIdGenerator, State, StreamId,
        StreamType, Version, ZeroRttState,
    };
    use nss::{
        AllowZeroRtt, AuthenticationStatus, SecretAgentInfo, TLS_AES_128_GCM_SHA256,
        TLS_GRP_EC_X25519, TLS_VERSION_1_3,
    };
    use rustls::{client::WebPkiServerVerifier, RootCertStore};
    use std::{cell::RefCell, rc::Rc};

    const ANTI_REPLAY_HASHES: usize = 16;
    const ANTI_REPLAY_BITS: usize = 20;

    fn verify_peer_identity(
        conn: &Connection,
        verifier: &WebPkiServerVerifier,
        expected_leaf: &[u8],
        hostname: &str,
        calendar_unix_seconds: u64,
    ) -> Result<(), String> {
        let peer = conn
            .peer_certificate()
            .ok_or_else(|| "Neqo peer supplied no certificate chain".to_string())?;
        let chain = peer.iter().map(<[u8]>::to_vec).collect::<Vec<_>>();
        let leaf = chain
            .first()
            .ok_or_else(|| "Neqo peer certificate chain is empty".to_string())?;
        if leaf.as_slice() != expected_leaf {
            return Err("Neqo peer leaf does not match the configured PEM certificate".into());
        }
        let end_entity = CertificateDer::from(leaf.clone());
        let intermediates = chain
            .iter()
            .skip(1)
            .cloned()
            .map(CertificateDer::from)
            .collect::<Vec<_>>();
        let server_name = ServerName::try_from(hostname.to_owned())
            .map_err(|e| format!("invalid Neqo TLS hostname: {e}"))?;
        verifier
            .verify_server_cert(
                &end_entity,
                &intermediates,
                &server_name,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(calendar_unix_seconds)),
            )
            .map_err(|e| format!("Neqo frozen-time CA/hostname verification failed: {e}"))?;
        Ok(())
    }

    fn validate_tls_treatment(info: &SecretAgentInfo) -> Result<(), String> {
        if info.version() != TLS_VERSION_1_3 {
            return Err(format!(
                "Neqo negotiated unexpected TLS version: {:?}",
                info.version()
            ));
        }
        if info.cipher_suite() != TLS_AES_128_GCM_SHA256 {
            return Err(format!(
                "Neqo negotiated unexpected TLS cipher: {:?}",
                info.cipher_suite()
            ));
        }
        if info.key_exchange() != TLS_GRP_EC_X25519 {
            return Err(format!(
                "Neqo negotiated unexpected TLS key exchange: {:?}",
                info.key_exchange()
            ));
        }
        if info.alpn() != Some("qperf/2") {
            return Err(format!(
                "Neqo negotiated unexpected ALPN: {:?}",
                info.alpn()
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod identity_tests {
        use super::*;

        #[test]
        fn configured_ed25519_identity_builds_an_nss_server() {
            let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
            nss::init().unwrap();
            let certificate = load_certs(root.join("tls/server.cert.pem").to_str().unwrap())
                .unwrap()
                .remove(0);
            let key = load_key(root.join("tls/server.key.pem").to_str().unwrap()).unwrap();
            nss::Server::new_with_identity_der(certificate.as_ref(), key.secret_der()).unwrap();
        }
    }

    struct ClientConn {
        conn: Connection,
        connected: bool,
        retire_when_closed: bool,
        known_streams: HashSet<u64>,
        accepted_bidi_streams: VecDeque<u64>,
        accepted_uni_streams: VecDeque<u64>,
        datagrams: VecDeque<Vec<u8>>,
        resumption_token: Option<Vec<u8>>,
        early_data_limit: u64,
        early_data_sent: u64,
        peer_terminal: HashMap<u64, QpfPeerTerminalFactsV6>,
        connection_terminal: QpfPeerTerminalFactsV6,
    }

    struct ServerConn {
        conn: Rc<RefCell<Connection>>,
        connected: bool,
        retire_when_closed: bool,
        ticket_sent: bool,
        known_streams: HashSet<u64>,
        accepted_bidi_streams: VecDeque<u64>,
        accepted_uni_streams: VecDeque<u64>,
        datagrams: VecDeque<Vec<u8>>,
        peer_terminal: HashMap<u64, QpfPeerTerminalFactsV6>,
        connection_terminal: QpfPeerTerminalFactsV6,
    }

    struct Outbound {
        destination: SocketAddr,
        bytes: Vec<u8>,
    }

    pub struct NeqoEngine {
        is_server: bool,
        local_addr: SocketAddr,
        params: ConnectionParameters,
        server: Option<Server>,
        clients: BTreeMap<u64, ClientConn>,
        retired_clients: Vec<Connection>,
        server_conns: HashMap<u64, ServerConn>,
        server_ptr_to_id: HashMap<usize, u64>,
        accepted_connections: VecDeque<u64>,
        outbound: VecDeque<Outbound>,
        pending_resumption_handle: Option<u64>,
        pending_zero_rtt: bool,
        engine_id: u64,
        next_conn_id: u64,
        callback: Option<Duration>,
        base_us: u64,
        base_instant: Instant,
        tls_verify_peer: bool,
        tls_hostname: String,
        calendar_unix_seconds: u64,
        peer_verifier: Arc<WebPkiServerVerifier>,
        expected_leaf: Vec<u8>,
        connection_id_bytes: usize,
        local_settings: QpfNegotiatedSettingsV7,
        retired_counters: QpfTransportCountersV3,
        retirement_pending: bool,
        fatal_error: Option<String>,
    }

    impl NeqoEngine {
        pub fn new(config: &QpfConfig) -> Result<Self, String> {
            let cert_path = unsafe { cstr(config.cert_path)? };
            let key_path = unsafe { cstr(config.key_path)? };
            let chain_path = unsafe { cstr(config.chain_path)? };
            let tls_hostname = unsafe { cstr(config.tls_hostname)? };
            nss::init().map_err(|e| format!("initialize Neqo NSS: {e:?}"))?;
            let calendar_us = config
                .calendar_unix_seconds
                .checked_mul(1_000_000)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| "Neqo frozen calendar exceeds NSS PRTime".to_string())?;
            let now: Instant = nss::time::Time::try_from(calendar_us)
                .map_err(|e| format!("anchor Neqo NSS frozen calendar: {e:?}"))?
                .into();
            let mut configured_leaf = load_certs(&cert_path)?;
            if configured_leaf.len() != 1 {
                return Err(format!(
                    "Neqo requires exactly one configured leaf certificate, got {}",
                    configured_leaf.len()
                ));
            }
            let expected_leaf = configured_leaf.remove(0).as_ref().to_vec();
            let roots = load_certs(&chain_path)?;
            if roots.is_empty() {
                return Err("Neqo configured CA bundle is empty".into());
            }
            let mut root_store = RootCertStore::empty();
            for root in roots {
                root_store
                    .add(root)
                    .map_err(|e| format!("add Neqo configured CA: {e}"))?;
            }
            let peer_verifier = WebPkiServerVerifier::builder_with_provider(
                Arc::new(root_store),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .map_err(|e| format!("build Neqo peer verifier: {e}"))?;
            let connection_id_bytes = usize::try_from(config.connection_id_bytes)
                .map_err(|_| "Neqo connection ID length exceeds usize".to_string())?;
            if connection_id_bytes == 0 {
                return Err("Neqo connection ID length must be nonzero".into());
            }
            if config.use_bbr {
                return Err("Neqo does not implement the frozen BBR treatment".into());
            }
            if !config.one_use_tickets {
                return Err("Neqo requires the frozen one-use ticket policy".into());
            }
            let local_leaf_ed25519 =
                certificate_signature_is_ed25519(&CertificateDer::from(expected_leaf.clone()));
            if config.max_ack_delay_ns % 1_000_000 != 0 {
                return Err("Neqo maximum ACK delay must be a whole number of milliseconds".into());
            }
            let initial_congestion_window = usize::try_from(config.initial_congestion_window_bytes)
                .map_err(|_| "Neqo initial congestion window exceeds usize".to_string())?;
            let params = ConnectionParameters::default()
                .versions(Version::Version1, vec![Version::Version1])
                .congestion_control(CongestionControl::Cubic)
                .initial_congestion_window(initial_congestion_window)
                .max_udp_payload_size(u64::from(config.udp_payload_size))
                .max_ack_delay(Duration::from_nanos(config.max_ack_delay_ns))
                .ack_delay_exponent(config.ack_delay_exponent)
                .ack_frequency(config.ack_frequency)
                .disable_migration(!config.active_migration)
                .active_connection_id_limit(config.active_connection_id_limit)
                .max_data(config.connection_window)
                .max_stream_data(StreamType::BiDi, false, config.stream_window)
                .max_stream_data(StreamType::BiDi, true, config.stream_window)
                .max_stream_data(StreamType::UniDi, true, config.stream_window)
                .max_streams(StreamType::BiDi, config.max_bidi_streams)
                .max_streams(StreamType::UniDi, config.max_uni_streams)
                .idle_timeout(Duration::from_millis(config.idle_timeout_ms))
                .datagram_size(config.datagram_max_frame_size)
                .incoming_datagram_queue(1024)
                .outgoing_datagram_queue(1024)
                .mlkem(false)
                .grease(false)
                .disable_preferred_address()
                .sni_slicing(false)
                .pacing(true)
                .pmtud(false)
                .pmtud_iface_mtu(false);
            let server = if config.is_server {
                let anti_replay_window = Duration::from_secs(10);
                let anti_replay_now = now.checked_sub(anti_replay_window).unwrap_or(now);
                let key = load_key(&key_path)?;
                let mut server = Server::new_with_identity_der(
                    now,
                    &expected_leaf,
                    key.secret_der(),
                    ALPN_STR,
                    nss::AntiReplay::new(
                        anti_replay_now,
                        anti_replay_window,
                        ANTI_REPLAY_HASHES,
                        ANTI_REPLAY_BITS,
                    )
                    .map_err(|e| format!("neqo anti replay config: {e:?}"))?,
                    Box::new(AllowZeroRtt {}),
                    Rc::new(RefCell::new(RandomConnectionIdGenerator::new(
                        connection_id_bytes,
                    ))),
                    params.clone(),
                )
                .map_err(|e| format!("neqo server config: {e:?}"))?;
                server.set_ciphers([TLS_AES_128_GCM_SHA256]);
                Some(server)
            } else {
                None
            };
            Ok(Self {
                is_server: config.is_server,
                local_addr: socket_from_qpf(&config.local_addr),
                params,
                server,
                clients: BTreeMap::new(),
                retired_clients: Vec::new(),
                server_conns: HashMap::new(),
                server_ptr_to_id: HashMap::new(),
                accepted_connections: VecDeque::new(),
                outbound: VecDeque::new(),
                pending_resumption_handle: None,
                pending_zero_rtt: false,
                engine_id: NEXT_RUST_ENGINE_ID.fetch_add(1, Ordering::Relaxed),
                next_conn_id: 1,
                callback: None,
                base_us: config.now_us,
                base_instant: now,
                tls_verify_peer: config.tls_verify_peer,
                tls_hostname,
                calendar_unix_seconds: config.calendar_unix_seconds,
                peer_verifier,
                expected_leaf,
                connection_id_bytes,
                local_settings: QpfNegotiatedSettingsV7 {
                    tls_leaf_ed25519: u8::from(local_leaf_ed25519),
                    use_bbr: 0,
                    ack_frequency: u8::from(config.ack_frequency),
                    active_migration: u8::from(config.active_migration),
                    one_use_tickets: u8::from(config.one_use_tickets),
                    initial_congestion_window_bytes: config.initial_congestion_window_bytes,
                    stream_credit_replenish_below: config.stream_credit_replenish_below,
                    ticket_lifetime_ns: config.ticket_lifetime_ns,
                    maximum_early_data_bytes: config.maximum_early_data_bytes,
                    ..QpfNegotiatedSettingsV7::default()
                },
                retired_counters: QpfTransportCountersV3::default(),
                retirement_pending: false,
                fatal_error: None,
            })
        }

        fn add_counters(result: &mut QpfTransportCountersV3, stats: &neqo_transport::Stats) {
            result.packets_lost = result.packets_lost.saturating_add(stats.lost as u64);
            result.recovery_wakeups = result
                .recovery_wakeups
                .saturating_add(stats.recovery_wakeups as u64);
            result.flow_control_blocked_events = result
                .flow_control_blocked_events
                .saturating_add(stats.frame_tx.data_blocked as u64);
            result.stream_credit_blocked_events = result
                .stream_credit_blocked_events
                .saturating_add(stats.frame_tx.stream_data_blocked as u64);
        }

        fn reap_retired_connections(&mut self) {
            if !self.retirement_pending {
                return;
            }
            let closed_client = self
                .clients
                .values()
                .any(|state| state.retire_when_closed && state.conn.state().closed());
            let closed_server = self
                .server_conns
                .values()
                .any(|state| state.retire_when_closed && state.conn.borrow().state().closed());
            if !closed_client && !closed_server {
                return;
            }

            let client_ids: Vec<_> = self
                .clients
                .iter()
                .filter_map(|(id, state)| {
                    (state.retire_when_closed && state.conn.state().closed()).then_some(*id)
                })
                .collect();
            for id in client_ids {
                let state = self.clients.remove(&id).unwrap();
                Self::add_counters(&mut self.retired_counters, &state.conn.stats());
                self.retired_clients.push(state.conn);
            }

            let active_server_pointers: HashSet<_> = if closed_server {
                self.server
                    .as_ref()
                    .map(|server| {
                        server
                            .active_connections()
                            .into_iter()
                            .map(|connection| Rc::as_ptr(&connection.connection()) as usize)
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };
            let server_ids: Vec<_> = self
                .server_conns
                .iter()
                .filter_map(|(id, state)| {
                    let pointer = Rc::as_ptr(&state.conn) as usize;
                    (state.retire_when_closed
                        && state.conn.borrow().state().closed()
                        && !active_server_pointers.contains(&pointer))
                    .then_some(*id)
                })
                .collect();
            for id in server_ids {
                let state = self.server_conns.remove(&id).unwrap();
                let pointer = Rc::as_ptr(&state.conn) as usize;
                self.server_ptr_to_id.remove(&pointer);
                Self::add_counters(&mut self.retired_counters, &state.conn.borrow().stats());
                self.accepted_connections.retain(|accepted| *accepted != id);
            }
            self.retirement_pending = self.clients.values().any(|state| state.retire_when_closed)
                || self
                    .server_conns
                    .values()
                    .any(|state| state.retire_when_closed);
        }

        fn queue_output(&mut self, output: Output) {
            match output {
                Output::Datagram(datagram) => self.outbound.push_back(Outbound {
                    destination: datagram.destination(),
                    bytes: datagram.to_vec(),
                }),
                Output::Callback(delay) => {
                    self.callback = Some(self.callback.map_or(delay, |current| current.min(delay)));
                }
                Output::None => {}
            }
        }

        fn now(&self, now_us: u64) -> Instant {
            self.base_instant + Duration::from_micros(now_us.saturating_sub(self.base_us))
        }

        fn drive_output(&mut self, now: Instant) {
            self.callback = None;
            if self.is_server {
                let output = self.server.as_mut().unwrap().process_output(now);
                self.queue_output(output);
                self.drain_server_events(now);
            } else {
                let ids: Vec<_> = self.clients.keys().copied().collect();
                for id in &ids {
                    let output = self.clients.get_mut(id).unwrap().conn.process_output(now);
                    self.queue_output(output);
                }
                for id in ids {
                    self.drain_client_events(id, now);
                }
            }
            self.reap_retired_connections();
        }

        fn drain_client_events(&mut self, conn_id: u64, now: Instant) {
            let tls_verify_peer = self.tls_verify_peer;
            let peer_verifier = Arc::clone(&self.peer_verifier);
            let expected_leaf = self.expected_leaf.clone();
            let tls_hostname = self.tls_hostname.clone();
            let calendar_unix_seconds = self.calendar_unix_seconds;
            let Some(state) = self.clients.get_mut(&conn_id) else {
                return;
            };
            let conn = &mut state.conn;
            let mut fatal_error = None;
            let events: Vec<_> = conn.events().collect();
            for event in events {
                match event {
                    ConnectionEvent::AuthenticationNeeded
                    | ConnectionEvent::EchFallbackAuthenticationNeeded { .. } => {
                        let verification = if tls_verify_peer {
                            verify_peer_identity(
                                conn,
                                &peer_verifier,
                                &expected_leaf,
                                &tls_hostname,
                                calendar_unix_seconds,
                            )
                        } else {
                            Ok(())
                        };
                        let status = match verification {
                            Ok(()) => AuthenticationStatus::Ok,
                            Err(error) => {
                                fatal_error = Some(error);
                                AuthenticationStatus::PolicyRejection
                            }
                        };
                        conn.authenticated(status, now);
                    }
                    ConnectionEvent::StateChange(event_state)
                        if event_state == State::Confirmed =>
                    {
                        match conn
                            .tls_info()
                            .ok_or_else(|| "Neqo connected without TLS info".to_string())
                            .and_then(validate_tls_treatment)
                        {
                            Ok(()) => state.connected = true,
                            Err(error) => fatal_error = Some(error),
                        }
                    }
                    ConnectionEvent::StateChange(State::Closed(error)) => {
                        if !state.connected {
                            fatal_error = Some(format!(
                                "neqo client handshake closed before connected: {error:?}"
                            ));
                        }
                        state.connected = false;
                    }
                    ConnectionEvent::NewStream { stream_id } if stream_id.is_bidi() => {
                        state.known_streams.insert(stream_id.as_u64());
                        state.accepted_bidi_streams.push_back(stream_id.as_u64());
                    }
                    ConnectionEvent::NewStream { stream_id } => {
                        state.known_streams.insert(stream_id.as_u64());
                        state.accepted_uni_streams.push_back(stream_id.as_u64());
                    }
                    ConnectionEvent::Datagram(data) => {
                        state.datagrams.push_back(data);
                    }
                    ConnectionEvent::ResumptionToken(token) => {
                        state.resumption_token = Some(token.as_ref().to_vec());
                    }
                    ConnectionEvent::RecvStreamReset {
                        stream_id,
                        app_error,
                    } => {
                        let terminal = state.peer_terminal.entry(stream_id.as_u64()).or_insert(
                            QpfPeerTerminalFactsV6 {
                                available: true,
                                ..Default::default()
                            },
                        );
                        terminal.reset_stream = true;
                        terminal.reset_stream_error = app_error;
                    }
                    ConnectionEvent::SendStreamStopSending {
                        stream_id,
                        app_error,
                    } => {
                        let terminal = state.peer_terminal.entry(stream_id.as_u64()).or_insert(
                            QpfPeerTerminalFactsV6 {
                                available: true,
                                ..Default::default()
                            },
                        );
                        terminal.stop_sending = true;
                        terminal.stop_sending_error = app_error;
                    }
                    ConnectionEvent::PeerApplicationClose {
                        app_error,
                        reason_len,
                    } => {
                        state.connection_terminal.connection_close = true;
                        state.connection_terminal.connection_close_error = app_error;
                        state.connection_terminal.connection_close_reason_length =
                            reason_len as u64;
                    }
                    _ => {}
                }
            }
            if fatal_error.is_some() {
                self.fatal_error = fatal_error;
            }
        }

        fn refresh_resumption_token(&mut self, conn_id: u64, now: Instant) -> Result<(), String> {
            let state = self
                .clients
                .get_mut(&conn_id)
                .ok_or_else(|| format!("unknown neqo client connection {conn_id}"))?;
            if state.resumption_token.is_none() {
                if let Some(token) = state.conn.take_resumption_token(now) {
                    state.resumption_token = Some(token.as_ref().to_vec());
                }
            }
            Ok(())
        }

        fn drain_server_events(&mut self, now: Instant) {
            let active = self.server.as_ref().unwrap().active_connections();
            for conn_ref in active {
                let rc = conn_ref.connection();
                let ptr = Rc::as_ptr(&rc) as usize;
                let id = if let Some(id) = self.server_ptr_to_id.get(&ptr).copied() {
                    id
                } else {
                    let id = self.next_conn_id;
                    self.next_conn_id += 1;
                    self.server_ptr_to_id.insert(ptr, id);
                    self.server_conns.insert(
                        id,
                        ServerConn {
                            conn: Rc::clone(&rc),
                            connected: false,
                            retire_when_closed: false,
                            ticket_sent: false,
                            known_streams: HashSet::new(),
                            accepted_bidi_streams: VecDeque::new(),
                            accepted_uni_streams: VecDeque::new(),
                            datagrams: VecDeque::new(),
                            peer_terminal: HashMap::new(),
                            connection_terminal: QpfPeerTerminalFactsV6 {
                                available: true,
                                ..Default::default()
                            },
                        },
                    );
                    self.accepted_connections.push_back(id);
                    id
                };
                {
                    let state = self.server_conns.get_mut(&id).unwrap();
                    let mut conn = rc.borrow_mut();
                    let events: Vec<_> = conn.events().collect();
                    for event in events {
                        match event {
                            ConnectionEvent::AuthenticationNeeded
                            | ConnectionEvent::EchFallbackAuthenticationNeeded { .. } => {
                                conn.authenticated(AuthenticationStatus::Ok, now);
                            }
                            ConnectionEvent::StateChange(next) if next == State::Confirmed => {
                                match conn
                                    .tls_info()
                                    .ok_or_else(|| {
                                        "Neqo server connected without TLS info".to_string()
                                    })
                                    .and_then(validate_tls_treatment)
                                {
                                    Ok(()) => state.connected = true,
                                    Err(error) => self.fatal_error = Some(error),
                                }
                                if !state.ticket_sent {
                                    match conn.send_ticket(now, &[]) {
                                        Ok(()) => state.ticket_sent = true,
                                        Err(error) => {
                                            self.fatal_error = Some(format!(
                                                "neqo server session ticket: {error:?}"
                                            ));
                                        }
                                    }
                                }
                            }
                            ConnectionEvent::StateChange(State::Closed(
                                CloseReason::Application(0)
                                | CloseReason::Transport(Error::None | Error::PeerApplication(0)),
                            )) => {}
                            ConnectionEvent::StateChange(State::Closed(error))
                                if !state.connected =>
                            {
                                self.fatal_error = Some(format!(
                                    "neqo server handshake closed before connected: {error:?}"
                                ));
                            }
                            ConnectionEvent::NewStream { stream_id } if stream_id.is_bidi() => {
                                state.known_streams.insert(stream_id.as_u64());
                                state.accepted_bidi_streams.push_back(stream_id.as_u64());
                            }
                            ConnectionEvent::NewStream { stream_id } => {
                                state.known_streams.insert(stream_id.as_u64());
                                state.accepted_uni_streams.push_back(stream_id.as_u64());
                            }
                            ConnectionEvent::Datagram(data) => {
                                state.datagrams.push_back(data);
                            }
                            ConnectionEvent::RecvStreamReset {
                                stream_id,
                                app_error,
                            } => {
                                let terminal = state
                                    .peer_terminal
                                    .entry(stream_id.as_u64())
                                    .or_insert(QpfPeerTerminalFactsV6 {
                                        available: true,
                                        ..Default::default()
                                    });
                                terminal.reset_stream = true;
                                terminal.reset_stream_error = app_error;
                            }
                            ConnectionEvent::SendStreamStopSending {
                                stream_id,
                                app_error,
                            } => {
                                let terminal = state
                                    .peer_terminal
                                    .entry(stream_id.as_u64())
                                    .or_insert(QpfPeerTerminalFactsV6 {
                                        available: true,
                                        ..Default::default()
                                    });
                                terminal.stop_sending = true;
                                terminal.stop_sending_error = app_error;
                            }
                            ConnectionEvent::PeerApplicationClose {
                                app_error,
                                reason_len,
                            } => {
                                state.connection_terminal.connection_close = true;
                                state.connection_terminal.connection_close_error = app_error;
                                state.connection_terminal.connection_close_reason_length =
                                    reason_len as u64;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        fn client(&self, conn_id: u64) -> Result<&ClientConn, String> {
            self.clients
                .get(&conn_id)
                .ok_or_else(|| format!("unknown neqo client connection {conn_id}"))
        }

        fn client_mut(&mut self, conn_id: u64) -> Result<&mut ClientConn, String> {
            self.clients
                .get_mut(&conn_id)
                .ok_or_else(|| format!("unknown neqo client connection {conn_id}"))
        }

        fn server_conn(&mut self, conn_id: u64) -> Result<Rc<RefCell<Connection>>, String> {
            self.server_conns
                .get(&conn_id)
                .map(|state| Rc::clone(&state.conn))
                .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))
        }

        fn check_fatal(&self) -> Result<(), String> {
            self.fatal_error.clone().map_or(Ok(()), Err)
        }

        fn stream_send_capacity(
            conn: &Connection,
            known_streams: &HashSet<u64>,
            stream_id: StreamId,
        ) -> Result<usize, String> {
            let outstanding = known_streams.iter().try_fold(0_u64, |total, id| {
                match conn.send_stream_stats(StreamId::new(*id)) {
                    Ok(stats) => Ok(total
                        .saturating_add(stats.bytes_written().saturating_sub(stats.bytes_acked()))),
                    Err(Error::InvalidStreamId) => Ok(total),
                    Err(error) => Err(format!("neqo send_stream_stats: {error:?} stream={id}")),
                }
            })?;
            let aggregate_capacity =
                usize::try_from(APPLICATION_BUFFER_BYTES.saturating_sub(outstanding))
                    .unwrap_or(usize::MAX);
            let stream_capacity = match conn.stream_avail_send_space(stream_id) {
                Ok(capacity) => capacity,
                Err(Error::NotAvailable) => 0,
                Err(error) => {
                    return Err(format!(
                        "neqo stream_avail_send_space: {error:?} stream={stream_id}"
                    ));
                }
            };
            Ok(aggregate_capacity.min(stream_capacity))
        }

        fn connection_negotiated_settings(
            &self,
            conn: &Connection,
            connected: bool,
        ) -> Result<QpfNegotiatedSettingsV7, String> {
            if !connected {
                return Err("Neqo connection has no completed handshake".into());
            }
            let tls = conn
                .tls_info()
                .ok_or_else(|| "Neqo TLS handshake evidence is unavailable".to_string())?;
            validate_tls_treatment(tls)?;
            let transport = conn
                .quicperf_negotiated_transport()
                .ok_or_else(|| "Neqo peer transport parameters are unavailable".to_string())?;
            if transport.initial_max_stream_data_bidi_local
                != transport.initial_max_stream_data_bidi_remote
                || transport.initial_max_stream_data_bidi_local
                    != transport.initial_max_stream_data_uni
            {
                return Err("Neqo peer stream windows differ".into());
            }
            let peer_certificates = conn
                .peer_certificate()
                .map(|chain| chain.iter().map(<[u8]>::to_vec).collect::<Vec<_>>());
            let peer_certificate_present = peer_certificates
                .as_ref()
                .is_some_and(|chain| !chain.is_empty());
            let leaf_ed25519 = peer_certificates
                .as_ref()
                .and_then(|chain| chain.first())
                .map_or(self.local_settings.tls_leaf_ed25519 != 0, |leaf| {
                    certificate_signature_is_ed25519(&CertificateDer::from(leaf.clone()))
                });
            let max_ack_delay_ns = transport
                .max_ack_delay_ms
                .checked_mul(1_000_000)
                .ok_or_else(|| "Neqo peer ACK delay overflows nanoseconds".to_string())?;
            let max_idle_timeout_ns = transport
                .max_idle_timeout_ms
                .checked_mul(1_000_000)
                .ok_or_else(|| "Neqo peer idle timeout overflows nanoseconds".to_string())?;
            let mut settings = self.local_settings;
            settings.available = 1;
            settings.alpn_qperf_2 = u8::from(tls.alpn() == Some("qperf/2"));
            settings.peer_certificate_present = u8::from(peer_certificate_present);
            settings.peer_certificate_verified =
                u8::from(self.tls_verify_peer && peer_certificate_present);
            settings.hostname_verified = settings.peer_certificate_verified;
            settings.tls_leaf_ed25519 = u8::from(leaf_ed25519);
            settings.quic_version = transport.quic_version;
            settings.tls_version = 0x0304;
            settings.tls_cipher_suite = 0x1301;
            settings.tls_key_exchange_group = 0x001d;
            settings.tls_leaf_signature_algorithm = if leaf_ed25519 { 0x0807 } else { 0 };
            settings.initial_congestion_window_bytes = transport.initial_congestion_window_bytes;
            settings.max_udp_payload_size = transport.max_udp_payload_size;
            settings.max_ack_delay_ns = max_ack_delay_ns;
            settings.ack_delay_exponent = transport.ack_delay_exponent;
            settings.ack_frequency = u8::from(transport.ack_frequency);
            settings.active_migration = u8::from(transport.active_migration);
            settings.active_connection_id_limit = transport.active_connection_id_limit;
            settings.connection_id_bytes = u64::try_from(transport.connection_id_bytes)
                .map_err(|_| "Neqo peer connection ID length does not fit u64".to_string())?;
            settings.max_idle_timeout_ns = max_idle_timeout_ns;
            settings.max_bidi_streams = transport.max_bidi_streams;
            settings.max_uni_streams = transport.max_uni_streams;
            settings.connection_window_bytes = transport.initial_max_data;
            settings.stream_window_bytes = transport.initial_max_stream_data_bidi_local;
            settings.datagram_max_frame_size = transport.max_datagram_frame_size;
            Ok(settings)
        }
    }

    impl Drop for NeqoEngine {
        fn drop(&mut self) {
            if let Some(handle_id) = self.pending_resumption_handle.take() {
                release_resumption_handle(self.engine_id, handle_id);
            }
        }
    }

    impl PacketEngine for NeqoEngine {
        fn connect(&mut self, remote: SocketAddr, now_us: u64) -> Result<u64, String> {
            if self.is_server {
                return Err("neqo connect called on server".into());
            }
            let now = self.now(now_us);
            let mut conn = Connection::new_client(
                self.tls_hostname.clone(),
                ALPN_STR,
                Rc::new(RefCell::new(RandomConnectionIdGenerator::new(
                    self.connection_id_bytes,
                ))),
                self.local_addr,
                remote,
                self.params.clone(),
                now,
            )
            .map_err(|e| format!("neqo client: {e:?}"))?;
            conn.set_ciphers(&[TLS_AES_128_GCM_SHA256])
                .map_err(|e| format!("neqo client cipher policy: {e:?}"))?;
            conn.set_groups(&[TLS_GRP_EC_X25519])
                .map_err(|e| format!("neqo client key-exchange policy: {e:?}"))?;
            let early_data_limit = if self.pending_zero_rtt {
                self.local_settings.maximum_early_data_bytes
            } else {
                0
            };
            if let Some(handle_id) = self.pending_resumption_handle {
                let token = reserved_opaque_resumption_state(self.engine_id, handle_id)?;
                if let Err(error) = conn.enable_resumption(now, &token) {
                    self.pending_resumption_handle = None;
                    self.pending_zero_rtt = false;
                    release_resumption_handle(self.engine_id, handle_id);
                    return Err(format!("neqo enable resumption: {error:?}"));
                }
                consume_resumption_handle(self.engine_id, handle_id)?;
                self.pending_resumption_handle = None;
            }
            self.pending_zero_rtt = false;
            let id = self.next_conn_id;
            self.next_conn_id += 1;
            self.clients.insert(
                id,
                ClientConn {
                    conn,
                    connected: false,
                    retire_when_closed: false,
                    known_streams: HashSet::new(),
                    accepted_bidi_streams: VecDeque::new(),
                    accepted_uni_streams: VecDeque::new(),
                    datagrams: VecDeque::new(),
                    resumption_token: None,
                    early_data_limit,
                    early_data_sent: 0,
                    peer_terminal: HashMap::new(),
                    connection_terminal: QpfPeerTerminalFactsV6 {
                        available: true,
                        ..Default::default()
                    },
                },
            );
            self.drive_output(now);
            self.check_fatal()?;
            Ok(id)
        }

        fn accept_connection(&mut self) -> Option<u64> {
            self.accepted_connections.pop_front()
        }

        fn is_connected(&mut self, conn_id: u64, _now_us: u64) -> Result<bool, String> {
            self.check_fatal()?;
            if self.is_server {
                Ok(self
                    .server_conns
                    .get(&conn_id)
                    .is_some_and(|state| state.connected))
            } else {
                Ok(self.client(conn_id)?.connected)
            }
        }

        fn connection_is_closed(&mut self, conn_id: u64, _now_us: u64) -> Result<bool, String> {
            self.check_fatal()?;
            if self.is_server {
                let state = self
                    .server_conns
                    .get(&conn_id)
                    .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))?;
                Ok(state.conn.borrow().state().closed())
            } else {
                Ok(self.client(conn_id)?.conn.state().closed())
            }
        }

        fn retire_connection(&mut self, conn_id: u64, _now_us: u64) -> Result<(), String> {
            self.check_fatal()?;
            if self.is_server {
                self.server_conns
                    .get_mut(&conn_id)
                    .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))?
                    .retire_when_closed = true;
            } else {
                self.client_mut(conn_id)?.retire_when_closed = true;
            }
            self.retirement_pending = true;
            self.reap_retired_connections();
            Ok(())
        }

        fn receive(&mut self, remote: SocketAddr, data: &[u8], now_us: u64) -> Result<(), String> {
            let now = self.now(now_us);
            if self.is_server {
                let datagram =
                    Datagram::new(remote, self.local_addr, Tos::default(), data.to_vec());
                let output = self.server.as_mut().unwrap().process([datagram], now);
                self.queue_output(output);
                self.drain_server_events(now);
            } else {
                let mut bytes = data.to_vec();
                let conn_id = self
                    .clients
                    .iter()
                    .find_map(|(id, state)| state.conn.accepts_input(&mut bytes).then_some(*id));
                let Some(conn_id) = conn_id else {
                    if self
                        .retired_clients
                        .iter()
                        .any(|conn| conn.accepts_input(&mut bytes))
                    {
                        return Ok(());
                    }
                    return Err("neqo input has no matching client connection ID".to_string());
                };
                let datagram = Datagram::new(remote, self.local_addr, Tos::default(), bytes);
                self.client_mut(conn_id)?.conn.process_input(datagram, now);
                self.drain_client_events(conn_id, now);
            }
            self.reap_retired_connections();
            self.check_fatal()?;
            Ok(())
        }

        fn poll_transmit(
            &mut self,
            now_us: u64,
            out: &mut [u8],
        ) -> Result<Option<(SocketAddr, usize)>, String> {
            self.check_fatal()?;
            if self.outbound.is_empty() {
                self.drive_output(self.now(now_us));
            }
            if let Some(next) = self.outbound.pop_front() {
                if next.bytes.len() > out.len() {
                    return Err("neqo transmit buffer too small".into());
                }
                out[..next.bytes.len()].copy_from_slice(&next.bytes);
                Ok(Some((next.destination, next.bytes.len())))
            } else {
                self.check_fatal()?;
                Ok(None)
            }
        }

        fn next_timeout_us(&mut self, _now_us: u64) -> Result<Option<u64>, String> {
            Ok(self
                .callback
                .map(|delay| delay.as_micros().min(u64::MAX as u128) as u64))
        }

        fn on_timeout(&mut self, now_us: u64) -> Result<(), String> {
            self.drive_output(self.now(now_us));
            self.check_fatal()?;
            Ok(())
        }

        fn export_resumption_state(
            &mut self,
            conn_id: u64,
            now_us: u64,
            out: &mut Vec<u8>,
        ) -> Result<bool, String> {
            let now = self.now(now_us);
            self.refresh_resumption_token(conn_id, now)?;
            let Some(token) = self.client_mut(conn_id)?.resumption_token.take() else {
                return Ok(false);
            };
            export_opaque_resumption_handle(
                self.tls_verify_peer,
                &self.tls_hostname,
                now_us,
                self.local_settings.maximum_early_data_bytes > 0,
                token,
                out,
            );
            Ok(true)
        }

        fn import_resumption_state(
            &mut self,
            data: &[u8],
            use_zero_rtt: bool,
            now_us: u64,
        ) -> Result<bool, String> {
            if self.pending_resumption_handle.is_some() {
                return Err("Neqo engine already has a reserved resumption handle".into());
            }
            let Some(handle_id) = reserve_resumption_handle(
                self.engine_id,
                self.tls_verify_peer,
                &self.tls_hostname,
                data,
                use_zero_rtt,
                now_us,
                self.local_settings.ticket_lifetime_ns,
                true,
            )?
            else {
                return Ok(false);
            };
            self.pending_resumption_handle = Some(handle_id);
            self.pending_zero_rtt = use_zero_rtt;
            Ok(true)
        }

        fn connection_resumed(&mut self, conn_id: u64, _now_us: u64) -> Result<bool, String> {
            Ok(self
                .client(conn_id)?
                .conn
                .tls_info()
                .is_some_and(|info| info.resumed()))
        }

        fn zero_rtt_attempted(&mut self, conn_id: u64, _now_us: u64) -> Result<bool, String> {
            Ok(matches!(
                self.client(conn_id)?.conn.zero_rtt_state(),
                ZeroRttState::Sending
                    | ZeroRttState::AcceptedClient
                    | ZeroRttState::AcceptedServer
                    | ZeroRttState::Rejected
            ))
        }

        fn zero_rtt_accepted(&mut self, conn_id: u64, _now_us: u64) -> Result<bool, String> {
            Ok(self.client(conn_id)?.conn.zero_rtt_state() == ZeroRttState::AcceptedClient)
        }

        fn zero_rtt_rejected(&mut self, conn_id: u64, _now_us: u64) -> Result<bool, String> {
            Ok(self.client(conn_id)?.conn.zero_rtt_state() == ZeroRttState::Rejected)
        }

        fn open_bidi(&mut self, conn_id: u64, _now_us: u64) -> Result<Option<u64>, String> {
            let created = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .stream_create(StreamType::BiDi)
            } else {
                self.client_mut(conn_id)?
                    .conn
                    .stream_create(StreamType::BiDi)
            };
            let stream = match created {
                Ok(stream) => stream,
                Err(Error::StreamLimit | Error::ConnectionState) => return Ok(None),
                Err(error) => return Err(format!("neqo open stream: {error:?}")),
            };
            if self.is_server {
                self.server_conns
                    .get_mut(&conn_id)
                    .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))?
                    .known_streams
                    .insert(stream.as_u64());
            } else {
                self.client_mut(conn_id)?
                    .known_streams
                    .insert(stream.as_u64());
            }
            Ok(Some(stream.as_u64()))
        }

        fn accept_bidi(&mut self, conn_id: u64, _now_us: u64) -> Result<Option<u64>, String> {
            if self.is_server {
                Ok(self
                    .server_conns
                    .get_mut(&conn_id)
                    .and_then(|state| state.accepted_bidi_streams.pop_front()))
            } else {
                Ok(self.client_mut(conn_id)?.accepted_bidi_streams.pop_front())
            }
        }

        fn open_uni(&mut self, conn_id: u64, _now_us: u64) -> Result<Option<u64>, String> {
            let created = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .stream_create(StreamType::UniDi)
            } else {
                self.client_mut(conn_id)?
                    .conn
                    .stream_create(StreamType::UniDi)
            };
            let stream = match created {
                Ok(stream) => stream,
                Err(Error::StreamLimit | Error::ConnectionState) => return Ok(None),
                Err(error) => {
                    return Err(format!("neqo open unidirectional stream: {error:?}"));
                }
            };
            if self.is_server {
                self.server_conns
                    .get_mut(&conn_id)
                    .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))?
                    .known_streams
                    .insert(stream.as_u64());
            } else {
                self.client_mut(conn_id)?
                    .known_streams
                    .insert(stream.as_u64());
            }
            Ok(Some(stream.as_u64()))
        }

        fn accept_uni(&mut self, conn_id: u64, _now_us: u64) -> Result<Option<u64>, String> {
            if self.is_server {
                Ok(self
                    .server_conns
                    .get_mut(&conn_id)
                    .and_then(|state| state.accepted_uni_streams.pop_front()))
            } else {
                Ok(self.client_mut(conn_id)?.accepted_uni_streams.pop_front())
            }
        }

        fn stream_send(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            data: &[u8],
            _now_us: u64,
        ) -> Result<usize, String> {
            let sid = StreamId::new(stream_id);
            let early_data = !self.is_server
                && self.client(conn_id)?.early_data_limit > 0
                && !self.client(conn_id)?.connected;
            let send_len = if early_data {
                let state = self.client(conn_id)?;
                usize::try_from(state.early_data_limit.saturating_sub(state.early_data_sent))
                    .unwrap_or(usize::MAX)
                    .min(data.len())
            } else {
                data.len()
            };
            let send_capacity = if self.is_server {
                let state = self
                    .server_conns
                    .get(&conn_id)
                    .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))?;
                Self::stream_send_capacity(&state.conn.borrow(), &state.known_streams, sid)?
            } else {
                let state = self.client(conn_id)?;
                Self::stream_send_capacity(&state.conn, &state.known_streams, sid)?
            };
            let send_len = send_len.min(send_capacity);
            if send_len == 0 {
                return Ok(0);
            }
            let data = &data[..send_len];
            let known_stream = if self.is_server {
                self.server_conns
                    .get(&conn_id)
                    .is_some_and(|state| state.known_streams.contains(&stream_id))
            } else {
                self.client(conn_id)?.known_streams.contains(&stream_id)
            };
            let written = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .stream_send(sid, data)
            } else {
                self.client_mut(conn_id)?.conn.stream_send(sid, data)
            };
            let written = match written {
                Ok(written) => written,
                Err(Error::NotAvailable) => 0,
                Err(error) => {
                    let connection_detail = if self.is_server {
                        self.server_conns.get(&conn_id).map(|state| {
                            let conn = state.conn.borrow();
                            let stats = conn.stats();
                            format!(
                                "state={:?} packets={}/{} stream_frames={}/{} blocked={}/{}",
                                conn.state(),
                                stats.packets_tx,
                                stats.packets_rx,
                                stats.frame_tx.stream,
                                stats.frame_rx.stream,
                                stats.frame_tx.data_blocked,
                                stats.frame_tx.stream_data_blocked,
                            )
                        })
                    } else {
                        let conn = &self.client(conn_id)?.conn;
                        let stats = conn.stats();
                        Some(format!(
                            "state={:?} packets={}/{} stream_frames={}/{} blocked={}/{}",
                            conn.state(),
                            stats.packets_tx,
                            stats.packets_rx,
                            stats.frame_tx.stream,
                            stats.frame_rx.stream,
                            stats.frame_tx.data_blocked,
                            stats.frame_tx.stream_data_blocked,
                        ))
                    };
                    return Err(format!(
                        "neqo stream_send: {error:?} connection={conn_id} stream={stream_id} known={known_stream} detail={connection_detail:?}"
                    ));
                }
            };
            if early_data {
                let state = self.client_mut(conn_id)?;
                state.early_data_sent = state.early_data_sent.saturating_add(written as u64);
            }
            Ok(written)
        }

        fn stream_recv(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            out: &mut [u8],
            _now_us: u64,
        ) -> Result<(usize, bool), String> {
            let sid = StreamId::new(stream_id);
            let known_stream = if self.is_server {
                self.server_conns
                    .get(&conn_id)
                    .is_some_and(|state| state.known_streams.contains(&stream_id))
            } else {
                self.client(conn_id)?.known_streams.contains(&stream_id)
            };
            let read = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .stream_recv(sid, out)
            } else {
                self.client_mut(conn_id)?.conn.stream_recv(sid, out)
            };
            let result = match read {
                Ok((read, fin)) => (read, fin),
                Err(Error::NoMoreData) => {
                    let fin = if self.is_server {
                        self.server_conns
                            .get(&conn_id)
                            .and_then(|state| state.peer_terminal.get(&stream_id))
                            .is_some_and(|terminal| terminal.fin)
                    } else {
                        self.client(conn_id)?
                            .peer_terminal
                            .get(&stream_id)
                            .is_some_and(|terminal| terminal.fin)
                    };
                    (0, fin)
                }
                Err(Error::NotAvailable) => (0, false),
                Err(Error::InvalidStreamId) if known_stream => (0, false),
                Err(error) => {
                    let zero_rtt_state = if self.is_server {
                        self.server_conns
                            .get(&conn_id)
                            .map(|state| state.conn.borrow().zero_rtt_state())
                    } else {
                        Some(self.client(conn_id)?.conn.zero_rtt_state())
                    };
                    return Err(format!(
                        "neqo stream_recv: {error:?} stream={stream_id} zero_rtt_state={zero_rtt_state:?}"
                    ));
                }
            };
            if result.1 {
                if self.is_server {
                    if let Some(state) = self.server_conns.get_mut(&conn_id) {
                        let terminal = state.peer_terminal.entry(stream_id).or_insert(
                            QpfPeerTerminalFactsV6 {
                                available: true,
                                ..Default::default()
                            },
                        );
                        terminal.fin = true;
                    }
                } else {
                    let terminal = self
                        .client_mut(conn_id)?
                        .peer_terminal
                        .entry(stream_id)
                        .or_insert(QpfPeerTerminalFactsV6 {
                            available: true,
                            ..Default::default()
                        });
                    terminal.fin = true;
                }
            }
            Ok(result)
        }

        fn stream_finish(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            _now_us: u64,
        ) -> Result<(), String> {
            let sid = StreamId::new(stream_id);
            let result = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .stream_close_send(sid)
            } else {
                self.client_mut(conn_id)?.conn.stream_close_send(sid)
            };
            match result {
                Ok(()) | Err(Error::NoMoreData) => {}
                Err(error) => return Err(format!("neqo stream_finish: {error:?}")),
            }
            Ok(())
        }

        fn stream_reset(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            application_error: u64,
            _now_us: u64,
        ) -> Result<(), String> {
            let sid = StreamId::new(stream_id);
            let result = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .stream_reset_send(sid, application_error)
            } else {
                self.client_mut(conn_id)?
                    .conn
                    .stream_reset_send(sid, application_error)
            };
            result.map_err(|e| format!("neqo stream reset: {e:?}"))?;
            Ok(())
        }

        fn stream_stop_sending(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            application_error: u64,
            _now_us: u64,
        ) -> Result<(), String> {
            let sid = StreamId::new(stream_id);
            let result = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .stream_stop_sending(sid, application_error)
            } else {
                self.client_mut(conn_id)?
                    .conn
                    .stream_stop_sending(sid, application_error)
            };
            result.map_err(|e| format!("neqo stop sending: {e:?}"))?;
            Ok(())
        }

        fn connection_close(
            &mut self,
            conn_id: u64,
            application_error: u64,
            now_us: u64,
        ) -> Result<(), String> {
            let now = self.now(now_us);
            if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .close(now, application_error, "");
            } else {
                self.client_mut(conn_id)?
                    .conn
                    .close(now, application_error, "");
            }
            Ok(())
        }

        fn datagram_send(
            &mut self,
            conn_id: u64,
            data: &[u8],
            _now_us: u64,
        ) -> Result<bool, String> {
            let early_data = !self.is_server
                && self.client(conn_id)?.early_data_limit > 0
                && !self.client(conn_id)?.connected;
            if early_data {
                let state = self.client(conn_id)?;
                let remaining = state.early_data_limit.saturating_sub(state.early_data_sent);
                if u64::try_from(data.len()).unwrap_or(u64::MAX) > remaining {
                    return Ok(false);
                }
            }
            let result = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .send_datagram(data.to_vec(), None)
            } else {
                self.client_mut(conn_id)?
                    .conn
                    .send_datagram(data.to_vec(), None)
            };
            match result {
                Ok(()) => {
                    if early_data {
                        let state = self.client_mut(conn_id)?;
                        state.early_data_sent = state
                            .early_data_sent
                            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
                    }
                    Ok(true)
                }
                Err(Error::TooMuchData) | Err(Error::NotAvailable) => Ok(false),
                Err(error) => Err(format!("neqo datagram_send: {error:?}")),
            }
        }

        fn datagram_recv(
            &mut self,
            conn_id: u64,
            out: &mut [u8],
            _now_us: u64,
        ) -> Result<Option<usize>, String> {
            let datagram = if self.is_server {
                self.server_conns
                    .get_mut(&conn_id)
                    .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))?
                    .datagrams
                    .pop_front()
            } else {
                self.client_mut(conn_id)?.datagrams.pop_front()
            };
            let Some(datagram) = datagram else {
                return Ok(None);
            };
            if datagram.len() > out.len() {
                return Err(format!(
                    "neqo datagram_recv buffer too small: {} > {}",
                    datagram.len(),
                    out.len()
                ));
            }
            let len = datagram.len();
            out[..len].copy_from_slice(&datagram);
            Ok(Some(len))
        }

        fn transport_counters(&mut self) -> QpfTransportCountersV3 {
            let mut result = self.retired_counters;
            for state in self.clients.values() {
                Self::add_counters(&mut result, &state.conn.stats());
            }
            for state in self.server_conns.values() {
                Self::add_counters(&mut result, &state.conn.borrow().stats());
            }
            result
        }

        fn peer_terminal_facts(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            now_us: u64,
        ) -> Result<QpfPeerTerminalFactsV6, String> {
            self.check_fatal()?;
            let (stream_terminal, connection_terminal) = if self.is_server {
                let state = self
                    .server_conns
                    .get(&conn_id)
                    .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))?;
                (
                    state.peer_terminal.get(&stream_id).copied(),
                    state.connection_terminal,
                )
            } else {
                let state = self.client(conn_id)?;
                (
                    state.peer_terminal.get(&stream_id).copied(),
                    state.connection_terminal,
                )
            };

            if stream_terminal.is_none() && !connection_terminal.connection_close {
                let mut empty = [];
                self.stream_recv(conn_id, stream_id, &mut empty, now_us)?;
            }

            let mut terminal = if self.is_server {
                self.server_conns
                    .get(&conn_id)
                    .and_then(|state| state.peer_terminal.get(&stream_id))
                    .copied()
                    .unwrap_or(QpfPeerTerminalFactsV6 {
                        available: true,
                        ..Default::default()
                    })
            } else {
                self.client(conn_id)?
                    .peer_terminal
                    .get(&stream_id)
                    .copied()
                    .unwrap_or(QpfPeerTerminalFactsV6 {
                        available: true,
                        ..Default::default()
                    })
            };
            terminal.connection_close = connection_terminal.connection_close;
            terminal.connection_close_error = connection_terminal.connection_close_error;
            terminal.connection_close_reason_length =
                connection_terminal.connection_close_reason_length;
            Ok(terminal)
        }

        fn negotiated_settings(&mut self) -> Result<QpfNegotiatedSettingsV7, String> {
            self.check_fatal()?;
            let mut aggregate: Option<QpfNegotiatedSettingsV7> = None;
            for state in self.clients.values() {
                let settings = self.connection_negotiated_settings(&state.conn, state.connected)?;
                if aggregate.is_some_and(|value| value != settings) {
                    return Err("Neqo connections negotiated different treatments".into());
                }
                aggregate = Some(settings);
            }
            for state in self.server_conns.values() {
                let conn = state.conn.borrow();
                let settings = self.connection_negotiated_settings(&conn, state.connected)?;
                if aggregate.is_some_and(|value| value != settings) {
                    return Err("Neqo connections negotiated different treatments".into());
                }
                aggregate = Some(settings);
            }
            aggregate.ok_or_else(|| "no Neqo connections are available for treatment audit".into())
        }
    }
}

mod s2n_engine {
    use super::*;
    use bytes::Bytes;
    use core::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    };
    use s2n_quic::{
        client::{Connect, ConnectionAttempt},
        connection::{Connection, Handle, StreamAcceptor},
        provider::{
            congestion_controller, connection_id, datagram as s2n_datagram, io, limits, mtu,
            tls::rustls as s2n_rustls,
        },
        stream::{Error as S2nStreamError, Stream},
        Client, Server,
    };
    use s2n_quic_core::{
        endpoint::Endpoint,
        event::{api as s2n_event, Subscriber as S2nEventSubscriber},
        inet::{datagram, ExplicitCongestionNotification, SocketAddress as S2nSocketAddress},
        io::{rx, tx},
        path::{Handle as _, Tuple},
        time::{Clock, Timestamp},
    };
    use std::fmt;

    type SharedDriver = Arc<Mutex<Option<Box<dyn EndpointDriver>>>>;
    static S2N_SERVER_ZERO_RTT_PACKETS: AtomicU64 = AtomicU64::new(0);

    #[derive(Default)]
    struct S2nResumptionEventState {
        client_zero_rtt_keys: AtomicU64,
        client_zero_rtt_packets_sent: AtomicU64,
        packets_lost: AtomicU64,
        recovery_wakeups: AtomicU64,
        flow_control_blocked_events: AtomicU64,
        stream_credit_blocked_events: AtomicU64,
        peer_terminal: Mutex<HashMap<(u64, u64), S2nPeerStreamTerminalFacts>>,
        peer_application_closes: Mutex<HashMap<u64, (u64, u64)>>,
        closed_connections: Mutex<HashMap<u64, bool>>,
        negotiated: Mutex<HashMap<u64, S2nNegotiatedFacts>>,
    }

    #[derive(Clone, Copy, Default)]
    struct S2nPeerStreamTerminalFacts {
        fin: bool,
        reset_stream: bool,
        stop_sending: bool,
        reset_stream_error: u64,
        stop_sending_error: u64,
    }

    #[derive(Clone)]
    struct S2nResumptionEvents {
        state: Arc<S2nResumptionEventState>,
    }

    struct S2nConnectionEventContext {
        is_server: bool,
    }

    #[derive(Clone, Debug, Default)]
    struct S2nNegotiatedFacts {
        handshake_complete: bool,
        alpn_qperf_2: bool,
        server_name_quicperf: bool,
        quic_version: u32,
        tls_cipher_suite: u16,
        tls_key_exchange_group: u16,
        peer_certificate_present: bool,
        peer_leaf_ed25519: bool,
        transport: Option<S2nPeerTransport>,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct S2nPeerTransport {
        max_idle_timeout_ns: u64,
        max_udp_payload_size: u64,
        max_ack_delay_ns: u64,
        ack_delay_exponent: u64,
        active_migration: bool,
        active_connection_id_limit: u64,
        connection_id_bytes: u64,
        max_bidi_streams: u64,
        max_uni_streams: u64,
        connection_window_bytes: u64,
        stream_window_bytes: u64,
        datagram_max_frame_size: u64,
    }

    impl S2nResumptionEvents {
        fn update_negotiated(
            &self,
            connection_id: u64,
            update: impl FnOnce(&mut S2nNegotiatedFacts),
        ) {
            let mut negotiated = self
                .state
                .negotiated
                .lock()
                .expect("s2n negotiated-settings lock poisoned");
            update(negotiated.entry(connection_id).or_default());
        }

        fn observe_packet_version(&self, connection_id: u64, header: &s2n_event::PacketHeader) {
            let version = match header {
                s2n_event::PacketHeader::Initial { version, .. }
                | s2n_event::PacketHeader::Handshake { version, .. }
                | s2n_event::PacketHeader::ZeroRtt { version, .. }
                | s2n_event::PacketHeader::Retry { version, .. } => Some(*version),
                _ => None,
            };
            if let Some(version) = version {
                self.update_negotiated(connection_id, |facts| facts.quic_version = version);
            }
        }
    }

    impl S2nEventSubscriber for S2nResumptionEvents {
        type ConnectionContext = S2nConnectionEventContext;

        fn create_connection_context(
            &mut self,
            meta: &s2n_event::ConnectionMeta,
            _info: &s2n_event::ConnectionInfo,
        ) -> Self::ConnectionContext {
            S2nConnectionEventContext {
                is_server: matches!(meta.endpoint_type, s2n_event::EndpointType::Server { .. }),
            }
        }

        fn on_key_update(
            &mut self,
            context: &mut Self::ConnectionContext,
            _meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::KeyUpdate,
        ) {
            if !context.is_server && matches!(event.key_type, s2n_event::KeyType::ZeroRtt { .. }) {
                self.state
                    .client_zero_rtt_keys
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        fn on_packet_received(
            &mut self,
            context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::PacketReceived,
        ) {
            self.observe_packet_version(meta.id, &event.packet_header);
            if context.is_server
                && matches!(event.packet_header, s2n_event::PacketHeader::ZeroRtt { .. })
            {
                S2N_SERVER_ZERO_RTT_PACKETS.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn on_packet_sent(
            &mut self,
            context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::PacketSent,
        ) {
            self.observe_packet_version(meta.id, &event.packet_header);
            if !context.is_server
                && matches!(event.packet_header, s2n_event::PacketHeader::ZeroRtt { .. })
            {
                self.state
                    .client_zero_rtt_packets_sent
                    .fetch_add(1, Ordering::Relaxed);
            }
            if matches!(
                &event.transmission_mode,
                s2n_event::TransmissionMode::LossRecoveryProbing { .. }
            ) {
                self.state.recovery_wakeups.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn on_packet_lost(
            &mut self,
            _context: &mut Self::ConnectionContext,
            _meta: &s2n_event::ConnectionMeta,
            _event: &s2n_event::PacketLost,
        ) {
            self.state.packets_lost.fetch_add(1, Ordering::Relaxed);
        }

        fn on_frame_sent(
            &mut self,
            _context: &mut Self::ConnectionContext,
            _meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::FrameSent,
        ) {
            match &event.frame {
                s2n_event::Frame::DataBlocked { .. } => {
                    self.state
                        .flow_control_blocked_events
                        .fetch_add(1, Ordering::Relaxed);
                }
                s2n_event::Frame::StreamDataBlocked { .. } => {
                    self.state
                        .stream_credit_blocked_events
                        .fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }

        fn on_frame_received(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::FrameReceived,
        ) {
            let (stream_id, update) = match &event.frame {
                s2n_event::Frame::Stream {
                    id, is_fin: true, ..
                } => (
                    *id,
                    S2nPeerStreamTerminalFacts {
                        fin: true,
                        ..Default::default()
                    },
                ),
                s2n_event::Frame::ResetStream { id, error_code, .. } => (
                    *id,
                    S2nPeerStreamTerminalFacts {
                        reset_stream: true,
                        reset_stream_error: *error_code,
                        ..Default::default()
                    },
                ),
                s2n_event::Frame::StopSending { id, error_code, .. } => (
                    *id,
                    S2nPeerStreamTerminalFacts {
                        stop_sending: true,
                        stop_sending_error: *error_code,
                        ..Default::default()
                    },
                ),
                _ => return,
            };
            let mut facts = self
                .state
                .peer_terminal
                .lock()
                .expect("s2n peer-terminal lock poisoned");
            let facts = facts.entry((meta.id, stream_id)).or_default();
            facts.fin |= update.fin;
            if update.reset_stream {
                facts.reset_stream = true;
                facts.reset_stream_error = update.reset_stream_error;
            }
            if update.stop_sending {
                facts.stop_sending = true;
                facts.stop_sending_error = update.stop_sending_error;
            }
        }

        fn on_connection_close_frame_received(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::ConnectionCloseFrameReceived,
        ) {
            if event.frame.frame_type.is_none() {
                self.state
                    .peer_application_closes
                    .lock()
                    .expect("s2n peer-close lock poisoned")
                    .insert(
                        meta.id,
                        (
                            event.frame.error_code,
                            event.frame.reason.map_or(0, |reason| reason.len() as u64),
                        ),
                    );
            }
        }

        fn on_connection_closed(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            _event: &s2n_event::ConnectionClosed,
        ) {
            self.state
                .closed_connections
                .lock()
                .expect("s2n closed-connection lock poisoned")
                .insert(meta.id, true);
        }

        fn on_application_protocol_information(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::ApplicationProtocolInformation,
        ) {
            self.update_negotiated(meta.id, |facts| {
                facts.alpn_qperf_2 = event.chosen_application_protocol == ALPN;
            });
        }

        fn on_server_name_information(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::ServerNameInformation,
        ) {
            self.update_negotiated(meta.id, |facts| {
                facts.server_name_quicperf = event.chosen_server_name == "server.quicperf.test";
            });
        }

        fn on_key_exchange_group(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::KeyExchangeGroup,
        ) {
            self.update_negotiated(meta.id, |facts| {
                facts.tls_key_exchange_group = if event
                    .chosen_group_name
                    .eq_ignore_ascii_case("X25519")
                    && !event.contains_kem
                {
                    0x001d
                } else {
                    0
                };
            });
        }

        fn on_tls_exporter_ready(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::TlsExporterReady,
        ) {
            let tls_cipher_suite = if matches!(
                event.session.cipher_suite(),
                s2n_event::CipherSuite::TLS_AES_128_GCM_SHA256 { .. }
            ) {
                0x1301
            } else {
                0
            };
            let peer_certs = event.session.peer_cert_chain_der().ok();
            let peer_certificate_present =
                peer_certs.as_ref().is_some_and(|certs| !certs.is_empty());
            let peer_leaf_ed25519 = peer_certs
                .as_ref()
                .and_then(|certs| certs.first())
                .is_some_and(|cert| {
                    certificate_signature_is_ed25519(&CertificateDer::from(cert.as_slice()))
                });
            self.update_negotiated(meta.id, |facts| {
                facts.tls_cipher_suite = tls_cipher_suite;
                facts.peer_certificate_present = peer_certificate_present;
                facts.peer_leaf_ed25519 = peer_leaf_ed25519;
            });
        }

        fn on_handshake_status_updated(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::HandshakeStatusUpdated,
        ) {
            if matches!(
                event.status,
                s2n_event::HandshakeStatus::Complete { .. }
                    | s2n_event::HandshakeStatus::Confirmed { .. }
                    | s2n_event::HandshakeStatus::HandshakeDoneAcked { .. }
            ) {
                self.update_negotiated(meta.id, |facts| facts.handshake_complete = true);
            }
        }

        fn on_transport_parameters_received(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &s2n_event::ConnectionMeta,
            event: &s2n_event::TransportParametersReceived,
        ) {
            let transport = &event.transport_parameters;
            let stream_window = transport.initial_max_stream_data_bidi_local;
            let snapshot = S2nPeerTransport {
                max_idle_timeout_ns: transport.max_idle_timeout.as_nanos().min(u64::MAX as u128)
                    as u64,
                max_udp_payload_size: transport.max_udp_payload_size,
                max_ack_delay_ns: transport.max_ack_delay.as_nanos().min(u64::MAX as u128) as u64,
                ack_delay_exponent: u64::from(transport.ack_delay_exponent),
                active_migration: transport.migration_support,
                active_connection_id_limit: transport.active_connection_id_limit,
                connection_id_bytes: transport
                    .initial_source_connection_id
                    .as_ref()
                    .map_or(0, |cid| cid.bytes.len() as u64),
                max_bidi_streams: transport.initial_max_streams_bidi,
                max_uni_streams: transport.initial_max_streams_uni,
                connection_window_bytes: transport.initial_max_data,
                stream_window_bytes: if stream_window
                    == transport.initial_max_stream_data_bidi_remote
                    && stream_window == transport.initial_max_stream_data_uni
                {
                    stream_window
                } else {
                    0
                },
                datagram_max_frame_size: transport.max_datagram_frame_size,
            };
            self.update_negotiated(meta.id, |facts| facts.transport = Some(snapshot));
        }
    }

    struct Inbound {
        remote: S2nSocketAddress,
        local: S2nSocketAddress,
        bytes: Vec<u8>,
    }

    struct Outbound {
        destination: SocketAddr,
        bytes: Vec<u8>,
    }

    struct ManualClock {
        now: Timestamp,
    }

    impl ManualClock {
        fn new(now_us: u64) -> Self {
            Self {
                now: unsafe { Timestamp::from_duration(Duration::from_micros(now_us.max(1))) },
            }
        }
    }

    impl Clock for ManualClock {
        fn get_time(&self) -> Timestamp {
            self.now
        }
    }

    struct ManualRxQueue {
        packets: VecDeque<Inbound>,
    }

    impl rx::Queue for ManualRxQueue {
        type Handle = Tuple;

        fn for_each<F: FnMut(datagram::Header<Self::Handle>, &mut [u8])>(
            &mut self,
            mut on_packet: F,
        ) {
            while let Some(mut packet) = self.packets.pop_front() {
                let header = datagram::Header {
                    path: Tuple {
                        remote_address: packet.remote.into(),
                        local_address: packet.local.into(),
                    },
                    ecn: ExplicitCongestionNotification::default(),
                };
                on_packet(header, &mut packet.bytes);
            }
        }

        fn is_empty(&self) -> bool {
            self.packets.is_empty()
        }
    }

    struct ManualTxQueue<'a> {
        outbound: &'a mut VecDeque<Outbound>,
        capacity: usize,
        packet_capacity: usize,
    }

    impl tx::Queue for ManualTxQueue<'_> {
        type Handle = Tuple;

        fn push<M: tx::Message<Handle = Self::Handle>>(
            &mut self,
            mut message: M,
        ) -> Result<tx::Outcome, tx::Error> {
            if self.capacity == 0 {
                return Err(tx::Error::AtCapacity);
            }

            let mut bytes = vec![0u8; self.packet_capacity];
            let len = message.write_payload(tx::PayloadBuffer::new(&mut bytes), 0)?;
            bytes.truncate(len);
            let destination = std::net::SocketAddr::from(message.path_handle().remote_address());
            let index = self.outbound.len();
            self.outbound.push_back(Outbound { destination, bytes });
            self.capacity -= 1;
            Ok(tx::Outcome { len, index })
        }

        fn capacity(&self) -> usize {
            self.capacity
        }
    }

    trait EndpointDriver: Send {
        fn enqueue_receive(&mut self, remote: SocketAddr, data: &[u8]);
        fn flush_receive(&mut self, now_us: u64);
        fn drive(&mut self, now_us: u64);
        fn pop_transmit(&mut self, now_us: u64) -> Option<Outbound>;
        fn next_timeout_us(&self, now_us: u64) -> Option<u64>;
    }

    struct ManualEndpoint<E> {
        endpoint: E,
        local_addr: S2nSocketAddress,
        packet_capacity: usize,
        inbound: VecDeque<Inbound>,
        outbound: VecDeque<Outbound>,
    }

    impl<E> ManualEndpoint<E>
    where
        E: Endpoint<PathHandle = Tuple>,
    {
        fn clock(now_us: u64) -> ManualClock {
            ManualClock::new(now_us)
        }

        fn poll_endpoint_wakeups(&mut self, now_us: u64) {
            let clock = Self::clock(now_us);
            for _ in 0..64 {
                let result = with_context(|cx| self.endpoint.poll_wakeups(cx, &clock));
                match result {
                    Poll::Ready(Ok(0)) | Poll::Pending | Poll::Ready(Err(_)) => break,
                    Poll::Ready(Ok(_)) => {}
                }
            }
        }

        fn transmit(&mut self, now_us: u64) {
            let clock = Self::clock(now_us);
            let mut queue = ManualTxQueue {
                outbound: &mut self.outbound,
                capacity: 64,
                packet_capacity: self.packet_capacity,
            };
            self.endpoint.transmit(&mut queue, &clock);
        }
    }

    impl<E> EndpointDriver for ManualEndpoint<E>
    where
        E: Endpoint<PathHandle = Tuple>,
    {
        fn enqueue_receive(&mut self, remote: SocketAddr, data: &[u8]) {
            self.inbound.push_back(Inbound {
                remote: remote.into(),
                local: self.local_addr,
                bytes: data.to_vec(),
            });
        }

        fn flush_receive(&mut self, now_us: u64) {
            let clock = Self::clock(now_us);
            let mut queue = ManualRxQueue {
                packets: core::mem::take(&mut self.inbound),
            };
            self.endpoint.receive(&mut queue, &clock);
            self.poll_endpoint_wakeups(now_us);
            self.transmit(now_us);
        }

        fn drive(&mut self, now_us: u64) {
            self.poll_endpoint_wakeups(now_us);
            self.transmit(now_us);
        }

        fn pop_transmit(&mut self, now_us: u64) -> Option<Outbound> {
            if self.outbound.is_empty() {
                self.drive(now_us);
            }
            self.outbound.pop_front()
        }

        fn next_timeout_us(&self, now_us: u64) -> Option<u64> {
            let now = ManualClock::new(now_us).get_time();
            self.endpoint.timeout().map(|deadline| {
                if deadline <= now {
                    0
                } else {
                    deadline
                        .saturating_duration_since(now)
                        .as_micros()
                        .min(u64::MAX as u128) as u64
                }
            })
        }
    }

    #[derive(Clone)]
    struct ManualIo {
        driver: SharedDriver,
        local_addr: S2nSocketAddress,
        packet_capacity: usize,
    }

    impl fmt::Debug for ManualIo {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ManualIo")
                .field("local_addr", &self.local_addr)
                .finish()
        }
    }

    impl io::Provider for ManualIo {
        type PathHandle = Tuple;
        type Error = String;

        fn start<E: Endpoint<PathHandle = Self::PathHandle>>(
            self,
            endpoint: E,
        ) -> Result<S2nSocketAddress, Self::Error> {
            let mut slot = self
                .driver
                .lock()
                .map_err(|_| "manual io lock poisoned".to_string())?;
            *slot = Some(Box::new(ManualEndpoint {
                endpoint,
                local_addr: self.local_addr,
                packet_capacity: self.packet_capacity,
                inbound: VecDeque::new(),
                outbound: VecDeque::new(),
            }));
            Ok(self.local_addr)
        }
    }

    struct ConnState {
        handle: Handle,
        acceptor: StreamAcceptor,
        connected: bool,
        event_id: u64,
    }

    struct StreamState {
        stream: Stream,
        pending_rx: VecDeque<Bytes>,
        local_send_terminal: bool,
        peer_send_terminal: bool,
    }

    impl StreamState {
        fn new(stream: Stream) -> Self {
            let local_send_terminal = matches!(&stream, Stream::Receive(_));
            let peer_send_terminal = matches!(&stream, Stream::Send(_));
            Self {
                stream,
                pending_rx: VecDeque::new(),
                local_send_terminal,
                peer_send_terminal,
            }
        }

        fn releasable(&self) -> bool {
            self.local_send_terminal && self.peer_send_terminal && self.pending_rx.is_empty()
        }
    }

    pub struct S2nEngine {
        is_server: bool,
        driver: SharedDriver,
        client: Option<Client>,
        server: Option<Server>,
        pending_connect: HashMap<u64, Pin<Box<ConnectionAttempt>>>,
        connections: HashMap<u64, ConnState>,
        accepted_connections: VecDeque<u64>,
        streams: HashMap<(u64, u64), StreamState>,
        next_conn_id: u64,
        tls_verify_peer: bool,
        imported_zero_rtt: bool,
        zero_rtt_connection_id: Option<u64>,
        resumption_take_baseline: u64,
        resumption_early_take_baseline: u64,
        zero_rtt_key_baseline: u64,
        zero_rtt_packet_sent_baseline: u64,
        server_zero_rtt_packet_baseline: u64,
        event_state: Arc<S2nResumptionEventState>,
        server_name: String,
        engine_id: u64,
        pending_resumption_handle: Option<u64>,
        local_settings: QpfNegotiatedSettingsV7,
    }

    impl S2nEngine {
        pub fn new(config: &QpfConfig) -> Result<Self, String> {
            let cert_path = unsafe { cstr(config.cert_path)? };
            let key_path = unsafe { cstr(config.key_path)? };
            let chain_path = unsafe { cstr(config.chain_path)? };
            let local_addr: S2nSocketAddress = socket_from_qpf(&config.local_addr).into();
            let server_name = unsafe { cstr(config.tls_hostname)? };
            let certs = load_certs(&cert_path)?;
            let local_leaf_ed25519 = certs.first().is_some_and(certificate_signature_is_ed25519);
            if !local_leaf_ed25519 {
                return Err("configured leaf certificate is not signed with Ed25519".into());
            }
            let connection_window = u32::try_from(config.connection_window)
                .map_err(|_| "s2n connection window exceeds u32".to_string())?;
            let stream_window = u32::try_from(config.stream_window)
                .map_err(|_| "s2n stream window exceeds u32".to_string())?;
            let initial_congestion_window =
                u32::try_from(config.initial_congestion_window_bytes)
                    .map_err(|_| "s2n initial congestion window exceeds u32".to_string())?;
            let connection_id_bytes = usize::try_from(config.connection_id_bytes)
                .map_err(|_| "s2n connection ID length exceeds usize".to_string())?;
            let udp_payload_size = u16::try_from(config.udp_payload_size)
                .map_err(|_| "s2n UDP payload size exceeds u16".to_string())?;
            let datagram_queue_capacity =
                usize::try_from(config.datagram_max_unreturned_per_connection.max(1))
                    .map_err(|_| "s2n DATAGRAM queue capacity exceeds usize".to_string())?;
            if config.max_ack_delay_ns != 25_000_000
                || config.ack_delay_exponent != 3
                || config.ack_frequency
                || config.active_migration
                || config.active_connection_id_limit != 2
                || connection_id_bytes != 8
                || udp_payload_size != 1_350
                || config.datagram_max_frame_size != 1_200
                || config.ticket_lifetime_ns != 300_000_000_000
                || config.maximum_early_data_bytes != 4_096
                || !config.one_use_tickets
            {
                return Err("s2n packet engine requires the frozen exact treatment".into());
            }
            let driver = Arc::new(Mutex::new(None));
            let io = ManualIo {
                driver: Arc::clone(&driver),
                local_addr,
                packet_capacity: config.udp_payload_size as usize,
            };
            let event_state = Arc::new(S2nResumptionEventState::default());
            let events = S2nResumptionEvents {
                state: Arc::clone(&event_state),
            };

            let limits = limits::Limits::new()
                .with_data_window(u64::from(connection_window))
                .map_err(|e| format!("s2n limits data window: {e:?}"))?
                .with_bidirectional_local_data_window(u64::from(stream_window))
                .map_err(|e| format!("s2n limits bidi local window: {e:?}"))?
                .with_bidirectional_remote_data_window(u64::from(stream_window))
                .map_err(|e| format!("s2n limits bidi remote window: {e:?}"))?
                .with_unidirectional_data_window(u64::from(stream_window))
                .map_err(|e| format!("s2n limits uni window: {e:?}"))?
                .with_max_open_local_bidirectional_streams(config.max_bidi_streams)
                .map_err(|e| format!("s2n limits local bidi streams: {e:?}"))?
                .with_max_open_remote_bidirectional_streams(config.max_bidi_streams)
                .map_err(|e| format!("s2n limits remote bidi streams: {e:?}"))?
                .with_max_open_local_unidirectional_streams(config.max_uni_streams)
                .map_err(|e| format!("s2n limits local uni streams: {e:?}"))?
                .with_max_open_remote_unidirectional_streams(config.max_uni_streams)
                .map_err(|e| format!("s2n limits remote uni streams: {e:?}"))?
                .with_max_idle_timeout(Duration::from_millis(config.idle_timeout_ms))
                .map_err(|e| format!("s2n limits idle timeout: {e:?}"))?
                .with_max_udp_payload_size(udp_payload_size)
                .map_err(|e| format!("s2n limits UDP payload size: {e:?}"))?
                .with_max_ack_delay(Duration::from_nanos(config.max_ack_delay_ns))
                .map_err(|e| format!("s2n limits ACK delay: {e:?}"))?
                .with_max_active_connection_ids(config.active_connection_id_limit)
                .map_err(|e| format!("s2n limits active connection IDs: {e:?}"))?
                .with_active_connection_migration(config.active_migration)
                .map_err(|e| format!("s2n limits migration: {e:?}"))?;

            let connection_id = connection_id::default::Format::builder()
                .with_len(connection_id_bytes)
                .map_err(|e| format!("s2n connection ID length: {e:?}"))?
                .with_handshake_connection_id_rotation(false)
                .expect("infallible s2n connection ID rotation")
                .build()
                .expect("infallible s2n connection ID build");
            let path_mtu = udp_payload_size
                .checked_add(48)
                .ok_or_else(|| "s2n IPv6 path MTU overflows u16".to_string())?;
            let mtu = mtu::Config::builder()
                .with_base_mtu(path_mtu)
                .map_err(|e| format!("s2n base MTU: {e}"))?
                .with_initial_mtu(path_mtu)
                .map_err(|e| format!("s2n initial MTU: {e}"))?
                .with_max_mtu(path_mtu)
                .map_err(|e| format!("s2n max MTU: {e}"))?
                .build()
                .map_err(|e| format!("s2n MTU build: {e}"))?;

            let (client, server) = if config.is_server {
                let datagram = s2n_datagram::default::Endpoint::builder()
                    .with_send_capacity(datagram_queue_capacity)
                    .map_err(|e| format!("s2n datagram send capacity: {e:?}"))?
                    .with_recv_capacity(datagram_queue_capacity)
                    .map_err(|e| format!("s2n datagram recv capacity: {e:?}"))?
                    .with_max_datagram_frame_size(config.datagram_max_frame_size)
                    .build()
                    .map_err(|e| format!("s2n datagram build: {e:?}"))?;
                let tls = s2n_rustls::Server::from(server_tls_config(
                    certs,
                    load_key(&key_path)?,
                    config.calendar_unix_seconds,
                ));
                let server_builder = Server::builder()
                    .with_io(io)
                    .map_err(|e| format!("s2n server io: {e}"))?
                    .with_tls(tls)
                    .map_err(|e| format!("s2n server tls: {e}"))?
                    .with_event(events)
                    .map_err(|e| format!("s2n server event: {e}"))?
                    .with_limits(limits)
                    .map_err(|e| format!("s2n server limits: {e}"))?
                    .with_datagram(datagram)
                    .map_err(|e| format!("s2n server datagram: {e}"))?
                    .with_connection_id(connection_id)
                    .map_err(|e| format!("s2n server connection ID: {e}"))?
                    .with_mtu(mtu)
                    .map_err(|e| format!("s2n server MTU: {e}"))?;
                let server = if config.use_bbr {
                    server_builder
                        .with_congestion_controller(
                            congestion_controller::bbr::Builder::default()
                                .with_initial_congestion_window(initial_congestion_window)
                                .build(),
                        )
                        .map_err(|e| format!("s2n server congestion: {e}"))?
                        .start()
                        .map_err(|e| format!("s2n server start: {e}"))?
                } else {
                    server_builder
                        .with_congestion_controller(
                            congestion_controller::cubic::Builder::default()
                                .with_initial_congestion_window(initial_congestion_window)
                                .build(),
                        )
                        .map_err(|e| format!("s2n server congestion: {e}"))?
                        .start()
                        .map_err(|e| format!("s2n server start: {e}"))?
                };
                (None, Some(server))
            } else {
                let datagram = s2n_datagram::default::Endpoint::builder()
                    .with_send_capacity(datagram_queue_capacity)
                    .map_err(|e| format!("s2n datagram send capacity: {e:?}"))?
                    .with_recv_capacity(datagram_queue_capacity)
                    .map_err(|e| format!("s2n datagram recv capacity: {e:?}"))?
                    .with_max_datagram_frame_size(config.datagram_max_frame_size)
                    .build()
                    .map_err(|e| format!("s2n datagram build: {e:?}"))?;
                let tls = s2n_rustls::Client::from(client_tls_config(
                    load_certs(if config.tls_verify_peer {
                        &chain_path
                    } else {
                        &cert_path
                    })?,
                    config.tls_verify_peer,
                    config.calendar_unix_seconds,
                ));
                let client_builder = Client::builder()
                    .with_io(io)
                    .map_err(|e| format!("s2n client io: {e}"))?
                    .with_tls(tls)
                    .map_err(|e| format!("s2n client tls: {e}"))?
                    .with_event(events)
                    .map_err(|e| format!("s2n client event: {e}"))?
                    .with_limits(limits)
                    .map_err(|e| format!("s2n client limits: {e}"))?
                    .with_datagram(datagram)
                    .map_err(|e| format!("s2n client datagram: {e}"))?
                    .with_connection_id(connection_id)
                    .map_err(|e| format!("s2n client connection ID: {e}"))?
                    .with_mtu(mtu)
                    .map_err(|e| format!("s2n client MTU: {e}"))?;
                let client = if config.use_bbr {
                    client_builder
                        .with_congestion_controller(
                            congestion_controller::bbr::Builder::default()
                                .with_initial_congestion_window(initial_congestion_window)
                                .build(),
                        )
                        .map_err(|e| format!("s2n client congestion: {e}"))?
                        .start()
                        .map_err(|e| format!("s2n client start: {e}"))?
                } else {
                    client_builder
                        .with_congestion_controller(
                            congestion_controller::cubic::Builder::default()
                                .with_initial_congestion_window(initial_congestion_window)
                                .build(),
                        )
                        .map_err(|e| format!("s2n client congestion: {e}"))?
                        .start()
                        .map_err(|e| format!("s2n client start: {e}"))?
                };
                (Some(client), None)
            };

            Ok(Self {
                is_server: config.is_server,
                driver,
                client,
                server,
                pending_connect: HashMap::new(),
                connections: HashMap::new(),
                accepted_connections: VecDeque::new(),
                streams: HashMap::new(),
                next_conn_id: if config.is_server { 1 } else { 0 },
                tls_verify_peer: config.tls_verify_peer,
                imported_zero_rtt: false,
                zero_rtt_connection_id: None,
                resumption_take_baseline: 0,
                resumption_early_take_baseline: 0,
                zero_rtt_key_baseline: 0,
                zero_rtt_packet_sent_baseline: 0,
                server_zero_rtt_packet_baseline: 0,
                event_state,
                server_name,
                engine_id: NEXT_RUST_ENGINE_ID.fetch_add(1, Ordering::Relaxed),
                pending_resumption_handle: None,
                local_settings: QpfNegotiatedSettingsV7 {
                    tls_leaf_ed25519: u8::from(local_leaf_ed25519),
                    use_bbr: u8::from(config.use_bbr),
                    ack_frequency: u8::from(config.ack_frequency),
                    active_migration: u8::from(config.active_migration),
                    one_use_tickets: u8::from(config.one_use_tickets),
                    initial_congestion_window_bytes: config.initial_congestion_window_bytes,
                    stream_credit_replenish_below: config.stream_credit_replenish_below,
                    ticket_lifetime_ns: config.ticket_lifetime_ns,
                    maximum_early_data_bytes: config.maximum_early_data_bytes,
                    ..QpfNegotiatedSettingsV7::default()
                },
            })
        }

        fn with_driver<T>(
            &self,
            f: impl FnOnce(&mut dyn EndpointDriver) -> T,
        ) -> Result<T, String> {
            let mut guard = self
                .driver
                .lock()
                .map_err(|_| "manual io lock poisoned".to_string())?;
            let driver = guard
                .as_mut()
                .ok_or_else(|| "s2n manual io endpoint was not started".to_string())?;
            Ok(f(driver.as_mut()))
        }

        fn insert_connection(&mut self, conn_id: u64, connection: Connection) {
            let (handle, acceptor) = connection.split();
            let event_id = handle.id();
            self.connections.insert(
                conn_id,
                ConnState {
                    handle,
                    acceptor,
                    connected: true,
                    event_id,
                },
            );
        }

        fn poll_application(&mut self) -> Result<bool, String> {
            let mut progressed = false;
            let pending_ids: Vec<_> = self.pending_connect.keys().copied().collect();
            for conn_id in pending_ids {
                let result = {
                    let attempt = self
                        .pending_connect
                        .get_mut(&conn_id)
                        .expect("pending s2n connection disappeared");
                    with_context(|cx| attempt.as_mut().poll(cx))
                };
                match result {
                    Poll::Ready(Ok(connection)) => {
                        self.pending_connect.remove(&conn_id);
                        self.insert_connection(conn_id, connection);
                        progressed = true;
                    }
                    Poll::Ready(Err(error)) => {
                        self.pending_connect.remove(&conn_id);
                        return Err(format!("s2n connect {conn_id}: {error:?}"));
                    }
                    Poll::Pending => {}
                }
            }

            let mut accepted = Vec::new();
            if let Some(server) = self.server.as_mut() {
                loop {
                    match with_context(|cx| server.poll_accept(cx)) {
                        Poll::Ready(Some(connection)) => {
                            accepted.push(connection);
                        }
                        Poll::Ready(None) | Poll::Pending => break,
                    }
                }
            }
            for connection in accepted {
                let conn_id = self.next_conn_id;
                self.next_conn_id += 1;
                self.insert_connection(conn_id, connection);
                self.accepted_connections.push_back(conn_id);
                progressed = true;
            }
            Ok(progressed)
        }

        fn drive_all(&mut self, now_us: u64) -> Result<(), String> {
            let ticket_scope =
                SessionTicketTakeScope::new(self.pending_resumption_handle.is_some());
            let mut application_idle = false;
            for _ in 0..8 {
                let progressed = self.poll_application()?;
                if self
                    .zero_rtt_connection_id
                    .is_some_and(|id| progressed && self.connections.contains_key(&id))
                {
                    break;
                }
                if application_idle && !progressed {
                    break;
                }
                self.with_driver(|driver| driver.drive(now_us))?;
                application_idle = !progressed;
            }
            self.poll_application()?;
            drop(ticket_scope);
            if let Some(handle_id) = self.pending_resumption_handle {
                let ticket_taken = shared_session_store_taken(self.tls_verify_peer)
                    > self.resumption_take_baseline
                    || shared_session_store_early_taken(self.tls_verify_peer)
                        > self.resumption_early_take_baseline;
                if ticket_taken {
                    consume_resumption_handle(self.engine_id, handle_id)?;
                    self.pending_resumption_handle = None;
                }
            }
            Ok(())
        }

        fn stream_mut(&mut self, conn_id: u64, stream_id: u64) -> Result<&mut StreamState, String> {
            self.streams
                .get_mut(&(conn_id, stream_id))
                .ok_or_else(|| format!("unknown s2n stream {conn_id}/{stream_id}"))
        }

        fn release_terminal_stream(&mut self, conn_id: u64, stream_id: u64) {
            if self
                .streams
                .get(&(conn_id, stream_id))
                .is_some_and(StreamState::releasable)
            {
                self.streams.remove(&(conn_id, stream_id));
            }
        }

        fn reap_connection(&mut self, conn_id: u64, event_id: u64) -> Result<(), String> {
            self.connections.remove(&conn_id);
            self.streams.retain(|(id, _), _| *id != conn_id);
            self.event_state
                .peer_terminal
                .lock()
                .map_err(|_| "s2n peer-terminal lock poisoned".to_string())?
                .retain(|(id, _), _| *id != event_id);
            self.event_state
                .peer_application_closes
                .lock()
                .map_err(|_| "s2n peer-close lock poisoned".to_string())?
                .remove(&event_id);
            self.event_state
                .closed_connections
                .lock()
                .map_err(|_| "s2n closed-connection lock poisoned".to_string())?
                .remove(&event_id);
            self.event_state
                .negotiated
                .lock()
                .map_err(|_| "s2n negotiated-settings lock poisoned".to_string())?
                .remove(&event_id);
            Ok(())
        }
    }

    impl Drop for S2nEngine {
        fn drop(&mut self) {
            if let Some(handle_id) = self.pending_resumption_handle.take() {
                release_resumption_handle(self.engine_id, handle_id);
            }
        }
    }

    impl PacketEngine for S2nEngine {
        fn connect(&mut self, remote: SocketAddr, now_us: u64) -> Result<u64, String> {
            if self.is_server {
                return Err("s2n connect called on server".into());
            }
            let client = self
                .client
                .as_ref()
                .ok_or_else(|| "s2n client not initialized".to_string())?;
            let connect = Connect::new(remote).with_server_name(self.server_name.as_str());
            let conn_id = self.next_conn_id;
            self.next_conn_id += 1;
            self.pending_connect
                .insert(conn_id, Box::pin(client.connect(connect)));
            self.zero_rtt_connection_id = self.imported_zero_rtt.then_some(conn_id);
            self.drive_all(now_us)?;
            Ok(conn_id)
        }

        fn accept_connection(&mut self) -> Option<u64> {
            self.accepted_connections.pop_front()
        }

        fn is_connected(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
            self.drive_all(now_us)?;
            Ok(self
                .connections
                .get(&conn_id)
                .is_some_and(|state| state.connected))
        }

        fn connection_is_closed(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
            self.drive_all(now_us)?;
            if self.pending_connect.contains_key(&conn_id) {
                return Ok(false);
            }
            let event_id = self
                .connections
                .get(&conn_id)
                .ok_or_else(|| format!("unknown s2n connection {conn_id}"))?
                .event_id;
            let closed = self
                .event_state
                .closed_connections
                .lock()
                .map_err(|_| "s2n closed-connection lock poisoned".to_string())?
                .get(&event_id)
                .copied()
                .unwrap_or(false);
            if closed && self.is_server {
                self.reap_connection(conn_id, event_id)?;
            }
            Ok(closed)
        }

        fn receive(&mut self, remote: SocketAddr, data: &[u8], now_us: u64) -> Result<(), String> {
            self.with_driver(|driver| {
                driver.enqueue_receive(remote, data);
                driver.flush_receive(now_us);
            })?;
            self.drive_all(now_us)
        }

        fn receive_batch(
            &mut self,
            packets: &[QpfReceiveDescriptorV2],
            now_us: u64,
        ) -> Result<(), String> {
            if packets.is_empty() {
                return Ok(());
            }
            self.with_driver(|driver| -> Result<(), String> {
                for packet in packets {
                    let (remote, data) = receive_descriptor(packet)?;
                    driver.enqueue_receive(remote, data);
                }
                driver.flush_receive(now_us);
                Ok(())
            })??;
            self.drive_all(now_us)
        }

        fn poll_transmit(
            &mut self,
            now_us: u64,
            out: &mut [u8],
        ) -> Result<Option<(SocketAddr, usize)>, String> {
            if let Some(packet) = self.with_driver(|driver| driver.pop_transmit(now_us))? {
                if packet.bytes.len() > out.len() {
                    return Err("s2n transmit buffer too small".into());
                }
                out[..packet.bytes.len()].copy_from_slice(&packet.bytes);
                Ok(Some((packet.destination, packet.bytes.len())))
            } else {
                Ok(None)
            }
        }

        fn next_timeout_us(&mut self, now_us: u64) -> Result<Option<u64>, String> {
            self.with_driver(|driver| driver.next_timeout_us(now_us))
        }

        fn on_timeout(&mut self, now_us: u64) -> Result<(), String> {
            self.drive_all(now_us)
        }

        fn export_resumption_state(
            &mut self,
            _conn_id: u64,
            now_us: u64,
            out: &mut Vec<u8>,
        ) -> Result<bool, String> {
            self.drive_all(now_us)?;
            if shared_session_store_ticket_count(self.tls_verify_peer, &self.server_name) == 0 {
                return Ok(false);
            }
            Ok(export_resumption_handle(
                self.tls_verify_peer,
                &self.server_name,
                now_us,
                out,
            ))
        }

        fn import_resumption_state(
            &mut self,
            data: &[u8],
            use_zero_rtt: bool,
            now_us: u64,
        ) -> Result<bool, String> {
            if self.pending_resumption_handle.is_some() {
                return Err("s2n engine already has a reserved resumption handle".into());
            }
            let Some(handle_id) = reserve_resumption_handle(
                self.engine_id,
                self.tls_verify_peer,
                &self.server_name,
                data,
                use_zero_rtt,
                now_us,
                self.local_settings.ticket_lifetime_ns,
                false,
            )?
            else {
                return Ok(false);
            };
            self.pending_resumption_handle = Some(handle_id);
            self.imported_zero_rtt = use_zero_rtt;
            self.resumption_take_baseline = shared_session_store_taken(self.tls_verify_peer);
            self.resumption_early_take_baseline =
                shared_session_store_early_taken(self.tls_verify_peer);
            self.zero_rtt_key_baseline = self
                .event_state
                .client_zero_rtt_keys
                .load(Ordering::Relaxed);
            self.zero_rtt_packet_sent_baseline = self
                .event_state
                .client_zero_rtt_packets_sent
                .load(Ordering::Relaxed);
            self.server_zero_rtt_packet_baseline =
                S2N_SERVER_ZERO_RTT_PACKETS.load(Ordering::Relaxed);
            Ok(true)
        }

        fn connection_resumed(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
            self.drive_all(now_us)?;
            let connected = self
                .connections
                .get(&conn_id)
                .is_some_and(|state| state.connected);
            Ok(connected
                && (shared_session_store_taken(self.tls_verify_peer)
                    > self.resumption_take_baseline
                    || shared_session_store_early_taken(self.tls_verify_peer)
                        > self.resumption_early_take_baseline))
        }

        fn zero_rtt_attempted(&mut self, _conn_id: u64, now_us: u64) -> Result<bool, String> {
            self.drive_all(now_us)?;
            let zero_rtt_keys = self
                .event_state
                .client_zero_rtt_keys
                .load(Ordering::Relaxed);
            let zero_rtt_packets = self
                .event_state
                .client_zero_rtt_packets_sent
                .load(Ordering::Relaxed);
            if std::env::var_os("QUICPERF_PACKET_RESUMPTION_DEBUG").is_some() {
                eprintln!(
                    "s2n zero_rtt_attempted_debug imported={} keys={} key_baseline={} packets={} packet_baseline={}",
                    self.imported_zero_rtt,
                    zero_rtt_keys,
                    self.zero_rtt_key_baseline,
                    zero_rtt_packets,
                    self.zero_rtt_packet_sent_baseline
                );
            }
            Ok(self.imported_zero_rtt
                && (zero_rtt_keys > self.zero_rtt_key_baseline
                    || zero_rtt_packets > self.zero_rtt_packet_sent_baseline))
        }

        fn zero_rtt_accepted(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
            self.drive_all(now_us)?;
            Ok(self.zero_rtt_attempted(conn_id, now_us)?
                && self.connection_resumed(conn_id, now_us)?
                && self
                    .event_state
                    .client_zero_rtt_keys
                    .load(Ordering::Relaxed)
                    > self.zero_rtt_key_baseline)
        }

        fn zero_rtt_rejected(&mut self, conn_id: u64, now_us: u64) -> Result<bool, String> {
            let attempted = self.zero_rtt_attempted(conn_id, now_us)?;
            Ok(attempted
                && S2N_SERVER_ZERO_RTT_PACKETS.load(Ordering::Relaxed)
                    > self.server_zero_rtt_packet_baseline)
        }

        fn open_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
            let zero_rtt_connection_ready = self.zero_rtt_connection_id == Some(conn_id)
                && self.connections.contains_key(&conn_id);
            if !zero_rtt_connection_ready {
                self.drive_all(now_us)?;
            }
            let Some(conn) = self.connections.get_mut(&conn_id) else {
                if self.pending_connect.contains_key(&conn_id) {
                    return Ok(None);
                }
                return Err(format!("unknown s2n connection {conn_id}"));
            };
            match with_context(|cx| conn.handle.poll_open_bidirectional_stream(cx)) {
                Poll::Ready(Ok(stream)) => {
                    let stream_id = stream.id();
                    self.streams
                        .insert((conn_id, stream_id), StreamState::new(stream.into()));
                    if !self.imported_zero_rtt {
                        self.drive_all(now_us)?;
                    }
                    Ok(Some(stream_id))
                }
                Poll::Ready(Err(error)) => Err(format!("s2n open stream: {error:?}")),
                Poll::Pending => {
                    self.drive_all(now_us)?;
                    Ok(None)
                }
            }
        }

        fn accept_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
            self.drive_all(now_us)?;
            let Some(conn) = self.connections.get_mut(&conn_id) else {
                if self.pending_connect.contains_key(&conn_id) {
                    return Ok(None);
                }
                return Err(format!("unknown s2n connection {conn_id}"));
            };
            match with_context(|cx| conn.acceptor.poll_accept_bidirectional_stream(cx)) {
                Poll::Ready(Ok(Some(stream))) => {
                    let stream_id = stream.id();
                    self.streams
                        .insert((conn_id, stream_id), StreamState::new(stream.into()));
                    Ok(Some(stream_id))
                }
                Poll::Ready(Ok(None)) | Poll::Pending => Ok(None),
                Poll::Ready(Err(error)) => Err(format!("s2n accept stream: {error:?}")),
            }
        }

        fn open_uni(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
            self.drive_all(now_us)?;
            let Some(conn) = self.connections.get_mut(&conn_id) else {
                if self.pending_connect.contains_key(&conn_id) {
                    return Ok(None);
                }
                return Err(format!("unknown s2n connection {conn_id}"));
            };
            match with_context(|cx| conn.handle.poll_open_send_stream(cx)) {
                Poll::Ready(Ok(stream)) => {
                    let stream_id = stream.id();
                    self.streams
                        .insert((conn_id, stream_id), StreamState::new(stream.into()));
                    self.drive_all(now_us)?;
                    Ok(Some(stream_id))
                }
                Poll::Ready(Err(error)) => {
                    Err(format!("s2n open unidirectional stream: {error:?}"))
                }
                Poll::Pending => {
                    self.drive_all(now_us)?;
                    Ok(None)
                }
            }
        }

        fn accept_uni(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
            self.drive_all(now_us)?;
            let Some(conn) = self.connections.get_mut(&conn_id) else {
                if self.pending_connect.contains_key(&conn_id) {
                    return Ok(None);
                }
                return Err(format!("unknown s2n connection {conn_id}"));
            };
            match with_context(|cx| conn.acceptor.poll_accept_receive_stream(cx)) {
                Poll::Ready(Ok(Some(stream))) => {
                    let stream_id = stream.id();
                    self.streams
                        .insert((conn_id, stream_id), StreamState::new(stream.into()));
                    Ok(Some(stream_id))
                }
                Poll::Ready(Ok(None)) | Poll::Pending => Ok(None),
                Poll::Ready(Err(error)) => {
                    Err(format!("s2n accept unidirectional stream: {error:?}"))
                }
            }
        }

        fn stream_send(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            data: &[u8],
            _now_us: u64,
        ) -> Result<usize, String> {
            let len = {
                let stream = self.stream_mut(conn_id, stream_id)?;
                let ready = with_context(|cx| stream.stream.poll_send_ready(cx));
                let capacity = match ready {
                    Poll::Ready(Ok(capacity)) => capacity,
                    Poll::Ready(Err(error)) => {
                        return Err(format!("s2n stream send ready: {error:?}"));
                    }
                    Poll::Pending => return Ok(0),
                };
                let len = capacity.min(data.len());
                if len == 0 {
                    return Ok(0);
                }
                stream
                    .stream
                    .send_data(Bytes::copy_from_slice(&data[..len]))
                    .map_err(|e| format!("s2n stream send: {e:?}"))?;
                len
            };
            Ok(len)
        }

        fn stream_recv(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            out: &mut [u8],
            _now_us: u64,
        ) -> Result<(usize, bool), String> {
            let (result, peer_send_terminal) = {
                let stream = self.stream_mut(conn_id, stream_id)?;
                if let Some(mut pending) = stream.pending_rx.pop_front() {
                    let len = pending.len().min(out.len());
                    out[..len].copy_from_slice(&pending[..len]);
                    if len < pending.len() {
                        let rest = pending.split_off(len);
                        stream.pending_rx.push_front(rest);
                    }
                    return Ok((len, false));
                }

                let result = match with_context(|cx| stream.stream.poll_receive(cx)) {
                    Poll::Ready(Ok(Some(mut chunk))) => {
                        let len = chunk.len().min(out.len());
                        out[..len].copy_from_slice(&chunk[..len]);
                        if len < chunk.len() {
                            let rest = chunk.split_off(len);
                            stream.pending_rx.push_back(rest);
                        }
                        Ok((len, false))
                    }
                    Poll::Ready(Ok(None)) => {
                        stream.peer_send_terminal = true;
                        Ok((0, true))
                    }
                    Poll::Ready(Err(S2nStreamError::StreamReset { .. })) => {
                        stream.peer_send_terminal = true;
                        Ok((0, false))
                    }
                    Poll::Ready(Err(error)) => Err(format!("s2n stream recv: {error:?}")),
                    Poll::Pending => Ok((0, false)),
                };
                (result, stream.peer_send_terminal)
            };
            let result = result?;
            if peer_send_terminal {
                self.release_terminal_stream(conn_id, stream_id);
            }
            Ok(result)
        }

        fn stream_finish(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            now_us: u64,
        ) -> Result<(), String> {
            {
                let stream = self.stream_mut(conn_id, stream_id)?;
                if !stream.local_send_terminal {
                    stream
                        .stream
                        .finish()
                        .map_err(|e| format!("s2n stream finish: {e:?}"))?;
                    stream.local_send_terminal = true;
                }
            }
            self.release_terminal_stream(conn_id, stream_id);
            self.drive_all(now_us)
        }

        fn stream_reset(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            application_error: u64,
            now_us: u64,
        ) -> Result<(), String> {
            let error = s2n_quic::application::Error::try_from(application_error)
                .map_err(|e| format!("s2n stream reset application error: {e:?}"))?;
            {
                let stream = self.stream_mut(conn_id, stream_id)?;
                if !stream.local_send_terminal {
                    stream
                        .stream
                        .reset(error)
                        .map_err(|e| format!("s2n stream reset: {e:?}"))?;
                    stream.local_send_terminal = true;
                }
            }
            self.release_terminal_stream(conn_id, stream_id);
            self.drive_all(now_us)
        }

        fn stream_stop_sending(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            application_error: u64,
            now_us: u64,
        ) -> Result<(), String> {
            let error = s2n_quic::application::Error::try_from(application_error)
                .map_err(|e| format!("s2n stop sending application error: {e:?}"))?;
            self.stream_mut(conn_id, stream_id)?
                .stream
                .stop_sending(error)
                .map_err(|e| format!("s2n stop sending: {e:?}"))?;
            self.drive_all(now_us)
        }

        fn connection_close(
            &mut self,
            conn_id: u64,
            application_error: u64,
            now_us: u64,
        ) -> Result<(), String> {
            let error = s2n_quic::application::Error::try_from(application_error)
                .map_err(|e| format!("s2n connection close application error: {e:?}"))?;
            let event_id = self
                .connections
                .get(&conn_id)
                .ok_or_else(|| format!("unknown s2n connection {conn_id}"))?
                .event_id;
            self.connections
                .get(&conn_id)
                .expect("s2n connection disappeared")
                .handle
                .close(error);
            self.event_state
                .closed_connections
                .lock()
                .map_err(|_| "s2n closed-connection lock poisoned".to_string())?
                .insert(event_id, true);
            self.drive_all(now_us)
        }

        fn peer_terminal_facts(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            now_us: u64,
        ) -> Result<QpfPeerTerminalFactsV6, String> {
            self.drive_all(now_us)?;
            let event_id = self
                .connections
                .get(&conn_id)
                .ok_or_else(|| format!("unknown s2n connection {conn_id}"))?
                .event_id;
            let stream = self
                .event_state
                .peer_terminal
                .lock()
                .map_err(|_| "s2n peer-terminal lock poisoned".to_string())?
                .get(&(event_id, stream_id))
                .copied()
                .unwrap_or_default();
            let connection_close = self
                .event_state
                .peer_application_closes
                .lock()
                .map_err(|_| "s2n peer-close lock poisoned".to_string())?
                .get(&event_id)
                .copied()
                .unwrap_or_default();
            let result = QpfPeerTerminalFactsV6 {
                available: true,
                fin: stream.fin,
                reset_stream: stream.reset_stream,
                stop_sending: stream.stop_sending,
                connection_close: self
                    .event_state
                    .peer_application_closes
                    .lock()
                    .map_err(|_| "s2n peer-close lock poisoned".to_string())?
                    .contains_key(&event_id),
                reserved: [0; 3],
                reset_stream_error: stream.reset_stream_error,
                stop_sending_error: stream.stop_sending_error,
                connection_close_error: connection_close.0,
                connection_close_reason_length: connection_close.1,
            };
            if result.connection_close {
                self.reap_connection(conn_id, event_id)?;
            }
            Ok(result)
        }

        fn datagram_send(
            &mut self,
            conn_id: u64,
            data: &[u8],
            _now_us: u64,
        ) -> Result<bool, String> {
            let conn = self
                .connections
                .get_mut(&conn_id)
                .ok_or_else(|| format!("unknown s2n connection {conn_id}"))?;
            let mut payload = Bytes::copy_from_slice(data);
            let send = conn
                .handle
                .datagram_mut(|sender: &mut s2n_datagram::default::Sender| {
                    with_context(|cx| sender.poll_send_datagram(&mut payload, cx))
                })
                .map_err(|e| format!("s2n datagram send query: {e:?}"))?;
            match send {
                Poll::Ready(Ok(())) => Ok(true),
                Poll::Pending => Ok(false),
                Poll::Ready(Err(error)) => Err(format!("s2n datagram send: {error:?}")),
            }
        }

        fn datagram_recv(
            &mut self,
            conn_id: u64,
            out: &mut [u8],
            _now_us: u64,
        ) -> Result<Option<usize>, String> {
            if self.pending_connect.contains_key(&conn_id) {
                return Ok(None);
            }
            let conn = self
                .connections
                .get_mut(&conn_id)
                .ok_or_else(|| format!("unknown s2n connection {conn_id}"))?;
            let datagram = conn
                .handle
                .datagram_mut(|receiver: &mut s2n_datagram::default::Receiver| {
                    receiver.recv_datagram()
                })
                .map_err(|e| format!("s2n datagram recv query: {e:?}"))?;
            let Some(datagram) = datagram else {
                return Ok(None);
            };
            if datagram.len() > out.len() {
                return Err(format!(
                    "s2n datagram recv buffer too small: {} > {}",
                    datagram.len(),
                    out.len()
                ));
            }
            let len = datagram.len();
            out[..len].copy_from_slice(&datagram);
            Ok(Some(len))
        }

        fn transport_counters(&mut self) -> QpfTransportCountersV3 {
            QpfTransportCountersV3 {
                packets_lost: self.event_state.packets_lost.load(Ordering::Relaxed),
                packets_retransmitted: 0,
                recovery_wakeups: self.event_state.recovery_wakeups.load(Ordering::Relaxed),
                flow_control_blocked_events: self
                    .event_state
                    .flow_control_blocked_events
                    .load(Ordering::Relaxed),
                stream_credit_blocked_events: self
                    .event_state
                    .stream_credit_blocked_events
                    .load(Ordering::Relaxed),
            }
        }

        fn negotiated_settings(&mut self) -> Result<QpfNegotiatedSettingsV7, String> {
            let negotiated = self
                .event_state
                .negotiated
                .lock()
                .map_err(|_| "s2n negotiated-settings lock poisoned".to_string())?;
            let mut aggregate: Option<QpfNegotiatedSettingsV7> = None;
            for connection in self.connections.values() {
                if !connection.connected {
                    continue;
                }
                let Some(facts) = negotiated.get(&connection.event_id) else {
                    continue;
                };
                if !facts.handshake_complete {
                    continue;
                }
                let Some(transport) = facts.transport else {
                    continue;
                };
                let leaf_ed25519 = if facts.peer_certificate_present {
                    facts.peer_leaf_ed25519
                } else {
                    self.local_settings.tls_leaf_ed25519 != 0
                };
                let mut settings = self.local_settings;
                settings.available = 1;
                settings.alpn_qperf_2 = u8::from(facts.alpn_qperf_2);
                settings.peer_certificate_present = u8::from(facts.peer_certificate_present);
                settings.peer_certificate_verified =
                    u8::from(self.tls_verify_peer && facts.peer_certificate_present);
                settings.hostname_verified = u8::from(
                    self.tls_verify_peer
                        && facts.peer_certificate_present
                        && facts.server_name_quicperf,
                );
                settings.tls_leaf_ed25519 = u8::from(leaf_ed25519);
                settings.quic_version = facts.quic_version;
                settings.tls_version = 0x0304;
                settings.tls_cipher_suite = facts.tls_cipher_suite;
                settings.tls_key_exchange_group = facts.tls_key_exchange_group;
                settings.tls_leaf_signature_algorithm = if leaf_ed25519 { 0x0807 } else { 0 };
                settings.max_udp_payload_size = transport.max_udp_payload_size;
                settings.max_ack_delay_ns = transport.max_ack_delay_ns;
                settings.ack_delay_exponent = transport.ack_delay_exponent;
                settings.active_migration = u8::from(transport.active_migration);
                settings.active_connection_id_limit = transport.active_connection_id_limit;
                settings.connection_id_bytes = transport.connection_id_bytes;
                settings.max_idle_timeout_ns = transport.max_idle_timeout_ns;
                settings.max_bidi_streams = transport.max_bidi_streams;
                settings.max_uni_streams = transport.max_uni_streams;
                settings.connection_window_bytes = transport.connection_window_bytes;
                settings.stream_window_bytes = transport.stream_window_bytes;
                settings.datagram_max_frame_size = transport.datagram_max_frame_size;
                if aggregate.is_some_and(|value| value != settings) {
                    return Err("s2n connections negotiated different treatments".into());
                }
                aggregate = Some(settings);
            }
            aggregate.ok_or_else(|| "no s2n connections are available for treatment audit".into())
        }
    }

    fn raw_waker() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        RawWaker::new(ptr::null(), &VTABLE)
    }

    fn with_context<T>(f: impl FnOnce(&mut Context<'_>) -> T) -> T {
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut context = Context::from_waker(&waker);
        f(&mut context)
    }
}

#[no_mangle]
pub extern "C" fn qpf_engine_new(config: *const QpfConfig) -> *mut qpf_engine_t {
    match ffi_result(|| {
        let config = unsafe { config.as_ref() }.ok_or_else(|| "null config".to_string())?;
        let engine = match config.library {
            QPF_LIBRARY_QUINN => Engine::Quinn(quinn_engine::QuinnEngine::new(config)?),
            QPF_LIBRARY_NOQ => Engine::Noq(noq_engine::NoqEngine::new(config)?),
            QPF_LIBRARY_NEQO => Engine::Neqo(neqo_engine::NeqoEngine::new(config)?),
            QPF_LIBRARY_S2N => Engine::S2n(s2n_engine::S2nEngine::new(config)?),
            other => return Err(format!("unknown rust packet library {other}")),
        };
        Ok(Box::into_raw(Box::new(qpf_engine_t { engine })))
    }) {
        Ok(engine) => engine,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn qpf_engine_free(engine: *mut qpf_engine_t) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine));
        }
    }
}

fn engine_mut<'a>(engine: *mut qpf_engine_t) -> Result<&'a mut qpf_engine_t, String> {
    unsafe { engine.as_mut() }.ok_or_else(|| "null engine".to_string())
}

#[no_mangle]
pub extern "C" fn qpf_engine_connect(
    engine: *mut qpf_engine_t,
    remote: *const QpfAddr,
    now_us: u64,
    conn_id: *mut u64,
) -> i32 {
    ffi_result(|| {
        let engine = engine_mut(engine)?;
        let remote = unsafe { remote.as_ref() }.ok_or_else(|| "null remote".to_string())?;
        let conn = engine.engine.connect(socket_from_qpf(remote), now_us)?;
        unsafe { *conn_id = conn };
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_engine_accept_connection(
    engine: *mut qpf_engine_t,
    conn_id: *mut u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        if let Some(conn) = engine.engine.accept_connection() {
            unsafe { *conn_id = conn };
            Ok(1)
        } else {
            Ok(0)
        }
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_engine_is_connected(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        engine
            .engine
            .is_connected(conn_id, now_us)
            .map(|v| if v { 1 } else { 0 })
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_is_closed(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        engine_mut(engine)?
            .engine
            .connection_is_closed(conn_id, now_us)
            .map(|closed| if closed { 1 } else { 0 })
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_retire(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    now_us: u64,
) -> i32 {
    ffi_result(|| {
        engine_mut(engine)?
            .engine
            .retire_connection(conn_id, now_us)
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_engine_receive(
    engine: *mut qpf_engine_t,
    remote: *const QpfAddr,
    data: *const u8,
    len: usize,
    now_us: u64,
) -> i32 {
    ffi_result(|| {
        let engine = engine_mut(engine)?;
        let remote = unsafe { remote.as_ref() }.ok_or_else(|| "null remote".to_string())?;
        let data = checked_slice(data, len)?;
        engine.engine.receive(socket_from_qpf(remote), data, now_us)
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_engine_poll_transmit(
    engine: *mut qpf_engine_t,
    remote: *mut QpfAddr,
    data: *mut u8,
    capacity: usize,
    len: *mut usize,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        let out = checked_mut_slice(data, capacity)?;
        match engine.engine.poll_transmit(now_us, out)? {
            Some((destination, written)) => {
                unsafe {
                    *remote = qpf_from_socket(destination);
                    *len = written;
                }
                Ok(1)
            }
            None => Ok(0),
        }
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_engine_next_timeout_us(
    engine: *mut qpf_engine_t,
    now_us: u64,
    timeout_us: *mut u64,
) -> i32 {
    ffi_result(|| {
        let engine = engine_mut(engine)?;
        let timeout = engine.engine.next_timeout_us(now_us)?.unwrap_or(u64::MAX);
        unsafe { *timeout_us = timeout };
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_engine_on_timeout(engine: *mut qpf_engine_t, now_us: u64) -> i32 {
    ffi_result(|| {
        let engine = engine_mut(engine)?;
        engine.engine.on_timeout(now_us)
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_packet_abi_version() -> u32 {
    QPF_PACKET_ABI_VERSION
}

fn receive_descriptor(packet: &QpfReceiveDescriptorV2) -> Result<(SocketAddr, &[u8]), String> {
    if packet.ecn > 3 || packet.reserved.iter().any(|value| *value != 0) {
        return Err("invalid receive descriptor metadata".into());
    }
    Ok((
        socket_from_qpf(&packet.peer),
        checked_slice(packet.data, packet.len)?,
    ))
}

#[no_mangle]
pub extern "C" fn qpf_engine_receive_batch(
    engine: *mut qpf_engine_t,
    packets: *const QpfReceiveDescriptorV2,
    count: usize,
    now_raw_ns: u64,
    status: *mut QpfAdapterStatusV2,
) -> i32 {
    batch_result(status, || {
        if count > QPF_PACKET_BATCH_CAPACITY {
            return Err(format!("receive batch exceeds {QPF_PACKET_BATCH_CAPACITY}"));
        }
        if count != 0 && packets.is_null() {
            return Err("null receive batch".into());
        }
        let engine = engine_mut(engine)?;
        let packets = if count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(packets, count) }
        };
        let now_us = now_raw_ns / 1_000;
        engine.engine.receive_batch(packets, now_us)
    })
    .map(|_| 0)
    .unwrap_or_else(|code| code)
}

#[no_mangle]
pub extern "C" fn qpf_engine_poll_transmit_batch(
    engine: *mut qpf_engine_t,
    packets: *mut QpfTransmitDescriptorV2,
    capacity: usize,
    count: *mut usize,
    now_raw_ns: u64,
    status: *mut QpfAdapterStatusV2,
) -> i32 {
    batch_result(status, || {
        if capacity > QPF_PACKET_BATCH_CAPACITY {
            return Err(format!(
                "transmit batch exceeds {QPF_PACKET_BATCH_CAPACITY}"
            ));
        }
        if count.is_null() || (capacity != 0 && packets.is_null()) {
            return Err("null transmit batch output".into());
        }
        let engine = engine_mut(engine)?;
        let packets = if capacity == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(packets, capacity) }
        };
        let now_us = now_raw_ns / 1_000;
        let mut produced = 0;
        for packet in packets {
            packet.len = 0;
            packet.ecn = 0;
            packet.reserved.fill(0);
            packet.desired_send_raw_ns = now_raw_ns;
            let out = checked_mut_slice(packet.data, packet.capacity)?;
            let Some((destination, written)) = engine.engine.poll_transmit(now_us, out)? else {
                break;
            };
            if written > packet.capacity {
                return Err("engine exceeded borrowed transmit capacity".into());
            }
            packet.peer = qpf_from_socket(destination);
            packet.len = written;
            produced += 1;
        }
        unsafe { *count = produced };
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or_else(|code| code)
}

#[no_mangle]
pub extern "C" fn qpf_engine_next_timeout_raw_ns(
    engine: *mut qpf_engine_t,
    now_raw_ns: u64,
    deadline_raw_ns: *mut u64,
    status: *mut QpfAdapterStatusV2,
) -> i32 {
    batch_result(status, || {
        if deadline_raw_ns.is_null() {
            return Err("null timeout output".into());
        }
        let engine = engine_mut(engine)?;
        let delay_us = engine.engine.next_timeout_us(now_raw_ns / 1_000)?;
        let deadline = delay_us.map_or(0, |delay| {
            if delay == u64::MAX {
                0
            } else {
                now_raw_ns.saturating_add(delay.saturating_mul(1_000))
            }
        });
        unsafe { *deadline_raw_ns = deadline };
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or_else(|code| code)
}

#[no_mangle]
pub extern "C" fn qpf_engine_on_timeout_raw_ns(
    engine: *mut qpf_engine_t,
    now_raw_ns: u64,
    status: *mut QpfAdapterStatusV2,
) -> i32 {
    batch_result(status, || {
        engine_mut(engine)?.engine.on_timeout(now_raw_ns / 1_000)
    })
    .map(|_| 0)
    .unwrap_or_else(|code| code)
}

#[no_mangle]
pub extern "C" fn qpf_engine_transport_counters_v3(
    engine: *mut qpf_engine_t,
    counters: *mut QpfTransportCountersV3,
    status: *mut QpfAdapterStatusV2,
) -> i32 {
    batch_result(status, || {
        let counters = unsafe { counters.as_mut() }
            .ok_or_else(|| "null transport counters output".to_string())?;
        *counters = engine_mut(engine)?.engine.transport_counters();
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or_else(|code| code)
}

#[no_mangle]
pub extern "C" fn qpf_engine_negotiated_settings_v7(
    engine: *mut qpf_engine_t,
    settings: *mut QpfNegotiatedSettingsV7,
    status: *mut QpfAdapterStatusV2,
) -> i32 {
    batch_result(status, || {
        let settings = unsafe { settings.as_mut() }
            .ok_or_else(|| "null negotiated settings output".to_string())?;
        *settings = engine_mut(engine)?.engine.negotiated_settings()?;
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or_else(|code| code)
}

#[no_mangle]
pub extern "C" fn qpf_peer_terminal_facts_v6(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: u64,
    facts: *mut QpfPeerTerminalFactsV6,
    now_us: u64,
) -> i32 {
    ffi_result(|| {
        let facts = unsafe { facts.as_mut() }
            .ok_or_else(|| "null peer terminal facts output".to_string())?;
        *facts = engine_mut(engine)?
            .engine
            .peer_terminal_facts(conn_id, stream_id, now_us)?;
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_engine_export_resumption_state(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    data: *mut u8,
    capacity: usize,
    len: *mut usize,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        if len.is_null() {
            return Err("null resumption length pointer".to_string());
        }
        let mut state = Vec::new();
        let exported = engine
            .engine
            .export_resumption_state(conn_id, now_us, &mut state)?;
        if !exported {
            unsafe { *len = 0 };
            return Ok(0);
        }
        if state.len() > capacity {
            return Err(format!(
                "resumption state buffer too small: {} > {}",
                state.len(),
                capacity
            ));
        }
        let out = checked_mut_slice(data, capacity)?;
        out[..state.len()].copy_from_slice(&state);
        unsafe { *len = state.len() };
        Ok(1)
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_engine_import_resumption_state(
    engine: *mut qpf_engine_t,
    data: *const u8,
    len: usize,
    use_zero_rtt: bool,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        let data = checked_slice(data, len)?;
        engine
            .engine
            .import_resumption_state(data, use_zero_rtt, now_us)
            .map(|imported| if imported { 1 } else { 0 })
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_resumed(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        engine
            .engine
            .connection_resumed(conn_id, now_us)
            .map(|value| if value { 1 } else { 0 })
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_zero_rtt_attempted(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        engine
            .engine
            .zero_rtt_attempted(conn_id, now_us)
            .map(|value| if value { 1 } else { 0 })
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_zero_rtt_accepted(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        engine
            .engine
            .zero_rtt_accepted(conn_id, now_us)
            .map(|value| if value { 1 } else { 0 })
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_zero_rtt_rejected(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        engine
            .engine
            .zero_rtt_rejected(conn_id, now_us)
            .map(|value| if value { 1 } else { 0 })
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_open_bidi(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: *mut u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        match engine.engine.open_bidi(conn_id, now_us)? {
            Some(stream) => {
                unsafe { *stream_id = stream };
                Ok(1)
            }
            None => Ok(0),
        }
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_accept_bidi(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: *mut u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        match engine.engine.accept_bidi(conn_id, now_us)? {
            Some(stream) => {
                unsafe { *stream_id = stream };
                Ok(1)
            }
            None => Ok(0),
        }
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_open_uni(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: *mut u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        match engine.engine.open_uni(conn_id, now_us)? {
            Some(stream) => {
                unsafe { *stream_id = stream };
                Ok(1)
            }
            None => Ok(0),
        }
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_accept_uni(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: *mut u64,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        match engine.engine.accept_uni(conn_id, now_us)? {
            Some(stream) => {
                unsafe { *stream_id = stream };
                Ok(1)
            }
            None => Ok(0),
        }
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_stream_send(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: u64,
    data: *const u8,
    len: usize,
    written: *mut usize,
    now_us: u64,
) -> i32 {
    ffi_result(|| {
        let engine = engine_mut(engine)?;
        let data = checked_slice(data, len)?;
        let count = engine
            .engine
            .stream_send(conn_id, stream_id, data, now_us)?;
        unsafe { *written = count };
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_stream_recv(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: u64,
    data: *mut u8,
    capacity: usize,
    read: *mut usize,
    fin: *mut bool,
    now_us: u64,
) -> i32 {
    ffi_result(|| {
        let engine = engine_mut(engine)?;
        let out = checked_mut_slice(data, capacity)?;
        let (count, done) = engine.engine.stream_recv(conn_id, stream_id, out, now_us)?;
        unsafe {
            *read = count;
            *fin = done;
        }
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_stream_finish(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: u64,
    now_us: u64,
) -> i32 {
    ffi_result(|| {
        let engine = engine_mut(engine)?;
        engine.engine.stream_finish(conn_id, stream_id, now_us)
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_stream_reset(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: u64,
    application_error: u64,
    now_us: u64,
) -> i32 {
    ffi_result(|| {
        engine_mut(engine)?
            .engine
            .stream_reset(conn_id, stream_id, application_error, now_us)
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_stream_stop_sending(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    stream_id: u64,
    application_error: u64,
    now_us: u64,
) -> i32 {
    ffi_result(|| {
        engine_mut(engine)?.engine.stream_stop_sending(
            conn_id,
            stream_id,
            application_error,
            now_us,
        )
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_datagram_send(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    data: *const u8,
    len: usize,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        let data = checked_slice(data, len)?;
        engine.engine.datagram_send(conn_id, data, now_us)
    }) {
        Ok(sent) => {
            if sent {
                1
            } else {
                0
            }
        }
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_datagram_recv(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    data: *mut u8,
    capacity: usize,
    read: *mut usize,
    now_us: u64,
) -> i32 {
    match ffi_result(|| {
        let engine = engine_mut(engine)?;
        let out = checked_mut_slice(data, capacity)?;
        match engine.engine.datagram_recv(conn_id, out, now_us)? {
            Some(count) => {
                unsafe { *read = count };
                Ok(1)
            }
            None => Ok(0),
        }
    }) {
        Ok(value) => value,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn qpf_connection_close(
    engine: *mut qpf_engine_t,
    conn_id: u64,
    application_error: u64,
    now_us: u64,
) -> i32 {
    ffi_result(|| {
        engine_mut(engine)?
            .engine
            .connection_close(conn_id, application_error, now_us)
    })
    .map(|_| 0)
    .unwrap_or_else(|status| status)
}

#[no_mangle]
pub extern "C" fn qpf_last_error() -> *const c_char {
    LAST_ERROR.with(|last_error| {
        last_error
            .borrow()
            .as_ref()
            .map_or(ptr::null(), |message| message.as_ptr())
    })
}
