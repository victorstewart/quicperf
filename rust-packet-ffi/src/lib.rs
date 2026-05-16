use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    ffi::{c_char, CStr, CString},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::{Arc, Mutex, Once},
    time::{Duration, Instant},
};

use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};

const QPF_LIBRARY_QUINN: u32 = 1;
const QPF_LIBRARY_NOQ: u32 = 2;
const QPF_LIBRARY_NEQO: u32 = 3;
const QPF_LIBRARY_S2N: u32 = 4;
const ALPN: &[u8] = b"perf";
const MAX_DATAGRAMS: usize = 1;
const MAX_PROTO_DRIVE_PASSES: usize = 256;

#[repr(C)]
pub struct QpfAddr {
    ip: [u8; 16],
    port: u16,
}

#[repr(C)]
pub struct QpfConfig {
    library: u32,
    is_server: bool,
    local_addr: QpfAddr,
    cert_path: *const c_char,
    key_path: *const c_char,
    chain_path: *const c_char,
    tls_verify_peer: bool,
    use_bbr: bool,
    connection_window: u64,
    stream_window: u64,
    max_bidi_streams: u64,
    max_uni_streams: u64,
    idle_timeout_ms: u64,
    udp_payload_size: u32,
    now_us: u64,
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
    fn receive(&mut self, remote: SocketAddr, data: &[u8], now_us: u64) -> Result<(), String>;
    fn poll_transmit(
        &mut self,
        now_us: u64,
        out: &mut [u8],
    ) -> Result<Option<(SocketAddr, usize)>, String>;
    fn next_timeout_us(&mut self, now_us: u64) -> Result<Option<u64>, String>;
    fn on_timeout(&mut self, now_us: u64) -> Result<(), String>;
    fn open_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String>;
    fn accept_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String>;
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

    fn receive(&mut self, remote: SocketAddr, data: &[u8], now_us: u64) -> Result<(), String> {
        match self {
            Self::Quinn(engine) => engine.receive(remote, data, now_us),
            Self::Noq(engine) => engine.receive(remote, data, now_us),
            Self::Neqo(engine) => engine.receive(remote, data, now_us),
            Self::S2n(engine) => engine.receive(remote, data, now_us),
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
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

static RUSTLS_PROVIDER: Once = Once::new();

fn init_crypto_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
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

fn client_tls_config(_certs: Vec<CertificateDer<'static>>, verify: bool) -> rustls::ClientConfig {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("ring provider supports TLS 1.3");

    let mut config = if verify {
        let mut roots = rustls::RootCertStore::empty();
        for cert in _certs {
            roots
                .add(cert)
                .expect("benchmark root certificate is valid");
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![ALPN.to_vec()];
    config
}

fn server_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("ring provider supports TLS 1.3")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("benchmark certificate/key pair is valid");
    config.alpn_protocols = vec![ALPN.to_vec()];
    config
}

fn configured_cert_chain_valid(cert_path: &str, chain_path: &str) -> Result<bool, String> {
    let certs = load_certs(cert_path)?;
    let Some(end_entity) = certs.first() else {
        return Ok(false);
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in load_certs(chain_path)? {
        roots
            .add(cert)
            .map_err(|e| format!("benchmark root certificate is invalid: {e:?}"))?;
    }
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|e| format!("build benchmark chain verifier: {e:?}"))?;
    let server_name =
        ServerName::try_from("localhost").map_err(|e| format!("benchmark server name: {e:?}"))?;
    Ok(verifier
        .verify_server_cert(end_entity, &certs[1..], &server_name, &[], UnixTime::now())
        .is_ok())
}

fn checked_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], String> {
    if ptr.is_null() && len != 0 {
        return Err("null data pointer".into());
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

fn checked_mut_slice<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8], String> {
    if ptr.is_null() && len != 0 {
        return Err("null mutable data pointer".into());
    }
    Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

macro_rules! proto_engine {
    (
        $mod_name:ident,
        $engine_name:ident,
        $proto:path,
        $bbr_expr:expr,
        $poll_datagrams:expr,
        $handle_datagram:expr
    ) => {
        mod $mod_name {
            use super::*;
            use bytes::{Bytes, BytesMut};
            use $proto as proto;

            struct ConnState {
                conn: proto::Connection,
                connected: bool,
                accepted_streams: VecDeque<u64>,
                closed: bool,
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
                base_us: u64,
                base_instant: Instant,
            }

            impl $engine_name {
                pub fn new(config: &QpfConfig) -> Result<Self, String> {
                    init_crypto_provider();
                    let cert_path = unsafe { cstr(config.cert_path)? };
                    let chain_path = unsafe { cstr(config.chain_path)? };
                    let certs = load_certs(&cert_path)?;
                    let connection_window = config.connection_window.min(u32::MAX as u64) as u32;
                    let stream_window = config.stream_window.min(u32::MAX as u64) as u32;
                    let mut transport = proto::TransportConfig::default();
                    transport
                        .receive_window(proto::VarInt::from_u32(connection_window))
                        .stream_receive_window(proto::VarInt::from_u32(stream_window))
                        .send_window(config.connection_window)
                        .max_concurrent_bidi_streams(proto::VarInt::from_u32(
                            config.max_bidi_streams.min(u32::MAX as u64) as u32,
                        ))
                        .max_concurrent_uni_streams(proto::VarInt::from_u32(
                            config.max_uni_streams.min(u32::MAX as u64) as u32,
                        ))
                        .max_idle_timeout(Some(
                            proto::IdleTimeout::try_from(Duration::from_millis(
                                config.idle_timeout_ms,
                            ))
                            .map_err(|e| format!("{e:?}"))?,
                        ))
                        .datagram_receive_buffer_size(Some(
                            config.connection_window.min(usize::MAX as u64) as usize,
                        ))
                        .datagram_send_buffer_size(
                            config.connection_window.min(usize::MAX as u64) as usize
                        )
                        .enable_segmentation_offload(false);
                    if config.use_bbr {
                        transport.congestion_controller_factory($bbr_expr);
                    }
                    let transport = Arc::new(transport);

                    let mut endpoint_config = proto::EndpointConfig::default();
                    endpoint_config
                        .max_udp_payload_size(
                            config
                                .udp_payload_size
                                .try_into()
                                .map_err(|e| format!("{e:?}"))?,
                        )
                        .map_err(|e| format!("{e:?}"))?;
                    let endpoint_config = Arc::new(endpoint_config);
                    let (server_config, client_config) = if config.is_server {
                        let key_path = unsafe { cstr(config.key_path)? };
                        let key = load_key(&key_path)?;
                        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                            rustls::crypto::ring::default_provider(),
                        ))
                        .with_protocol_versions(&[&rustls::version::TLS13])
                        .map_err(|e| format!("server tls versions: {e:?}"))?
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .map_err(|e| format!("server tls cert: {e}"))?;
                        tls.max_early_data_size = u32::MAX;
                        tls.alpn_protocols = vec![ALPN.to_vec()];
                        let quic_tls = proto::crypto::rustls::QuicServerConfig::try_from(tls)
                            .map_err(|e| format!("server quic tls config: {e:?}"))?;
                        let mut server = proto::ServerConfig::with_crypto(Arc::new(quic_tls));
                        server.transport_config(transport.clone());
                        (Some(Arc::new(server)), None)
                    } else {
                        let roots = if config.tls_verify_peer {
                            load_certs(&chain_path)?
                        } else {
                            certs
                        };
                        let tls = client_tls_config(roots, config.tls_verify_peer);
                        let quic_tls = proto::crypto::rustls::QuicClientConfig::try_from(tls)
                            .map_err(|e| format!("client tls config: {e:?}"))?;
                        let mut client = proto::ClientConfig::new(Arc::new(quic_tls));
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
                        base_us: config.now_us,
                        base_instant: Instant::now(),
                    })
                }

                fn now(&self, now_us: u64) -> Instant {
                    let delta = now_us.saturating_sub(self.base_us);
                    self.base_instant + Duration::from_micros(delta)
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

                fn process_datagram_event(
                    &mut self,
                    event: proto::DatagramEvent,
                    now: Instant,
                ) -> Result<(), String> {
                    let mut buf = Vec::with_capacity(
                        self.endpoint.config().get_max_udp_payload_size() as usize,
                    );
                    match event {
                        proto::DatagramEvent::NewConnection(incoming) => {
                            let (ch, conn) = self
                                .endpoint
                                .accept(incoming, now, &mut buf, self.server_config.clone())
                                .map_err(|e| format!("accept: {:?}", e.cause))?;
                            self.connections.insert(
                                ch,
                                ConnState {
                                    conn,
                                    connected: false,
                                    accepted_streams: VecDeque::new(),
                                    closed: false,
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
                            self.queue_transmit(transmit, &buf[..size]);
                        }
                    }
                    Ok(())
                }

                fn drive(&mut self, now_us: u64) -> Result<(), String> {
                    let now = self.now(now_us);
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

                        for (ch, state) in self.connections.iter_mut() {
                            while let Some(event) = state.conn.poll_endpoint_events() {
                                endpoint_events.push((*ch, event));
                            }
                            while let Some(event) = state.conn.poll() {
                                app_events.push((*ch, event));
                            }
                            let mut buf = Vec::with_capacity(usize::from(
                                self.endpoint.config().get_max_udp_payload_size() as usize,
                            ));
                            while let Some(transmit) =
                                state.conn.poll_transmit(now, $poll_datagrams, &mut buf)
                            {
                                let size = transmit.size;
                                transmits.push((transmit, buf[..size].to_vec()));
                                buf.clear();
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
                                    proto::Event::ConnectionLost { .. } => {
                                        state.closed = true;
                                        had_progress = true;
                                    }
                                    proto::Event::Stream(proto::StreamEvent::Opened { dir })
                                        if dir == proto::Dir::Bi =>
                                    {
                                        let before = state.accepted_streams.len();
                                        while let Some(stream_id) =
                                            state.conn.streams().accept(proto::Dir::Bi)
                                        {
                                            state.accepted_streams.push_back(u64::from(stream_id));
                                        }
                                        if state.accepted_streams.len() != before {
                                            had_progress = true;
                                        }
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
                                    | proto::Event::Stream(proto::StreamEvent::Stopped {
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
                    Ok(())
                }
            }

            impl PacketEngine for $engine_name {
                fn connect(&mut self, remote: SocketAddr, now_us: u64) -> Result<u64, String> {
                    let now = self.now(now_us);
                    let config = self
                        .client_config
                        .clone()
                        .ok_or_else(|| "connect called on server endpoint".to_string())?;
                    let (ch, conn) = self
                        .endpoint
                        .connect(now, config, remote, "localhost")
                        .map_err(|e| format!("connect: {e:?}"))?;
                    self.connections.insert(
                        ch,
                        ConnState {
                            conn,
                            connected: false,
                            accepted_streams: VecDeque::new(),
                            closed: false,
                        },
                    );
                    self.drive(now_us)?;
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

                fn receive(
                    &mut self,
                    remote: SocketAddr,
                    data: &[u8],
                    now_us: u64,
                ) -> Result<(), String> {
                    let now = self.now(now_us);
                    let mut buf = Vec::with_capacity(usize::from(
                        self.endpoint.config().get_max_udp_payload_size() as usize,
                    ));
                    if let Some(event) = ($handle_datagram)(
                        &mut self.endpoint,
                        now,
                        remote,
                        BytesMut::from(data),
                        &mut buf,
                    ) {
                        self.process_datagram_event(event, now)?;
                    }
                    self.drive(now_us)
                }

                fn poll_transmit(
                    &mut self,
                    now_us: u64,
                    out: &mut [u8],
                ) -> Result<Option<(SocketAddr, usize)>, String> {
                    self.drive(now_us)?;
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
                    let now = self.now(now_us);
                    let timeout = self
                        .connections
                        .values_mut()
                        .filter_map(|state| state.conn.poll_timeout())
                        .min();
                    Ok(timeout.map(|deadline| {
                        if deadline <= now {
                            0
                        } else {
                            deadline
                                .duration_since(now)
                                .as_micros()
                                .min(u64::MAX as u128) as u64
                        }
                    }))
                }

                fn on_timeout(&mut self, now_us: u64) -> Result<(), String> {
                    self.drive(now_us)
                }

                fn open_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    let stream_id = state.conn.streams().open(proto::Dir::Bi).map(u64::from);
                    self.drive(now_us)?;
                    Ok(stream_id)
                }

                fn accept_bidi(
                    &mut self,
                    conn_id: u64,
                    now_us: u64,
                ) -> Result<Option<u64>, String> {
                    self.drive(now_us)?;
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
                    if state.accepted_streams.is_empty() {
                        while let Some(stream_id) = state.conn.streams().accept(proto::Dir::Bi) {
                            state.accepted_streams.push_back(u64::from(stream_id));
                        }
                    }
                    Ok(state.accepted_streams.pop_front())
                }

                fn stream_send(
                    &mut self,
                    conn_id: u64,
                    stream_id: u64,
                    data: &[u8],
                    now_us: u64,
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
                    self.drive(now_us)?;
                    Ok(written)
                }

                fn stream_recv(
                    &mut self,
                    conn_id: u64,
                    stream_id: u64,
                    out: &mut [u8],
                    now_us: u64,
                ) -> Result<(usize, bool), String> {
                    let ch = proto::ConnectionHandle(conn_id as usize);
                    let sid = Self::stream_id(stream_id);
                    let state = self
                        .connections
                        .get_mut(&ch)
                        .ok_or_else(|| format!("unknown connection {conn_id}"))?;
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
                                Ok((0, true))
                            }
                            Err(proto::ReadError::Blocked) => {
                                let _ = chunks.finalize();
                                Ok((0, false))
                            }
                            Err(error) => Err(format!("stream_recv: {error:?}")),
                        },
                        Err(proto::ReadableError::ClosedStream) => Ok((0, true)),
                        Err(error) => Err(format!("stream_recv: {error:?}")),
                    }?;
                    self.drive(now_us)?;
                    Ok(result)
                }

                fn stream_finish(
                    &mut self,
                    conn_id: u64,
                    stream_id: u64,
                    now_us: u64,
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
                    self.drive(now_us)
                }

                fn datagram_send(
                    &mut self,
                    conn_id: u64,
                    data: &[u8],
                    now_us: u64,
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
                    self.drive(now_us)?;
                    Ok(sent)
                }

                fn datagram_recv(
                    &mut self,
                    conn_id: u64,
                    out: &mut [u8],
                    now_us: u64,
                ) -> Result<Option<usize>, String> {
                    self.drive(now_us)?;
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
            }
        }
    };
}

proto_engine!(
    quinn_engine,
    QuinnEngine,
    quinn_proto,
    Arc::new(quinn_proto::congestion::BbrConfig::default()),
    MAX_DATAGRAMS,
    |endpoint: &mut quinn_proto::Endpoint, now, remote, data, buf: &mut Vec<u8>| endpoint
        .handle(now, remote, None, None, data, buf)
);

proto_engine!(
    noq_engine,
    NoqEngine,
    noq_proto,
    Arc::new(noq_proto::congestion::Bbr3Config::default()),
    std::num::NonZeroUsize::new(MAX_DATAGRAMS).unwrap(),
    |endpoint: &mut noq_proto::Endpoint, now, remote, data, buf: &mut Vec<u8>| endpoint.handle(
        now,
        noq_proto::FourTuple::from_remote(remote),
        None,
        data,
        buf
    )
);

mod neqo_engine {
    use super::*;
    use neqo_common::{event::Provider as _, Datagram, Tos};
    use neqo_transport::{
        server::Server, Connection, ConnectionEvent, ConnectionParameters, Error, Output, State,
        StreamId, StreamType,
    };
    use nss::{AllowZeroRtt, AuthenticationStatus};
    use std::{cell::RefCell, rc::Rc};

    struct ServerConn {
        conn: Rc<RefCell<Connection>>,
        connected: bool,
        accepted_streams: VecDeque<u64>,
        datagrams: VecDeque<Vec<u8>>,
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
        client: Option<Connection>,
        client_connected: bool,
        client_accepted_streams: VecDeque<u64>,
        client_datagrams: VecDeque<Vec<u8>>,
        server_conns: HashMap<u64, ServerConn>,
        server_ptr_to_id: HashMap<usize, u64>,
        accepted_connections: VecDeque<u64>,
        outbound: VecDeque<Outbound>,
        next_conn_id: u64,
        callback: Option<Duration>,
        tls_verify_peer: bool,
        tls_chain_valid: bool,
    }

    impl NeqoEngine {
        pub fn new(config: &QpfConfig) -> Result<Self, String> {
            test_fixture::fixture_init();
            let cert_path = unsafe { cstr(config.cert_path)? };
            let chain_path = unsafe { cstr(config.chain_path)? };
            let tls_chain_valid =
                !config.tls_verify_peer || configured_cert_chain_valid(&cert_path, &chain_path)?;
            let params = ConnectionParameters::default()
                .max_data(config.connection_window)
                .max_stream_data(StreamType::BiDi, false, config.stream_window)
                .max_stream_data(StreamType::BiDi, true, config.stream_window)
                .max_stream_data(StreamType::UniDi, true, config.stream_window)
                .max_streams(StreamType::BiDi, config.max_bidi_streams)
                .max_streams(StreamType::UniDi, config.max_uni_streams)
                .idle_timeout(Duration::from_millis(config.idle_timeout_ms))
                .datagram_size(u64::from(config.udp_payload_size))
                .incoming_datagram_queue(1024)
                .outgoing_datagram_queue(1024)
                .pmtud(false);
            let now = Instant::now();
            let server = if config.is_server {
                Some(
                    Server::new(
                        now,
                        test_fixture::DEFAULT_KEYS,
                        test_fixture::DEFAULT_ALPN,
                        test_fixture::anti_replay(),
                        Box::new(AllowZeroRtt {}),
                        Rc::new(RefCell::new(
                            test_fixture::CountingConnectionIdGenerator::default(),
                        )),
                        params.clone(),
                    )
                    .map_err(|e| format!("neqo server config: {e:?}"))?,
                )
            } else {
                None
            };
            Ok(Self {
                is_server: config.is_server,
                local_addr: socket_from_qpf(&config.local_addr),
                params,
                server,
                client: None,
                client_connected: false,
                client_accepted_streams: VecDeque::new(),
                client_datagrams: VecDeque::new(),
                server_conns: HashMap::new(),
                server_ptr_to_id: HashMap::new(),
                accepted_connections: VecDeque::new(),
                outbound: VecDeque::new(),
                next_conn_id: 1,
                callback: None,
                tls_verify_peer: config.tls_verify_peer,
                tls_chain_valid,
            })
        }

        fn queue_output(&mut self, output: Output) {
            match output {
                Output::Datagram(datagram) => self.outbound.push_back(Outbound {
                    destination: datagram.destination(),
                    bytes: datagram.to_vec(),
                }),
                Output::Callback(delay) => self.callback = Some(delay),
                Output::None => {}
            }
        }

        fn drive_output(&mut self, now: Instant) {
            if self.is_server {
                loop {
                    let output = self.server.as_mut().unwrap().process_output(now);
                    let done = !matches!(output, Output::Datagram(_));
                    self.queue_output(output);
                    if done {
                        break;
                    }
                }
                self.drain_server_events(now);
            } else if self.client.is_some() {
                loop {
                    let output = self.client.as_mut().unwrap().process_output(now);
                    let done = !matches!(output, Output::Datagram(_));
                    self.queue_output(output);
                    if done {
                        break;
                    }
                }
                self.drain_client_events(now);
            }
        }

        fn drain_client_events(&mut self, now: Instant) {
            let Some(conn) = self.client.as_mut() else {
                return;
            };
            let events: Vec<_> = conn.events().collect();
            for event in events {
                match event {
                    ConnectionEvent::AuthenticationNeeded
                    | ConnectionEvent::EchFallbackAuthenticationNeeded { .. } => {
                        let status = if self.tls_verify_peer && !self.tls_chain_valid {
                            AuthenticationStatus::PolicyRejection
                        } else {
                            AuthenticationStatus::Ok
                        };
                        conn.authenticated(status, now);
                    }
                    ConnectionEvent::StateChange(state) if state.connected() => {
                        self.client_connected = true;
                    }
                    ConnectionEvent::StateChange(State::Closed(_)) => {
                        self.client_connected = false;
                    }
                    ConnectionEvent::NewStream { stream_id } if stream_id.is_bidi() => {
                        self.client_accepted_streams.push_back(stream_id.as_u64());
                    }
                    ConnectionEvent::Datagram(data) => {
                        self.client_datagrams.push_back(data);
                    }
                    _ => {}
                }
            }
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
                            accepted_streams: VecDeque::new(),
                            datagrams: VecDeque::new(),
                        },
                    );
                    self.accepted_connections.push_back(id);
                    id
                };
                let state = self.server_conns.get_mut(&id).unwrap();
                let mut conn = rc.borrow_mut();
                let events: Vec<_> = conn.events().collect();
                for event in events {
                    match event {
                        ConnectionEvent::AuthenticationNeeded
                        | ConnectionEvent::EchFallbackAuthenticationNeeded { .. } => {
                            conn.authenticated(AuthenticationStatus::Ok, now);
                        }
                        ConnectionEvent::StateChange(next) if next.connected() => {
                            state.connected = true;
                        }
                        ConnectionEvent::NewStream { stream_id } if stream_id.is_bidi() => {
                            state.accepted_streams.push_back(stream_id.as_u64());
                        }
                        ConnectionEvent::Datagram(data) => {
                            state.datagrams.push_back(data);
                        }
                        _ => {}
                    }
                }
            }
        }

        fn client_mut(&mut self) -> Result<&mut Connection, String> {
            self.client
                .as_mut()
                .ok_or_else(|| "neqo client connection not created".to_string())
        }

        fn server_conn(&mut self, conn_id: u64) -> Result<Rc<RefCell<Connection>>, String> {
            self.server_conns
                .get(&conn_id)
                .map(|state| Rc::clone(&state.conn))
                .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))
        }
    }

    impl PacketEngine for NeqoEngine {
        fn connect(&mut self, remote: SocketAddr, _now_us: u64) -> Result<u64, String> {
            if self.is_server {
                return Err("neqo connect called on server".into());
            }
            let now = Instant::now();
            let conn = Connection::new_client(
                test_fixture::DEFAULT_SERVER_NAME,
                test_fixture::DEFAULT_ALPN,
                Rc::new(RefCell::new(
                    test_fixture::CountingConnectionIdGenerator::default(),
                )),
                self.local_addr,
                remote,
                self.params.clone(),
                now,
            )
            .map_err(|e| format!("neqo client: {e:?}"))?;
            self.client = Some(conn);
            self.drive_output(now);
            Ok(0)
        }

        fn accept_connection(&mut self) -> Option<u64> {
            self.accepted_connections.pop_front()
        }

        fn is_connected(&mut self, conn_id: u64, _now_us: u64) -> Result<bool, String> {
            let now = Instant::now();
            self.drive_output(now);
            if self.is_server {
                Ok(self
                    .server_conns
                    .get(&conn_id)
                    .is_some_and(|state| state.connected))
            } else {
                Ok(self.client_connected)
            }
        }

        fn receive(&mut self, remote: SocketAddr, data: &[u8], _now_us: u64) -> Result<(), String> {
            let now = Instant::now();
            let datagram = Datagram::new(remote, self.local_addr, Tos::default(), data.to_vec());
            if self.is_server {
                let output = self.server.as_mut().unwrap().process([datagram], now);
                self.queue_output(output);
                self.drain_server_events(now);
            } else {
                self.client_mut()?.process_input(datagram, now);
                self.drain_client_events(now);
            }
            self.drive_output(now);
            Ok(())
        }

        fn poll_transmit(
            &mut self,
            _now_us: u64,
            out: &mut [u8],
        ) -> Result<Option<(SocketAddr, usize)>, String> {
            if self.outbound.is_empty() {
                self.drive_output(Instant::now());
            }
            if let Some(next) = self.outbound.pop_front() {
                if next.bytes.len() > out.len() {
                    return Err("neqo transmit buffer too small".into());
                }
                out[..next.bytes.len()].copy_from_slice(&next.bytes);
                Ok(Some((next.destination, next.bytes.len())))
            } else {
                Ok(None)
            }
        }

        fn next_timeout_us(&mut self, _now_us: u64) -> Result<Option<u64>, String> {
            Ok(self
                .callback
                .map(|delay| delay.as_micros().min(u64::MAX as u128) as u64))
        }

        fn on_timeout(&mut self, _now_us: u64) -> Result<(), String> {
            self.drive_output(Instant::now());
            Ok(())
        }

        fn open_bidi(&mut self, _conn_id: u64, _now_us: u64) -> Result<Option<u64>, String> {
            let stream = self
                .client_mut()?
                .stream_create(StreamType::BiDi)
                .map_err(|e| format!("neqo open stream: {e:?}"))?;
            self.drive_output(Instant::now());
            Ok(Some(stream.as_u64()))
        }

        fn accept_bidi(&mut self, conn_id: u64, _now_us: u64) -> Result<Option<u64>, String> {
            self.drive_output(Instant::now());
            if self.is_server {
                Ok(self
                    .server_conns
                    .get_mut(&conn_id)
                    .and_then(|state| state.accepted_streams.pop_front()))
            } else {
                Ok(self.client_accepted_streams.pop_front())
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
            let written = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .stream_send(sid, data)
            } else {
                self.client_mut()?.stream_send(sid, data)
            };
            let written = match written {
                Ok(written) => written,
                Err(Error::NotAvailable) => 0,
                Err(error) => return Err(format!("neqo stream_send: {error:?}")),
            };
            self.drive_output(Instant::now());
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
            let read = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .stream_recv(sid, out)
            } else {
                self.client_mut()?.stream_recv(sid, out)
            };
            let result = match read {
                Ok((read, fin)) => (read, fin),
                Err(Error::NoMoreData) => (0, true),
                Err(Error::NotAvailable) => (0, false),
                Err(error) => return Err(format!("neqo stream_recv: {error:?}")),
            };
            self.drive_output(Instant::now());
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
                self.client_mut()?.stream_close_send(sid)
            };
            match result {
                Ok(()) | Err(Error::NoMoreData) => {}
                Err(error) => return Err(format!("neqo stream_finish: {error:?}")),
            }
            self.drive_output(Instant::now());
            Ok(())
        }

        fn datagram_send(
            &mut self,
            conn_id: u64,
            data: &[u8],
            _now_us: u64,
        ) -> Result<bool, String> {
            let result = if self.is_server {
                self.server_conn(conn_id)?
                    .borrow_mut()
                    .send_datagram(data.to_vec(), None)
            } else {
                self.client_mut()?.send_datagram(data.to_vec(), None)
            };
            match result {
                Ok(()) => {
                    self.drive_output(Instant::now());
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
            self.drive_output(Instant::now());
            let datagram = if self.is_server {
                self.server_conns
                    .get_mut(&conn_id)
                    .ok_or_else(|| format!("unknown neqo server connection {conn_id}"))?
                    .datagrams
                    .pop_front()
            } else {
                self.client_datagrams.pop_front()
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
            congestion_controller, datagram as s2n_datagram, io, limits, tls::rustls as s2n_rustls,
        },
        stream::BidirectionalStream,
        Client, Server,
    };
    use s2n_quic_core::{
        endpoint::Endpoint,
        inet::{datagram, ExplicitCongestionNotification, SocketAddress as S2nSocketAddress},
        io::{rx, tx},
        path::{Handle as _, Tuple},
        time::{Clock, Timestamp},
    };
    use std::fmt;

    type SharedDriver = Arc<Mutex<Option<Box<dyn EndpointDriver>>>>;

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

            let mut bytes = vec![0u8; 65_535];
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
        fn receive(&mut self, remote: SocketAddr, data: &[u8], now_us: u64);
        fn drive(&mut self, now_us: u64);
        fn pop_transmit(&mut self, now_us: u64) -> Option<Outbound>;
        fn next_timeout_us(&self, now_us: u64) -> Option<u64>;
    }

    struct ManualEndpoint<E> {
        endpoint: E,
        local_addr: S2nSocketAddress,
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
            };
            self.endpoint.transmit(&mut queue, &clock);
        }
    }

    impl<E> EndpointDriver for ManualEndpoint<E>
    where
        E: Endpoint<PathHandle = Tuple>,
    {
        fn receive(&mut self, remote: SocketAddr, data: &[u8], now_us: u64) {
            self.inbound.push_back(Inbound {
                remote: remote.into(),
                local: self.local_addr,
                bytes: data.to_vec(),
            });
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
    }

    struct StreamState {
        stream: BidirectionalStream,
        pending_rx: VecDeque<Bytes>,
    }

    pub struct S2nEngine {
        is_server: bool,
        driver: SharedDriver,
        client: Option<Client>,
        server: Option<Server>,
        pending_connect: Option<Pin<Box<ConnectionAttempt>>>,
        connections: HashMap<u64, ConnState>,
        accepted_connections: VecDeque<u64>,
        streams: HashMap<(u64, u64), StreamState>,
        next_conn_id: u64,
    }

    impl S2nEngine {
        pub fn new(config: &QpfConfig) -> Result<Self, String> {
            let cert_path = unsafe { cstr(config.cert_path)? };
            let key_path = unsafe { cstr(config.key_path)? };
            let chain_path = unsafe { cstr(config.chain_path)? };
            let local_addr: S2nSocketAddress = socket_from_qpf(&config.local_addr).into();
            let driver = Arc::new(Mutex::new(None));
            let io = ManualIo {
                driver: Arc::clone(&driver),
                local_addr,
            };

            let limits = limits::Limits::new()
                .with_data_window(config.connection_window.min(u32::MAX as u64))
                .map_err(|e| format!("s2n limits data window: {e:?}"))?
                .with_bidirectional_local_data_window(config.stream_window.min(u32::MAX as u64))
                .map_err(|e| format!("s2n limits bidi local window: {e:?}"))?
                .with_bidirectional_remote_data_window(config.stream_window.min(u32::MAX as u64))
                .map_err(|e| format!("s2n limits bidi remote window: {e:?}"))?
                .with_unidirectional_data_window(config.stream_window.min(u32::MAX as u64))
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
                .map_err(|e| format!("s2n limits idle timeout: {e:?}"))?;

            let (client, server) = if config.is_server {
                let datagram = s2n_datagram::default::Endpoint::builder()
                    .with_send_capacity(config.max_bidi_streams.max(1) as usize * 1024)
                    .map_err(|e| format!("s2n datagram send capacity: {e:?}"))?
                    .with_recv_capacity(config.max_bidi_streams.max(1) as usize * 1024)
                    .map_err(|e| format!("s2n datagram recv capacity: {e:?}"))?
                    .build()
                    .map_err(|e| format!("s2n datagram build: {e:?}"))?;
                let tls = s2n_rustls::Server::from(server_tls_config(
                    load_certs(&cert_path)?,
                    load_key(&key_path)?,
                ));
                let server = Server::builder()
                    .with_io(io)
                    .map_err(|e| format!("s2n server io: {e}"))?
                    .with_tls(tls)
                    .map_err(|e| format!("s2n server tls: {e}"))?
                    .with_limits(limits)
                    .map_err(|e| format!("s2n server limits: {e}"))?
                    .with_datagram(datagram)
                    .map_err(|e| format!("s2n server datagram: {e}"))?
                    .with_congestion_controller(congestion_controller::Bbr::default())
                    .map_err(|e| format!("s2n server congestion: {e}"))?
                    .start()
                    .map_err(|e| format!("s2n server start: {e}"))?;
                (None, Some(server))
            } else {
                let datagram = s2n_datagram::default::Endpoint::builder()
                    .with_send_capacity(config.max_bidi_streams.max(1) as usize * 1024)
                    .map_err(|e| format!("s2n datagram send capacity: {e:?}"))?
                    .with_recv_capacity(config.max_bidi_streams.max(1) as usize * 1024)
                    .map_err(|e| format!("s2n datagram recv capacity: {e:?}"))?
                    .build()
                    .map_err(|e| format!("s2n datagram build: {e:?}"))?;
                let tls = s2n_rustls::Client::from(client_tls_config(
                    load_certs(if config.tls_verify_peer {
                        &chain_path
                    } else {
                        &cert_path
                    })?,
                    config.tls_verify_peer,
                ));
                let client = Client::builder()
                    .with_io(io)
                    .map_err(|e| format!("s2n client io: {e}"))?
                    .with_tls(tls)
                    .map_err(|e| format!("s2n client tls: {e}"))?
                    .with_limits(limits)
                    .map_err(|e| format!("s2n client limits: {e}"))?
                    .with_datagram(datagram)
                    .map_err(|e| format!("s2n client datagram: {e}"))?
                    .with_congestion_controller(congestion_controller::Bbr::default())
                    .map_err(|e| format!("s2n client congestion: {e}"))?
                    .start()
                    .map_err(|e| format!("s2n client start: {e}"))?;
                (Some(client), None)
            };

            Ok(Self {
                is_server: config.is_server,
                driver,
                client,
                server,
                pending_connect: None,
                connections: HashMap::new(),
                accepted_connections: VecDeque::new(),
                streams: HashMap::new(),
                next_conn_id: if config.is_server { 1 } else { 0 },
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
            self.connections.insert(
                conn_id,
                ConnState {
                    handle,
                    acceptor,
                    connected: true,
                },
            );
        }

        fn poll_application(&mut self) -> Result<(), String> {
            if let Some(attempt) = self.pending_connect.as_mut() {
                let result = with_context(|cx| attempt.as_mut().poll(cx));
                match result {
                    Poll::Ready(Ok(connection)) => {
                        self.insert_connection(0, connection);
                        self.pending_connect = None;
                    }
                    Poll::Ready(Err(error)) => return Err(format!("s2n connect: {error:?}")),
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
            }
            Ok(())
        }

        fn drive_all(&mut self, now_us: u64) -> Result<(), String> {
            for _ in 0..8 {
                self.poll_application()?;
                self.with_driver(|driver| driver.drive(now_us))?;
            }
            self.poll_application()
        }

        fn stream_mut(&mut self, conn_id: u64, stream_id: u64) -> Result<&mut StreamState, String> {
            self.streams
                .get_mut(&(conn_id, stream_id))
                .ok_or_else(|| format!("unknown s2n stream {conn_id}/{stream_id}"))
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
            let connect = Connect::new(remote).with_server_name("localhost");
            self.pending_connect = Some(Box::pin(client.connect(connect)));
            self.drive_all(now_us)?;
            Ok(0)
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

        fn receive(&mut self, remote: SocketAddr, data: &[u8], now_us: u64) -> Result<(), String> {
            self.with_driver(|driver| driver.receive(remote, data, now_us))?;
            self.drive_all(now_us)
        }

        fn poll_transmit(
            &mut self,
            now_us: u64,
            out: &mut [u8],
        ) -> Result<Option<(SocketAddr, usize)>, String> {
            self.drive_all(now_us)?;
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

        fn open_bidi(&mut self, conn_id: u64, now_us: u64) -> Result<Option<u64>, String> {
            self.drive_all(now_us)?;
            let Some(conn) = self.connections.get_mut(&conn_id) else {
                return Err(format!("unknown s2n connection {conn_id}"));
            };
            match with_context(|cx| conn.handle.poll_open_bidirectional_stream(cx)) {
                Poll::Ready(Ok(stream)) => {
                    let stream_id = stream.id();
                    self.streams.insert(
                        (conn_id, stream_id),
                        StreamState {
                            stream,
                            pending_rx: VecDeque::new(),
                        },
                    );
                    self.drive_all(now_us)?;
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
                return Err(format!("unknown s2n connection {conn_id}"));
            };
            match with_context(|cx| conn.acceptor.poll_accept_bidirectional_stream(cx)) {
                Poll::Ready(Ok(Some(stream))) => {
                    let stream_id = stream.id();
                    self.streams.insert(
                        (conn_id, stream_id),
                        StreamState {
                            stream,
                            pending_rx: VecDeque::new(),
                        },
                    );
                    Ok(Some(stream_id))
                }
                Poll::Ready(Ok(None)) | Poll::Pending => Ok(None),
                Poll::Ready(Err(error)) => Err(format!("s2n accept stream: {error:?}")),
            }
        }

        fn stream_send(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            data: &[u8],
            now_us: u64,
        ) -> Result<usize, String> {
            self.drive_all(now_us)?;
            let stream = self.stream_mut(conn_id, stream_id)?;
            let ready = with_context(|cx| stream.stream.poll_send_ready(cx));
            let capacity = match ready {
                Poll::Ready(Ok(capacity)) => capacity,
                Poll::Ready(Err(error)) => return Err(format!("s2n stream send ready: {error:?}")),
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
            self.drive_all(now_us)?;
            Ok(len)
        }

        fn stream_recv(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            out: &mut [u8],
            now_us: u64,
        ) -> Result<(usize, bool), String> {
            self.drive_all(now_us)?;
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

            match with_context(|cx| stream.stream.poll_receive(cx)) {
                Poll::Ready(Ok(Some(mut chunk))) => {
                    let len = chunk.len().min(out.len());
                    out[..len].copy_from_slice(&chunk[..len]);
                    if len < chunk.len() {
                        let rest = chunk.split_off(len);
                        stream.pending_rx.push_back(rest);
                    }
                    Ok((len, false))
                }
                Poll::Ready(Ok(None)) => Ok((0, true)),
                Poll::Ready(Err(error)) => Err(format!("s2n stream recv: {error:?}")),
                Poll::Pending => Ok((0, false)),
            }
        }

        fn stream_finish(
            &mut self,
            conn_id: u64,
            stream_id: u64,
            now_us: u64,
        ) -> Result<(), String> {
            let stream = self.stream_mut(conn_id, stream_id)?;
            stream
                .stream
                .finish()
                .map_err(|e| format!("s2n stream finish: {e:?}"))?;
            self.drive_all(now_us)
        }

        fn datagram_send(
            &mut self,
            conn_id: u64,
            data: &[u8],
            now_us: u64,
        ) -> Result<bool, String> {
            self.drive_all(now_us)?;
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
                Poll::Ready(Ok(())) => {
                    self.drive_all(now_us)?;
                    Ok(true)
                }
                Poll::Pending => Ok(false),
                Poll::Ready(Err(error)) => Err(format!("s2n datagram send: {error:?}")),
            }
        }

        fn datagram_recv(
            &mut self,
            conn_id: u64,
            out: &mut [u8],
            now_us: u64,
        ) -> Result<Option<usize>, String> {
            self.drive_all(now_us)?;
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
pub extern "C" fn qpf_last_error() -> *const c_char {
    LAST_ERROR.with(|last_error| {
        last_error
            .borrow()
            .as_ref()
            .map_or(ptr::null(), |message| message.as_ptr())
    })
}
