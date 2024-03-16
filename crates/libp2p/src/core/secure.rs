/// # Overview
///
/// Before two peers can transmit data, the communication channel they establish needs to be secured.
/// By design, libp2p supports many different transports (TCP, QUIC, WebSocket, WebTransport, etc.).
/// Some transports have built-in encryption at the transport layer like QUIC,
/// while other transports (e.g. TCP, WebSocket) lack native security and require a security handshake
/// after the transport connection has been established.
pub trait SecureUpgrade: Sync + Send {}

#[derive(Default)]
pub struct TlsHandshake {}

impl SecureUpgrade for TlsHandshake {}
