use std::collections::{HashMap, HashSet};

/// The yamux error type.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("No more data to read/write.")]
    Done,

    #[error("The stream({0}) has already been stopped by the peer's RST frame.")]
    StreamStopped(u32),
}

/// Type alias of [`std::result::Result<T,Error>`]
pub type Result<T> = std::result::Result<T, Error>;

/// The type field is used to switch the frame message type. The following message types are supported:
/// - 0x0 Data - Used to transmit data. May transmit zero length payloads depending on the flags.
/// - 0x1 Window Update - Used to updated the senders receive window size. This is used to implement per-session flow control.
/// - 0x2 Ping - Used to measure RTT. It can also be used to heart-beat and do keep-alives over TCP.
/// - 0x3 Go Away - Used to close a session.
#[repr(u8)]
#[derive(Debug)]
pub enum FrameType {
    Data,
    WindowUpdate,
    Ping,
    GoAway,
}

/// The flags field is used to provide additional information related to the message type. The following flags are supported:
/// - 0x1 SYN - Signals the start of a new stream. May be sent with a data or window update message. Also sent with a ping to indicate outbound.
/// - 0x2 ACK - Acknowledges the start of a new stream. May be sent with a data or window update message. Also sent with a ping to indicate response.
/// - 0x4 FIN - Performs a half-close of a stream. May be sent with a data message or window update.
/// - 0x8 RST - Reset a stream immediately. May be sent with a data or window update message.
#[bitmask_enum::bitmask(u16)]
pub enum Flags {
    SYN,
    ACK,
    FIN,
    RST,
}

/// When a session is being terminated, the Go Away message should be sent.
/// The Length should be set to one of the following to provide an error code:
#[repr(u8)]
pub enum SessionTermination {
    Normal = 0,
    ProtocolError,
    InternalError,
}

/// Yamux uses a streaming connection underneath, but imposes a message framing so that it can be shared between many logical streams. Each frame contains a header like:
/// - Version (8 bits)
/// - Type (8 bits)
/// - Flags (16 bits)
/// - StreamID (32 bits)
/// - Length (32 bits)
#[repr(C)]
pub struct FrameHeader {
    /// The version field is used for future backward compatibility.
    /// At the current time, the field is always set to 0, to indicate the initial version.
    pub version: u8,
    /// See [`FrameType`] for more information.
    pub frame_type: FrameType,
    /// See [`Flags`] for more information.
    pub flags: Flags,
    /// The StreamID field is used to identify the logical stream the frame is addressing.
    /// The client side should use odd ID's, and the server even. This prevents any collisions.
    /// Additionally, the 0 ID is reserved to represent the session.
    ///
    /// Both Ping and Go Away messages should always use the 0 StreamID.
    pub stream_id: u32,
    /// The meaning of the length field depends on the message type:
    /// - Data - provides the length of bytes following the header
    /// - Window update - provides a delta update to the window size
    /// - Ping - Contains an opaque value, echoed back
    /// - Go Away - Contains an error code
    pub length: u32,
}

impl std::fmt::Display for FrameHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "frame, version={}, frame_type={:?}, flags=0x{:#010b}, stream_id={}, length={}",
            self.version, self.frame_type, self.flags, self.stream_id, self.length
        )
    }
}

struct StreamState {}

/// A state machine type to represent a yamux session
#[allow(unused)]
pub struct YamuxSession {
    /// The next outbound stream id value.
    next_outbound_stream_id: u32,
    /// The ACK backlog is defined as the number of streams that a
    /// peer has opened which have not yet been acknowledged.
    backlog: usize,
    /// unacknowledged inbound streams
    unack_inbound_stream_ids: HashSet<u32>,
    /// Opened stream states table.
    states: HashMap<u32, StreamState>,
}

#[allow(unused)]
impl YamuxSession {
    /// Processes ***YAMUX*** packets received from the peer.
    ///
    /// On success the number of bytes processed from the input buffer is returned.
    pub fn recv(&mut self, buf: &[u8]) -> Result<usize> {
        todo!()
    }

    /// Writes a single ***YAMUX*** packet to be sent to the peer.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize> {
        todo!()
    }

    /// Returns an iterator over streams that have outstanding data to read.
    ///
    /// Note that the iterator will only include streams that were readable
    /// at the time the iterator itself was created (i.e. when readable() was called).
    /// To account for newly readable streams, the iterator needs to be created again.
    pub fn readable(&self) -> impl Iterator<Item = u32> {
        vec![].into_iter()
    }

    /// Returns an iterator over streams that can be written in priority order.
    ///
    /// A “writable” stream is a stream that has enough flow control capacity to send data to the peer.
    /// To avoid buffering an infinite amount of data,
    /// streams are only allowed to buffer outgoing data up to the amount that the peer allows to send.
    ///
    /// Note that the iterator will only include streams that were writable at the time the iterator
    /// itself was created (i.e. when writable() was called). To account for newly writable streams,
    /// the iterator needs to be created again.
    pub fn writable(&self) -> impl Iterator<Item = u32> {
        vec![].into_iter()
    }

    /// Writes data to a stream.
    ///
    /// On success the number of bytes written is returned,
    /// or Done if no data was written (e.g. because the stream has no capacity).
    ///
    /// Applications can provide a 0-length buffer with the fin flag set to true.
    /// This will lead to a window update frame along with the FIN flag being sent at the latest offset.
    /// The Ok(0) value is only returned when the application provided a 0-length buffer.
    ///
    /// In addition, if the peer has signalled that it doesn’t want to receive any more data from this stream
    /// by sending the window update frame with RST flag, the StreamStopped error will be returned instead of any data.
    pub fn stream_send(&mut self, stream_id: u32, buf: &[u8], fin: bool) -> Result<usize> {
        todo!()
    }

    /// Reads contiguous data from a stream into the provided slice.
    ///
    /// The slice must be sized by the caller and will be populated up to its capacity.
    ///
    /// On success the amount of bytes read and a flag indicating the fin state is returned as a tuple,
    /// or Done if there is no data to read.
    ///
    /// Reading data from a stream may trigger queueing of control messages (e.g. Window Update).
    /// send() should be called after reading.
    pub fn stream_recv(&mut self, stream_id: u32, buf: &mut [u8]) -> Result<(usize, bool)> {
        todo!()
    }

    /// To hard close a stream immediately.
    ///
    /// This operation my trigger queueing of control messages (e.g. Window Update) with the RST flag.
    /// send() should be called after close.
    pub fn stream_close(&mut self, stream_id: u32) -> Result<()> {
        todo!()
    }
}
