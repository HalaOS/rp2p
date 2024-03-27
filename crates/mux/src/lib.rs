use std::{
    cmp::min,
    collections::{HashMap, HashSet, VecDeque},
};

use bitmask_enum::bitmask;

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

/// The yamux frame message type.
pub struct Frame {
    header: FrameHeader,
    body: Vec<u8>,
}

/// Half close status of a stream.
#[bitmask(u8)]
enum HalfClose {
    /// Received fin frame from peer, indicated that all data has sent from peer.
    ///
    /// Relying on the reliable stream underneath, we receive frames from peers in an ordered sequence,
    /// so when we see the `fin` frame, we can safely switch the state of the stream to read half close
    Read,
    /// Set this flag when call [`stream_send`](YamuxSession::stream_send) with the fin flag set to true.
    Write,
}

/// A ring buf implementation for stream send/recv buf.
#[derive(Default)]
struct RingBuf {
    memory: Vec<u8>,
    chunk_offset: usize,
    chunk_mut_offset: usize,
}

impl RingBuf {
    /// Create ring buf with fixed `capacity`.
    fn with_capacity(fixed: usize) -> Self {
        Self {
            memory: vec![0; fixed],
            ..Default::default()
        }
    }

    /// Returns the number of bytes can be read.
    fn remaining(&self) -> usize {
        self.chunk_mut_offset - self.chunk_offset
    }

    /// Returns the number of bytes that can be written from the current
    /// position until the end of the buffer is reached.
    fn remaining_mut(&self) -> usize {
        self.chunk_offset + self.memory.len() - self.chunk_mut_offset
    }

    /// Write data into ring buf.
    ///
    /// Returns the number of written bytes.
    /// the number of written bytes returned can be lower than the length of the
    /// input buffer when the ring buf doesn’t have enough capacity.
    fn write(&mut self, buf: &[u8]) -> usize {
        let max_written = min(self.remaining_mut(), buf.len());

        if self.chunk_mut_offset % self.memory.len() > self.chunk_offset % self.memory.len() {
            let chunk_mut_offset = self.chunk_mut_offset % self.memory.len();
            let write_to_end = self.memory.len() - chunk_mut_offset;

            let written_size = min(write_to_end, max_written);

            self.memory[chunk_mut_offset..chunk_mut_offset + written_size]
                .copy_from_slice(&buf[..written_size]);

            if written_size < max_written {
                let next_written = max_written - write_to_end;

                if next_written > 0 {
                    self.memory[..next_written].copy_from_slice(&buf[written_size..max_written]);
                }
            }
        } else if max_written > 0 {
            let chunk_mut_offset = self.chunk_mut_offset % self.memory.len();

            self.memory[chunk_mut_offset..chunk_mut_offset + max_written]
                .copy_from_slice(&buf[..max_written]);
        }

        self.chunk_mut_offset += max_written;

        max_written
    }

    /// Read data from ring buf.
    ///
    /// Returns the number of read bytes.
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let max_read = min(self.remaining(), buf.len());

        if self.chunk_offset % self.memory.len() > self.chunk_mut_offset % self.memory.len() {
            let chunk_offset = self.chunk_offset % self.memory.len();
            let read_to_end = self.memory.len() - chunk_offset;

            let read_size = min(read_to_end, max_read);

            buf[..read_size].copy_from_slice(&self.memory[chunk_offset..chunk_offset + read_size]);

            if read_size < max_read {
                let next_read_size = max_read - read_size;

                buf[read_size..max_read].copy_from_slice(&self.memory[..next_read_size]);
            }
        } else if max_read > 0 {
            let chunk_offset = self.chunk_offset % self.memory.len();
            buf[..max_read].copy_from_slice(&self.memory[chunk_offset..chunk_offset + max_read]);
        }

        self.chunk_offset += max_read;

        max_read
    }
}

/// Receive-side stream buffer.
///
/// Stream data received by the peer is buffered in a list of data chunks
/// ordered by offset in ascending order. Contiguous data can then be read
/// into a slice.
#[allow(unused)]
struct RecvBuf {
    /// When Yamux is initially starts each stream with a 256KB window size. There is no window size for the session stream(stream_id=0).
    flow_control_window_size: u32,

    /// ring buf initial with fixed size is 256 * 1024
    ring_buf: RingBuf,
}

/// Send-side stream buffer.
///
/// Stream data scheduled to be sent to the peer is buffered in a list of data
/// chunks ordered by offset in ascending order. Contiguous data can then be
/// read into a slice.
struct SendBuf {
    /// Peer's receive window size.
    ///
    /// when this value is 0, call the [`stream_send`](YamuxSession::stream_send) function
    /// will always returns [`Done`](Error::Done).
    flow_control_window_size: u32,

    /// ring buf initial with fixed size is 256 * 1024
    ring_buf: RingBuf,
}

/// The stream's inner state, managed by [`YamuxSession`].
///
/// Once both sides have sent a frame with fin flag, the stream is closed and
/// immediately removed from the session.
///
/// Alternatively, if an error occurs, the RST flag can be used to hard close a stream immediately.
///
/// Whenever a frame with the RST flag is sent or received,
/// the data stream is hard closed and immediately removed from the session.
#[allow(unused)]
struct StreamState {
    half_close_flags: HalfClose,
    recv_buf: RecvBuf,
    send_buf: SendBuf,
}

/// Variant for sending data.
#[allow(unused)]
#[derive(Debug)]
enum SendFrame {
    ///  Signals the start of a new stream.
    SYN(u32),
    /// Acknowledges the start of a new stream
    ACK(u32),
    /// Performs a half-close of a stream. May be sent with a data message or window update.
    FIN(u32),
    /// Reset a stream immediately, outstanding data in the stream’s send buffer is dropped and
    /// outstanding data in the stream’s receive buffer is dropped also.
    RST(u32),
    /// Send outstanding data in the stream’s send buffer.
    Send(u32),
    /// Send ping frame.
    Ping(u32),
}

/// A state machine type to represent a yamux session
#[allow(unused)]
pub struct YamuxSession {
    /// The initial receive window size for the data stream.
    stream_window_size: usize,
    /// The next outbound stream id value.
    next_outbound_stream_id: u32,
    /// The ACK backlog is defined as the number of streams that a
    /// peer has opened which have not yet been acknowledged.
    backlog: usize,
    /// unacknowledged inbound streams
    unack_inbound_stream_ids: HashSet<u32>,
    /// Opened stream states table.
    states: HashMap<u32, StreamState>,
    /// The queueing send frames.
    send_queue: VecDeque<SendFrame>,
}

#[allow(unused)]
impl YamuxSession {
    /// Processes one ***YAMUX*** frame received from the peer.
    ///
    /// Splitting coalesced packets is not the responsibility of
    /// this function and should be handled manually by yourself.
    pub fn recv(&mut self, frame: Frame) -> Result<()> {
        match frame.header.frame_type {
            FrameType::Data => todo!(),
            FrameType::WindowUpdate => todo!(),
            FrameType::Ping => todo!(),
            FrameType::GoAway => todo!(),
        }
        todo!()
    }

    /// Writes a single ***YAMUX*** frame to be sent to the peer.
    pub fn send(&mut self) -> Result<Frame> {
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
    /// [`send()`](Self::send) should be called after reading.
    pub fn stream_recv(&mut self, stream_id: u32, buf: &mut [u8]) -> Result<(usize, bool)> {
        todo!()
    }

    /// To hard close a stream immediately.
    ///
    /// This operation may trigger queueing of control messages (e.g. Window Update) with the RST flag.
    /// [`send()`](Self::send) should be called after close.
    pub fn stream_close(&mut self, stream_id: u32) -> Result<()> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::RingBuf;

    #[test]
    fn test_ring_buf() {
        let capacity = 1024;
        let mut ring_buf = RingBuf::with_capacity(capacity);

        assert_eq!(ring_buf.remaining(), 0);
        assert_eq!(ring_buf.remaining_mut(), capacity);

        // write data out of range.

        assert_eq!(ring_buf.write(&vec![1; capacity * 2]), ring_buf.remaining());

        assert_eq!(ring_buf.remaining(), capacity);
        assert_eq!(ring_buf.remaining_mut(), 0);

        let mut buf = vec![0; capacity / 2];

        assert_eq!(ring_buf.read(&mut buf), capacity / 2);

        assert_eq!(buf, vec![1; capacity / 2]);

        assert_eq!(ring_buf.write(&vec![2; capacity / 4]), capacity / 4);

        let mut buf = vec![0; capacity / 2];

        assert_eq!(ring_buf.read(&mut buf), capacity / 2);

        assert_eq!(buf, vec![1; capacity / 2]);

        let mut buf = vec![0; capacity / 8];

        assert_eq!(ring_buf.read(&mut buf), capacity / 8);

        assert_eq!(buf, vec![2; capacity / 8]);

        assert_eq!(ring_buf.remaining_mut(), 7 * capacity / 8);

        assert_eq!(ring_buf.write(&vec![3; capacity * 10]), 7 * capacity / 8);

        assert_eq!(ring_buf.remaining_mut(), 0);

        assert_eq!(ring_buf.remaining(), capacity);

        let mut buf = vec![0; capacity / 8];

        assert_eq!(ring_buf.read(&mut buf), capacity / 8);

        assert_eq!(buf, vec![2; capacity / 8]);

        assert_eq!(ring_buf.remaining_mut(), capacity / 8);

        assert_eq!(ring_buf.remaining(), 7 * capacity / 8);

        let mut buf = vec![0; capacity * 10];

        assert_eq!(ring_buf.read(&mut buf), 7 * capacity / 8);

        assert_eq!(buf[..7 * capacity / 8], vec![3; 7 * capacity / 8]);
    }
}
