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

    #[error("Call stream_send on stream({0}) after setting the fin flag.")]
    FinalSize(u32),

    #[error("Unexpect Go away code {0}")]
    UnknownGoAwayCode(u8),

    #[error("Session terminated by peer with code: {0}")]
    Terminated(GoAway),

    #[error("Stream not exist or has been closed.")]
    InvalidStreamState(u32),
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
#[derive(Debug, Clone, Copy)]
pub enum GoAway {
    Normal,
    ProtocolError,
    InternalError,
}

impl std::fmt::Display for GoAway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GoAway(0x{:#02x})", *self as u8)
    }
}

impl TryFrom<u8> for GoAway {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::ProtocolError),
            2 => Ok(Self::InternalError),
            _ => Err(Error::UnknownGoAwayCode(value)),
        }
    }
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

/// Stream status flags.
#[bitmask(u8)]
enum StreamFlags {
    READ,
    WRITE,
    ACK,
    RST,
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
    /// ring buf initial with fixed size is 256 * 1024
    ring_buf: RingBuf,
}

impl RecvBuf {
    /// Write data received from peer into recv ring buf.
    ///
    /// Returns false, if the ring_buf has overflowed.
    fn write(&mut self, buf: &[u8]) -> bool {
        if self.ring_buf.remaining_mut() > buf.len() {
            return false;
        }

        assert_eq!(self.ring_buf.write(buf), buf.len());

        true
    }
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

impl SendBuf {
    /// write data into send buf, calling this function has no effects on `flow_control_window_size`.
    fn write(&mut self, buf: &[u8]) -> usize {
        self.ring_buf.write(buf)
    }

    /// Read data from the ring buf, and decrease the flow_control_window_size.
    fn send(&mut self) -> Option<Vec<u8>> {
        let send_buf_len = min(
            self.ring_buf.remaining(),
            self.flow_control_window_size as usize,
        );

        if send_buf_len == 0 {
            return None;
        }

        let mut send_buf = vec![0; send_buf_len];

        assert_eq!(self.ring_buf.read(&mut send_buf), send_buf_len);

        self.flow_control_window_size -= send_buf_len as u32;

        Some(send_buf)
    }

    /// Increase peer's recv window size.
    ///
    /// Returns true, if data needs to send.
    fn update_window_size(&mut self, delta: u32) -> bool {
        self.flow_control_window_size += delta;

        let send_buf_len = min(
            self.ring_buf.remaining(),
            self.flow_control_window_size as usize,
        );

        send_buf_len > 0
    }
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
struct StreamState {
    flags: StreamFlags,
    recv_buf: RecvBuf,
    send_buf: SendBuf,
}

const INIT_WINDOW_SIZE: u32 = 256 * 1024;

impl StreamState {
    fn new(stream_window_size: u32) -> Self {
        Self {
            flags: StreamFlags::READ | StreamFlags::WRITE,
            recv_buf: RecvBuf {
                ring_buf: RingBuf::with_capacity(stream_window_size as usize),
            },
            send_buf: SendBuf {
                flow_control_window_size: INIT_WINDOW_SIZE,
                ring_buf: RingBuf::with_capacity(stream_window_size as usize),
            },
        }
    }
}

/// Variant for sending data.
#[allow(unused)]
#[derive(Debug)]
enum SendFrame {
    /// Send outstanding data in the stream’s send buffer.
    Data { stream_id: u32, flags: Flags },

    WindowUpdate {
        stream_id: u32,
        delta: u32,
        flags: Flags,
    },
    /// Send ping frame.
    Ping(u32),
    /// Send ping response.
    Pong(u32),
    /// Send go away frame to terminate this session.
    GoAway(GoAway),
}

/// A state machine type to represent a yamux session
pub struct YamuxSession {
    /// The initial receive window size for the data stream.
    stream_window_size: u32,
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
    /// The ping that is waiting response.
    active_ping_id: Option<u32>,
    /// Flag is set when a GoAway frame is received or is sent,
    /// after that all operations should return [`Error::Terminated`].
    go_away: Option<GoAway>,
}

impl YamuxSession {
    fn check_session_status(&self) -> Result<()> {
        if let Some(session_termination) = self.go_away {
            Err(Error::Terminated(session_termination))
        } else {
            Ok(())
        }
    }

    fn get_stream_mut(&mut self, stream_id: u32) -> Result<&mut StreamState> {
        self.states
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamState(stream_id))
    }

    fn handle_flags(&mut self, header: &FrameHeader) -> Result<bool> {
        // handle SYN flag
        if header.flags.contains(Flags::SYN) {
            if let FrameType::Ping = header.frame_type {
                if header.stream_id != 0 {
                    self.send_queue
                        .push_front(SendFrame::GoAway(GoAway::ProtocolError));

                    log::error!(
                        "SYN: send a ping using a non-session stream({})",
                        header.stream_id
                    );

                    return Ok(false);
                }

                return Ok(true);
            }
            // Check that stream already exists, send go away frame to terminate this session.
            if self.states.contains_key(&header.stream_id) {
                self.send_queue
                    .push_front(SendFrame::GoAway(GoAway::ProtocolError));

                return Ok(false);
            }

            self.states
                .insert(header.stream_id, StreamState::new(self.stream_window_size));

            // Yamux is configured provide a larger limit for window size that sends window update immediately.
            if self.stream_window_size > INIT_WINDOW_SIZE {
                let delta = self.stream_window_size - INIT_WINDOW_SIZE;

                self.send_queue.push_back(SendFrame::WindowUpdate {
                    stream_id: header.stream_id,
                    delta,
                    flags: Flags::ACK,
                })
            }

            // Otherwise, place the stream ID in the queue of not yet been acknowledged streams.
            self.unack_inbound_stream_ids.insert(header.stream_id);
        }

        if header.flags.contains(Flags::ACK) {
            if let FrameType::Ping = header.frame_type {
                if header.stream_id != 0 {
                    self.send_queue
                        .push_front(SendFrame::GoAway(GoAway::ProtocolError));

                    log::error!(
                        "ACK: send a ping using a non-session stream({})",
                        header.stream_id
                    );

                    return Ok(false);
                }

                return Ok(true);
            }

            if let Some(stream_state) = self.states.get_mut(&header.stream_id) {
                if stream_state.flags.contains(StreamFlags::ACK) {
                    log::error!(
                        "ACK: stream({}) had already been acknowledged.",
                        header.stream_id
                    );
                    self.send_queue
                        .push_back(SendFrame::GoAway(GoAway::ProtocolError));

                    return Ok(false);
                }

                if stream_state.flags.contains(StreamFlags::RST) {
                    log::error!("ACK: stream({}) had already been RST.", header.stream_id);
                    self.send_queue
                        .push_back(SendFrame::GoAway(GoAway::ProtocolError));

                    return Ok(false);
                }

                stream_state.flags = stream_state.flags | StreamFlags::ACK;
            } else {
                log::error!("ACK: stream({}) not found.", header.stream_id);
            }
        }

        if header.flags.contains(Flags::FIN) {
            if let FrameType::Ping = header.frame_type {
                self.send_queue
                    .push_front(SendFrame::GoAway(GoAway::ProtocolError));

                log::error!("FIN: send fin with ping",);

                return Ok(false);
            }

            if let Some(stream_state) = self.states.get_mut(&header.stream_id) {
                if !stream_state.flags.contains(StreamFlags::ACK) {
                    log::error!("FIN: stream({}) fin without ACK.", header.stream_id);
                    self.send_queue
                        .push_back(SendFrame::GoAway(GoAway::ProtocolError));

                    return Ok(false);
                }

                if stream_state.flags.contains(StreamFlags::RST) {
                    log::error!("FIN: stream({}) had already been RST.", header.stream_id);
                    self.send_queue
                        .push_back(SendFrame::GoAway(GoAway::ProtocolError));

                    return Ok(false);
                }

                stream_state.flags = stream_state.flags.xor(StreamFlags::READ);
            } else {
                log::error!("FIN: stream({}) not found.", header.stream_id);
            }
        }

        if header.flags.contains(Flags::RST) {
            if let FrameType::Ping = header.frame_type {
                self.send_queue
                    .push_front(SendFrame::GoAway(GoAway::ProtocolError));

                log::error!("RST: send rst with ping",);

                return Ok(false);
            }
            if let Some(stream_state) = self.states.get_mut(&header.stream_id) {
                stream_state.flags = stream_state.flags | StreamFlags::RST;
            } else {
                log::error!("RST: stream({}) not found.", header.stream_id);
            }
        }

        Ok(true)
    }

    fn handle_data(&mut self, frame: Frame) -> Result<()> {
        let state = self.get_stream_mut(frame.header.stream_id)?;

        if state.recv_buf.write(&frame.body) {
            return Ok(());
        }

        // stream recv window is overflow, send go away message.
        self.send_queue
            .push_back(SendFrame::GoAway(GoAway::ProtocolError));

        Ok(())
    }

    fn handle_window_update(&mut self, frame: Frame) -> Result<()> {
        let state = self.get_stream_mut(frame.header.stream_id)?;

        if state.send_buf.update_window_size(frame.header.length) {
            self.send_data_frame(frame.header.length);
        }

        Ok(())
    }

    /// Create new data [`SendFrame`] for `stream_id`
    fn send_data_frame(&mut self, stream_id: u32) {
        let mut needs_send_frame = true;
        for send_frame in &self.send_queue {
            if let SendFrame::Data {
                stream_id: id,
                flags: _,
            } = send_frame
            {
                if *id == stream_id {
                    needs_send_frame = false;
                }
            }
        }

        if needs_send_frame {
            let mut flags = Flags::none();

            if self.unack_inbound_stream_ids.remove(&stream_id) {
                flags |= Flags::ACK;
            }

            self.send_queue
                .push_back(SendFrame::Data { stream_id, flags })
        }
    }

    fn handle_ping(&mut self, frame: Frame) -> Result<()> {
        if let Some(ping_id) = self.active_ping_id {
            // this is a response frame of active ping, complete it.
            if frame.header.length == ping_id {
                // TODO: measure rtt.
                return Ok(());
            }
        } else {
            // queue pong frame.
            self.send_queue
                .push_back(SendFrame::Pong(frame.header.length));
        }

        Ok(())
    }

    fn handle_go_away(&mut self, frame: Frame) -> Result<()> {
        let flag = GoAway::try_from(frame.header.length as u8)?;

        log::info!("yamux: peer go away, code={:?}", flag);

        self.go_away = Some(flag);

        Err(Error::Terminated(flag))
    }

    fn send_ping(&mut self, opaque: u32) -> Frame {
        let header = FrameHeader {
            version: 0,
            frame_type: FrameType::Ping,
            flags: Flags::SYN,
            stream_id: 0,
            length: opaque,
        };

        Frame {
            header,
            body: vec![],
        }
    }

    fn send_pong(&mut self, opaque: u32) -> Frame {
        let header = FrameHeader {
            version: 0,
            frame_type: FrameType::Ping,
            flags: Flags::ACK,
            stream_id: 0,
            length: opaque,
        };

        Frame {
            header,
            body: vec![],
        }
    }

    fn send_go_away(&mut self, go_away: GoAway) -> Frame {
        let header = FrameHeader {
            version: 0,
            frame_type: FrameType::GoAway,
            flags: Flags::ACK,
            stream_id: 0,
            length: go_away as u8 as u32,
        };

        Frame {
            header,
            body: vec![],
        }
    }

    fn send_data(&mut self, stream_id: u32, flags: Flags) -> Option<Frame> {
        if let Some(stream_state) = self.states.get_mut(&stream_id) {
            let frame = stream_state.send_buf.send().map(|body| {
                let header = FrameHeader {
                    version: 0,
                    flags,
                    stream_id,
                    length: body.len() as u32,
                    frame_type: FrameType::Data,
                };

                Frame { header, body }
            });

            frame
        } else {
            None
        }
    }

    fn send_window_update(&mut self, stream_id: u32, delta: u32, flags: Flags) -> Frame {
        let header = FrameHeader {
            version: 0,
            flags,
            frame_type: FrameType::WindowUpdate,
            stream_id,
            length: delta,
        };

        Frame {
            header,
            body: vec![],
        }
    }
}

impl YamuxSession {
    /// Processes one ***YAMUX*** frame received from the peer.
    ///
    /// Splitting coalesced packets is not the responsibility of
    /// this function and should be handled manually by yourself.
    pub fn recv(&mut self, frame: Frame) -> Result<()> {
        self.check_session_status()?;

        if !self.handle_flags(&frame.header)? {
            return Ok(());
        }

        match frame.header.frame_type {
            FrameType::Data => self.handle_data(frame),
            FrameType::WindowUpdate => self.handle_window_update(frame),
            FrameType::Ping => self.handle_ping(frame),
            FrameType::GoAway => self.handle_go_away(frame),
        }
    }

    /// Writes a single ***YAMUX*** frame to be sent to the peer.
    ///
    /// Returns [`None`] if there are no frames to send.
    pub fn send(&mut self) -> Result<Option<Frame>> {
        self.check_session_status()?;

        while let Some(frame) = self.send_queue.pop_front() {
            match frame {
                SendFrame::Data { stream_id, flags } => {
                    if let Some(frame) = self.send_data(stream_id, flags) {
                        return Ok(Some(frame));
                    }

                    continue;
                }
                SendFrame::WindowUpdate {
                    stream_id,
                    delta,
                    flags,
                } => return Ok(Some(self.send_window_update(stream_id, delta, flags))),
                SendFrame::Ping(opaque) => return Ok(Some(self.send_ping(opaque))),
                SendFrame::Pong(opaque) => return Ok(Some(self.send_pong(opaque))),
                SendFrame::GoAway(go_way) => return Ok(Some(self.send_go_away(go_way))),
            }
        }

        Ok(None)
    }

    /// Returns an iterator over streams that have outstanding data to read.
    ///
    /// Note that the iterator will only include streams that were readable
    /// at the time the iterator itself was created (i.e. when readable() was called).
    /// To account for newly readable streams, the iterator needs to be created again.
    pub fn readable(&self) -> impl Iterator<Item = u32> {
        if self.check_session_status().is_err() {
            return vec![].into_iter();
        }

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
        if self.check_session_status().is_err() {
            return vec![].into_iter();
        }

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
        let stream_state = self
            .states
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamState(stream_id))?;

        if !stream_state.flags.contains(StreamFlags::WRITE) {
            return Err(Error::FinalSize(stream_id));
        }

        if fin {
            stream_state.flags ^= StreamFlags::WRITE;
        }

        Ok(stream_state.send_buf.write(buf))
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
        self.check_session_status()?;
        todo!()
    }

    /// To hard close a stream immediately.
    ///
    /// This operation may trigger queueing of control messages (e.g. Window Update) with the RST flag.
    /// [`send()`](Self::send) should be called after close.
    pub fn stream_close(&mut self, stream_id: u32) -> Result<()> {
        self.check_session_status()?;
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
