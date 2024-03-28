use std::{
    cmp::min,
    collections::{HashMap, HashSet, VecDeque},
};

use bitmask_enum::bitmask;

use crate::{ring_buf::RingBuf, Error, Flags, Frame, InvalidFrameKind, Result};

/// The send buf of stream state.
struct SendBuf {
    /// The peer's recv buf size.
    window_size: u32,
    /// A ring buf to cache contiguous send data.
    inner_buf: RingBuf,
}

impl SendBuf {
    /// Cached sending data into send buf.
    ///
    /// Returns [`Error::Done`], if the stream send buf has no capacity.
    fn cache(&mut self, buf: &[u8]) -> Result<usize> {
        let write_size = self.inner_buf.write(buf);

        if write_size == 0 {
            Err(Error::Done)
        } else {
            Ok(write_size)
        }
    }

    /// Reads contiguous data from the send buf into the provided slice.
    ///
    /// Return [`Error:Done`], if peer's recv window is zero.
    fn read(&mut self) -> Result<Vec<u8>> {
        let read_size = min(self.window_size as usize, self.inner_buf.remaining());

        if read_size == 0 {
            Err(Error::Done)
        } else {
            let mut buf = vec![0; read_size];
            assert_eq!(self.inner_buf.read(&mut buf), read_size);

            Ok(buf)
        }
    }
}

/// The recv buf of stream state.
struct RecvBuf {
    /// Init value is zero.
    delta_window_size: u32,
    /// A ring buf to cache contiguous received data.
    ///
    /// The number returned by function [`remaining_mut`](RingBuf::maintaining_mut) is the real window size.
    inner_buf: RingBuf,
}

impl RecvBuf {
    /// Cache received data of a stream.
    ///
    /// returns [`Error::FlowControl`], when the peer violated the local flow control limits.
    fn cache(&mut self, buf: &[u8]) -> Result<()> {
        if self.inner_buf.remaining_mut() < buf.len() {
            return Err(Error::FlowControl);
        }

        // there is enough space to cache recv data.
        assert_eq!(self.inner_buf.write(buf), buf.len());

        Ok(())
    }

    /// Reads contiguous data from cached into the provided slice.
    ///
    /// On success the amount of bytes read and delta_window_size are returned.
    fn read(&mut self, buf: &mut [u8]) -> Result<(usize, u32)> {
        let read_size = self.inner_buf.read(buf);
        self.delta_window_size += read_size as u32;

        Ok((read_size, self.delta_window_size))
    }

    fn readable(&self) -> bool {
        self.inner_buf.remaining() > 0
    }
}

/// The stream state flags.
#[bitmask(u8)]
enum StreamState {
    /// Set by peer's WINDOW_UPDATE_FRAME/DATA_FRAME with ACK flag.
    ACK,
    /// Init flag. removed by peer's WINDOW_UPDATE_FRAME/DATA_FRAME with FIN flag.
    READ,
    /// Init flag. removed by local's WINDOW_UPDATE_FRAME/DATA_FRAME with FIN flag.
    WRITE,
    /// Added by WINDOW_UPDATE_FRAME/DATA_FRAME with FIN flag.
    ///
    /// This flag should be removed immediately, when local really sent FRAME with FIN flag.
    RST,
}

/// Inner stream object of yamux session.
struct Stream {
    stream_id: u32,
    state: StreamState,
    recv_buf: RecvBuf,
    send_buf: SendBuf,
}

impl Stream {
    /// Create stream object with init window size.
    fn new(window_size: u32, stream_id: u32) -> Self {
        Self {
            stream_id,
            state: StreamState::READ | StreamState::WRITE,
            recv_buf: RecvBuf {
                delta_window_size: 0,
                inner_buf: RingBuf::with_capacity(window_size as usize),
            },
            send_buf: SendBuf {
                window_size,
                inner_buf: RingBuf::with_capacity(window_size as usize),
            },
        }
    }

    /// Cache received data.
    ///
    /// returns [`Error::FlowControl`], when the peer violated the local flow control limits.
    ///
    /// The caller should send a GO_AWAY_FRAME with `Protocol error` immediately, when this function returns [`Error::InvalidStreamState`].
    fn recv(&mut self, buf: &[u8], fin: bool) -> Result<()> {
        if !self.state.contains(StreamState::READ) || self.state.contains(StreamState::RST) {
            return Err(Error::InvalidStreamState(self.stream_id));
        }

        if fin {
            self.state ^= StreamState::READ;
        }

        self.recv_buf.cache(buf)
    }

    /// Read received data from cache buf.
    ///
    /// On success, returns the number of bytes read, the delta_window_size value and the fin flag.
    fn stream_recv(&mut self, buf: &mut [u8]) -> Result<(usize, u32, bool)> {
        let (read_size, delta_window_size) = self.recv_buf.read(buf)?;

        Ok((
            read_size,
            delta_window_size,
            !self.state.contains(StreamState::READ),
        ))
    }

    // Cache sending data in to the send buf.
    /// Returns [`Error::Done`], if the stream send buf has no capacity.
    ///
    /// Returns [`Error::InvalidStreamState`], if the peer has sent *-FRAME with RST flag or the local sent *-FRAME with FIN flag.
    fn stream_send(&mut self, buf: &[u8], fin: bool) -> Result<usize> {
        if !self.state.contains(StreamState::WRITE) || self.state.contains(StreamState::RST) {
            return Err(Error::InvalidStreamState(self.stream_id));
        }

        // No more data can be sent.
        if fin {
            self.state ^= StreamState::WRITE;
        }

        self.send_buf.cache(buf)
    }

    /// Write a single yamux DATA_FRAME body to be sent to the peer.
    ///
    /// This function always returns [`Error::Done`], when the stream has been RST by peer, .
    fn send(&mut self) -> Result<Vec<u8>> {
        if self.state.contains(StreamState::RST) {
            return Err(Error::Done);
        }

        self.send_buf.read()
    }

    /// Test if this stream can be safely removed from session .
    fn is_closed(&self) -> bool {
        if self.state.contains(StreamState::RST) {
            true
        } else if !self.state.contains(StreamState::READ)
            && !self.state.contains(StreamState::WRITE)
            && !self.recv_buf.readable()
        {
            true
        } else {
            false
        }
    }

    /// Test if has already received *-FRAME with FIN flag from peer.
    fn is_fin(&self) -> bool {
        !self.state.contains(StreamState::READ)
    }

    fn update_flags(&mut self, flags: Flags) {}

    fn update_window_size(&mut self, delta: u32) {
        self.send_buf.window_size += delta;
    }
}

/// When a session is being terminated, the Go Away message should be sent.
/// The Length should be set to one of the following to provide an error code:
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Reason {
    Normal,
    ProtocolError,
    InternalError,
    Unknown(u8),
}

impl From<u8> for Reason {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Normal,
            1 => Self::ProtocolError,
            2 => Self::InternalError,
            _ => Self::Unknown(value),
        }
    }
}

impl Into<u8> for Reason {
    fn into(self) -> u8 {
        match self {
            Reason::Normal => 0,
            Reason::ProtocolError => 1,
            Reason::InternalError => 2,
            Reason::Unknown(c) => c,
        }
    }
}

enum SendFrame {
    /// Send DATA_FRAME, associated datas are stream_id and flags.
    Data(u32, Flags),
    /// Send PING_FRAME, associated data is opaque value.
    Ping(u32),
    /// Send PING_FRAME response, associated data is opaque value received with PING_FRAME.
    Pong(u32),

    WindowUpdate {
        stream_id: u32,
        flags: Flags,
        /// delta update to the window size
        delta: u32,
    },
    /// Send GO_AWAY_FRAME to peer with termination error code.
    GoAway(Reason),
}

/// Runtime-independent yamux session state machine implementation.
pub struct Session {
    /// The configured session window size, which may be larger than the default of 256KB.
    window_size: u32,
    /// Stream states by this session.
    states: HashMap<u32, Stream>,
    /// The inbound stream ids that need be acknowledged.
    ack_stream_ids: HashSet<u32>,
    /// SendFrame that are queued for execution.
    send_queue: VecDeque<SendFrame>,
    /// Recived terminated reason from peer or self, carrying by GO_AWAY_FRAME.
    terminated_reason: Option<Reason>,
}

impl Session {
    fn recv_data_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let body = frame
            .body
            .as_ref()
            .expect("Frame parse function already check the body length.");
        let stream_id = frame.header.stream_id();

        let flags = frame.header.flags()?;

        if let Some(stream) = self.states.get_mut(&stream_id) {
            stream.recv(&body, flags.contains(Flags::FIN))?;
            stream.update_flags(flags);
        } else {
            log::error!(target:"DATA_FRAME","stream, id={}, not found",stream_id);
        }

        Ok(())
    }

    fn recv_window_update_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let stream_id = frame.header.stream_id();

        let flags = frame.header.flags()?;

        if let Some(stream) = self.states.get_mut(&stream_id) {
            let delta = frame.header.length();

            log::trace!(target:"WINDOW_UPDATE_FRAME","stream, id={}, update_window={}",stream_id,delta);

            stream.update_window_size(frame.header.length());

            stream.update_flags(flags);
        } else {
            log::error!(target:"WINDOW_UPDATE_FRAME","stream, id={}, not found",stream_id);
        }

        Ok(())
    }

    fn recv_ping_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let stream_id = frame.header.stream_id();

        let flags = frame.header.flags()?;

        if stream_id != 0 {
            // send GO_AWAY_FRAME to peer, and prepare shutdown this session.
            self.send_queue
                .push_front(SendFrame::GoAway(Reason::ProtocolError));

            return Err(Error::InvalidFrame(InvalidFrameKind::SessionId));
        }

        // this is a inbound ping, generate response
        if flags.contains(Flags::SYN) {
            self.send_queue
                .push_front(SendFrame::Pong(frame.header.length()));
        } else {
            // TODO: add meaningful RTT measurement codes, now just drop this response.
        }

        Ok(())
    }

    fn recv_go_way_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let stream_id = frame.header.stream_id();

        if stream_id != 0 {
            // What else can I do? It's already said goodbye to me.
            log::error!(target:"GO_AWAY_FRAME","received GO_AWAY_FRAME via non-session stream, stream_id={}",stream_id);
        }

        self.terminated_reason = Some((frame.header.length() as u8).into());

        Ok(())
    }
}

impl Session {
    /// Processes one FRAME received from the peer.
    pub fn recv(&mut self, buf: &[u8]) -> Result<usize> {
        let (frame, read_size) = Frame::parse(buf)?;

        match frame.header.frame_type()? {
            crate::FrameType::Data => self.recv_data_frame(&frame)?,
            crate::FrameType::WindowUpdate => self.recv_window_update_frame(&frame)?,
            crate::FrameType::Ping => self.recv_ping_frame(&frame)?,
            crate::FrameType::GoAway => self.recv_go_way_frame(&frame)?,
        }

        Ok(read_size)
    }

    /// Write a new frame to send to peer.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize> {
        while let Some(send_frame) = self.send_queue.pop_front() {
            match send_frame {
                SendFrame::Data(_, _) => todo!(),
                SendFrame::Ping(_) => todo!(),
                SendFrame::Pong(_) => todo!(),
                SendFrame::WindowUpdate {
                    stream_id,
                    flags,
                    delta,
                } => todo!(),
                SendFrame::GoAway(_) => todo!(),
            }
        }

        Err(Error::Done)
    }
}
