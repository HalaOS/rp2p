use std::{
    cmp::min,
    collections::{HashMap, VecDeque},
};

use bitmask_enum::bitmask;

use crate::{
    ring_buf::RingBuf, Error, Flags, Frame, FrameBuilder, FrameHeaderBuilder, FrameType, Result,
};

/// When Yamux is initially starts each stream with a 256KB window size.
const INIT_WINDOW_SIZE: u32 = 256 * 1024;

/// A buffer for stream received data.
struct RecvBuf {
    ///  The current window size of the receive buffer for this stream.
    delta_window_size: u32,
    /// The inner [`RingBuf`] of the receive buffer for this stream.
    ring_buf: RingBuf,
}

impl RecvBuf {
    /// Create [`RecvBuf`] with custom `window_size`, which must be greater than or equal to [`INIT_WINDOW_SIZE`].
    fn new(window_size: u32) -> Self {
        Self {
            // cause panic, if window_size < `INIT_WINDOW_SIZE`.
            delta_window_size: window_size - INIT_WINDOW_SIZE,
            ring_buf: RingBuf::with_capacity(window_size as usize),
        }
    }
    /// Write contiguous data into the receive buffer received from peer.
    ///
    /// Returns [`Error::FlowControl`], if the peer violated the local flow control limits.
    ///
    /// On success, returns the remaining receive buffer capacity.
    ///
    /// This function has no effects on delta_window_size.
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.len() > self.ring_buf.remaining_mut() {
            return Err(Error::FlowControl);
        }

        assert_eq!(self.ring_buf.write(buf), buf.len());

        Ok(self.ring_buf.remaining_mut())
    }

    /// Returns the length of the received contiguous data.
    fn remaining(&self) -> usize {
        self.ring_buf.remaining()
    }

    /// Reads contiguous data from the `RecvBuf` into the provided slice.
    ///
    /// On success the amount of bytes read is returned, or [`Error::Done`] if there is no data to read.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read_size = min(buf.len(), self.ring_buf.remaining());

        if read_size == 0 {
            return Err(Error::Done);
        }

        assert_eq!(self.ring_buf.read(buf), read_size);

        self.delta_window_size += read_size as u32;

        Ok(read_size)
    }

    /// Write a new `WINDOW_UPDATE_FRAME` into the provided slice.
    ///
    /// The length fo the provided slice must be greater than or equal to 12,
    /// otherwise returns [`Error::BufferTooShort`].
    ///
    /// Returns [`Error::Done`] if delta_window_size is zero.
    /// you should first call [`Self::window_size_updatable`] before calling
    /// this function to check if you need to send a `WINDOW_UPDATE_FRAME`.
    fn send_window_update_frame(
        &mut self,
        buf: &mut [u8],
        stream_id: u32,
        flags: Flags,
    ) -> Result<()> {
        if self.delta_window_size == 0 {
            return Err(Error::Done);
        }

        if buf.len() < 12 {
            return Err(Error::BufferTooShort(12));
        }

        let buf: &mut [u8; 12] = (&mut buf[0..12]).try_into().unwrap();

        let _ = FrameBuilder::new_with(buf)
            .stream_id(stream_id)
            .frame_type(FrameType::WindowUpdate)
            .flags(flags)
            .length(self.delta_window_size)
            // This function must be called to check the frame header constraints.
            .create_without_body()?;

        self.delta_window_size = 0;

        Ok(())
    }

    fn window_size_updatable(&self) -> bool {
        self.delta_window_size > 0
    }
}

/// A buffer for stream sending data.
struct SendBuf {
    window_size: u32,
    ring_buf: RingBuf,
}

impl SendBuf {
    /// Create [`SendBuf`] with ring buffer `length`, that must be greater than or equal to [`INIT_WINDOW_SIZE`]
    fn new(length: usize) -> Self {
        assert!(length >= INIT_WINDOW_SIZE as usize);

        Self {
            // As the spec description, the initial window size must be 256KB.
            window_size: INIT_WINDOW_SIZE,
            ring_buf: RingBuf::with_capacity(length),
        }
    }

    /// Create new `DATA_FRAME` to be sent to peer.
    ///
    /// Returns [`Error::None`], if there are no more packets to send or reached the peer's flow control limits.
    /// you should call `create_data_frame()` multiple times until Done is returned.
    fn send_data_frame(&mut self, buf: &mut [u8], stream_id: u32, flags: Flags) -> Result<usize> {
        let max_read_len = min(self.window_size, self.ring_buf.remaining() as u32);
        if max_read_len == 0 {
            return Err(Error::Done);
        }

        if buf.len() < 12 {
            return Err(Error::BufferTooShort(12));
        }

        let read_len = min(max_read_len, buf.len() as u32 - 12);

        if read_len == 0 {
            return Err(Error::BufferTooShort(max_read_len));
        }

        let header_buf: &mut [u8; 12] = (&mut buf[..12]).try_into().unwrap();

        FrameHeaderBuilder::with(header_buf)
            .stream_id(stream_id)
            .flags(flags)
            .frame_type(FrameType::Data)
            .length(read_len)
            .valid()
            .unwrap();

        // only track the number of bytes sent in Data body.
        self.window_size -= read_len;

        let read_len = read_len as usize + 12;

        assert_eq!(self.ring_buf.read(&mut buf[12..read_len]), read_len - 12);

        Ok(read_len)
    }

    /// Tests if a `DATA_FRAME` can be sent.
    fn sendable(&self) -> bool {
        min(self.window_size, self.ring_buf.remaining() as u32) > 0
    }

    /// Test if the send buf has enough capacity.
    fn writable(&self) -> bool {
        self.ring_buf.remaining_mut() > 0
    }

    /// Writes new data into send buffer.
    ///
    /// On success, returns the amount of bytes written.
    /// or [`Done`](Error::Done) if no data was written (because the send buffer has no capacity).
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.ring_buf.remaining_mut() == 0 {
            return Err(Error::Done);
        }

        Ok(self.ring_buf.write(buf))
    }

    /// A delta update to the window size
    fn update_window_size(&mut self, delta: u32) {
        self.window_size += delta;
    }
}

#[bitmask(u8)]
enum StreamState {
    /// Default flag bit at creation
    Read,
    /// Default flag bit at creation
    Write,
    /// Reset flag, set by local or peer.
    Reset,
    /// Syn flag, set by local.
    Syn,
    /// Acknowledged flag, set by local or peer.
    Ack,
}

impl Default for StreamState {
    fn default() -> Self {
        Self::Read | Self::Write
    }
}

/// A logical stream type.
struct Stream {
    stream_id: u32,
    state: StreamState,
    recv_buf: RecvBuf,
    send_buf: SendBuf,
}

impl Stream {
    /// Create `stream` with custom window size.
    fn new(stream_id: u32, window_size: u32) -> Self {
        Self {
            stream_id,
            state: Default::default(),
            recv_buf: RecvBuf::new(window_size),
            send_buf: SendBuf::new(window_size as usize),
        }
    }

    /// Check if nees send WINDOW_UPDATE_FRAME frame.
    fn window_size_updatable(&self) -> bool {
        self.recv_buf.window_size_updatable()
    }

    ///Create new `WINDOW_UPDATE_FRAME` to be sent to peer.
    ///
    /// The length fo the provided slice must be greater than or equal to 12,
    /// otherwise returns [`Error::BufferTooShort`].
    ///
    /// Returns [`Error::Done`] if delta_window_size is zero.
    /// you should first call [`Self::window_size_updatable`] before calling
    /// this function to check if you need to send a `WINDOW_UPDATE_FRAME`.
    fn send_window_size_update_frame(&mut self, buf: &mut [u8], mut flags: Flags) -> Result<()> {
        if flags.contains(Flags::ACK) {
            self.state |= StreamState::Ack;
        }

        if !self.state.contains(StreamState::Syn) {
            self.state |= StreamState::Syn;
            flags |= Flags::SYN;
        }

        self.recv_buf
            .send_window_update_frame(buf, self.stream_id, flags)
    }

    /// Create new `DATA_FRAME` to be sent to peer.
    ///
    /// Returns [`Error::None`], if there are no more packets to send or reached the peer's flow control limits.
    /// you should call `create_data_frame()` multiple times until Done is returned.
    fn send_data_frame(&mut self, buf: &mut [u8], mut flags: Flags) -> Result<usize> {
        if flags.contains(Flags::ACK) {
            self.state |= StreamState::Ack;
        }

        if !self.state.contains(StreamState::Syn) {
            self.state |= StreamState::Syn;
            flags |= Flags::SYN;
        }

        self.send_buf.send_data_frame(buf, self.stream_id, flags)
    }

    /// Receive a window update frame from peer.
    fn recv_window_update_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let flags = frame.header.flags()?;
        self.update_flags(flags)?;

        self.send_buf.update_window_size(frame.header.length());

        Ok(())
    }

    /// Receive a data frame from peer.
    ///
    /// Returns [`Error::InvalidFrame`], if the frame's body is [`None`].
    ///
    /// The caller must terminate the session immediately when this function returns error.
    fn recv_data_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let flags = frame.header.flags()?;

        self.update_flags(flags)?;

        if let Some(body) = &frame.body {
            self.recv_buf.write(body)?;
        } else {
            return Err(Error::InvalidFrame(crate::InvalidFrameKind::Body));
        }

        Ok(())
    }

    fn update_flags(&mut self, flags: Flags) -> Result<()> {
        if flags.contains(Flags::ACK) {
            if self.state.contains(StreamState::Ack) {
                log::error!("ACK same stream twice, stream_id={}", self.stream_id);
                return Err(Error::InvalidStreamState(self.stream_id));
            }

            self.state |= StreamState::Ack;
        }

        if flags.contains(Flags::FIN) {
            if !self.state.contains(StreamState::Read) {
                log::error!("FIN same stream twice, stream_id={}", self.stream_id);
                return Err(Error::InvalidStreamState(self.stream_id));
            }

            self.state ^= StreamState::Read;
        }

        if flags.contains(Flags::RST) {
            if self.state.contains(StreamState::Reset) {
                log::error!("RST same stream twice, stream_id={}", self.stream_id);
                return Err(Error::InvalidStreamState(self.stream_id));
            }

            self.state |= StreamState::Reset;
        }

        Ok(())
    }

    /// Test if the stream has enough send capacity.
    fn writable(&self) -> bool {
        self.send_buf.writable()
    }

    /// Test if the stream has data that can be read.
    fn readable(&self) -> bool {
        self.recv_buf.remaining() > 0
    }

    /// Writes new data into send buffer.
    ///
    /// On success, returns the amount of bytes written.
    /// or [`Done`](Error::Done) if no data was written (because the send buffer has no capacity).
    ///
    /// Returns [`Error::InvalidStreamState`], When the fin flag is set for a second time.
    fn send(&mut self, buf: &[u8], fin: bool) -> Result<usize> {
        if fin {
            if !self.state.contains(StreamState::Write) {
                log::error!("Set fin flag twice, stream_id={}", self.stream_id);
                return Err(Error::FinalSize(self.stream_id));
            }

            self.state ^= StreamState::Write;
        } else if !self.state.contains(StreamState::Write) {
            log::error!("Send data after set fin flag, stream_id={}", self.stream_id);
            return Err(Error::FinalSize(self.stream_id));
        }

        self.send_buf.write(buf)
    }

    /// Reads contiguous data from the `RecvBuf` into the provided slice.
    ///
    /// On success the amount of bytes read is returned, or [`Error::Done`] if there is no data to read.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.recv_buf.recv(buf)
    }

    /// Returns true if all the data has been read from the specified stream.
    ///
    /// This instructs the application that all the data received from the peer on the stream has been read, and there won’t be anymore in the future.
    ///
    /// Basically this returns true when the peer either set the fin flag for the stream, or sent RST_FRAME.
    fn is_finished(&self) -> bool {
        if self.recv_buf.remaining() > 0 {
            return false;
        }

        if !self.state.contains(StreamState::Read) || self.state.contains(StreamState::Reset) {
            return true;
        }

        return false;
    }
}

enum SendFrame {
    Ping(u32),
    Pong(u32),
    WindowUpdate { stream_id: u32, flags: Flags },
    Data { stream_id: u32, flags: Flags },
    GoAway(Reason),
}

/// Session terminated reason.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
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
            Reason::Unknown(v) => v,
        }
    }
}

/// A yamux session type for handling the logical streams.
pub struct Session {
    /// Session configured window size.
    window_size: u32,
    /// next oubtound stream id.
    next_outbound_stream_id: u32,
    /// incoming stream ids that have not yet been acknowledged.
    incoming_stream_ids: VecDeque<u32>,
    /// the streams handle by this session.
    streams: HashMap<u32, Stream>,
    /// Queue of frames waiting to be sent to peer.
    send_frames: VecDeque<SendFrame>,
    /// session terminated reason.
    terminated: Option<Reason>,
}

impl Session {
    fn recv_inner(&mut self, buf: &[u8]) -> Result<usize> {
        let (frame, read_size) = Frame::parse(buf)?;

        let frame_type = frame.header.frame_type()?;

        match frame_type {
            FrameType::Data => self.recv_data_frame(&frame)?,
            FrameType::WindowUpdate => self.recv_window_update_frame(&frame)?,
            FrameType::Ping => self.recv_ping_frame(&frame)?,
            FrameType::GoAway => self.recv_go_away_frame(&frame)?,
        }

        Ok(read_size)
    }

    fn recv_data_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let stream_id = frame.header.stream_id();

        let flags = frame.header.flags()?;

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.recv_data_frame(frame)?;
        } else {
            if flags.contains(Flags::SYN) {
                let mut stream = Stream::new(stream_id, self.window_size);
                stream.recv_data_frame(frame)?;

                if stream.window_size_updatable() {
                    self.send_frames.push_back(SendFrame::WindowUpdate {
                        stream_id,
                        flags: Flags::ACK,
                    });
                }
            } else {
                // terminate the session.
                self.send_frames
                    .push_back(SendFrame::GoAway(Reason::ProtocolError));
                // terminate recv loop
                return Err(Error::InvalidState);
            }
        }

        Ok(())
    }

    fn recv_window_update_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let stream_id = frame.header.stream_id();

        let flags = frame.header.flags()?;

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.recv_data_frame(frame)?;
        } else {
            if flags.contains(Flags::SYN) {
                let mut stream = Stream::new(stream_id, self.window_size);
                stream.recv_window_update_frame(frame)?;

                if stream.window_size_updatable() {
                    self.send_frames.push_back(SendFrame::WindowUpdate {
                        stream_id,
                        flags: Flags::ACK,
                    });
                }
            } else {
                // terminate the session.
                self.send_frames
                    .push_back(SendFrame::GoAway(Reason::ProtocolError));
                // terminate recv loop
                return Err(Error::InvalidState);
            }
        }

        Ok(())
    }

    fn recv_ping_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let stream_id = frame.header.stream_id();

        if stream_id != 0 {
            // terminate the session.
            self.send_frames
                .push_back(SendFrame::GoAway(Reason::ProtocolError));

            log::error!("received ping message via non-session id({})", stream_id);
            // terminate recv loop
            return Err(Error::InvalidState);
        }

        let flags = frame.header.flags()?;

        // indicate inbound ping
        if flags.contains(Flags::SYN) {
            self.send_frames
                .push_back(SendFrame::Pong(frame.header.length()));
        } else {
            // TODO: check ping result.
        }

        Ok(())
    }

    fn recv_go_away_frame<'a>(&mut self, frame: &Frame<'a>) -> Result<()> {
        let stream_id = frame.header.stream_id();

        if stream_id != 0 {
            // terminate the session.
            self.send_frames
                .push_back(SendFrame::GoAway(Reason::ProtocolError));

            log::error!("received go away message via non-session id({})", stream_id);
            // terminate recv loop
            return Err(Error::InvalidState);
        }

        self.terminated = Some((frame.header.length() as u8).into());

        Ok(())
    }

    fn verify_session_status(&self) -> Result<()> {
        if self.terminated.is_some() {
            Err(Error::InvalidState)
        } else {
            Ok(())
        }
    }

    fn send_ping(&mut self, buf: &mut [u8], opaque: u32) -> Result<usize> {
        let buf: &mut [u8; 12] = buf.try_into().unwrap();

        FrameBuilder::new_with(buf)
            .stream_id(0)
            .flags(Flags::SYN)
            .frame_type(FrameType::Ping)
            .length(opaque)
            .create_without_body()?;

        Ok(12)
    }

    fn send_pong(&mut self, buf: &mut [u8], opaque: u32) -> Result<usize> {
        let buf: &mut [u8; 12] = buf.try_into().unwrap();

        FrameBuilder::new_with(buf)
            .stream_id(0)
            .flags(Flags::ACK)
            .frame_type(FrameType::Ping)
            .length(opaque)
            .create_without_body()?;

        Ok(12)
    }

    fn send_window_size(&mut self, buf: &mut [u8], stream_id: u32, flags: Flags) -> Result<usize> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.send_window_size_update_frame(buf, flags)?;
            Ok(12)
        } else {
            Err(Error::Done)
        }
    }

    /// Returns [`Error::Done`] if stream not found.
    fn send_data(&mut self, buf: &mut [u8], stream_id: u32, flags: Flags) -> Result<usize> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let read_size = stream.send_data_frame(buf, flags)?;
            Ok(read_size)
        } else {
            Err(Error::Done)
        }
    }

    fn send_go_away(&mut self, buf: &mut [u8], reason: Reason) -> Result<usize> {
        self.terminated = Some(reason);

        let buf: &mut [u8; 12] = buf.try_into().unwrap();

        let reason_u8: u8 = reason.into();

        FrameBuilder::new_with(buf)
            .stream_id(0)
            .frame_type(FrameType::GoAway)
            .length(reason_u8 as u32)
            .create_without_body()?;

        Ok(12)
    }
}

impl Session {
    /// Create new session with custom window size.
    pub fn new(window_size: u32, is_server: bool) -> Self {
        assert!(window_size >= INIT_WINDOW_SIZE);

        Self {
            window_size,
            next_outbound_stream_id: if is_server { 2 } else { 1 },
            incoming_stream_ids: Default::default(),
            streams: Default::default(),
            send_frames: Default::default(),
            terminated: None,
        }
    }

    /// Write new data received from peer.
    pub fn recv(&mut self, buf: &[u8]) -> Result<usize> {
        self.verify_session_status()?;

        match self.recv_inner(buf) {
            Ok(read_size) => Ok(read_size),
            Err(err) => {
                // self.terminated = Some(Reason::ProtocolError);
                self.send_frames
                    .push_back(SendFrame::GoAway(Reason::ProtocolError));

                return Err(err);
            }
        }
    }

    /// Write new frame to be sent to peer.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.verify_session_status()?;

        if buf.len() < 12 {
            return Err(Error::BufferTooShort(12));
        }

        while let Some(send_frame) = self.send_frames.pop_front() {
            match send_frame {
                SendFrame::Ping(opaque) => return self.send_ping(buf, opaque),
                SendFrame::Pong(opaque) => return self.send_pong(buf, opaque),
                SendFrame::WindowUpdate { stream_id, flags } => {
                    match self.send_window_size(buf, stream_id, flags) {
                        Err(Error::Done) => continue,
                        r => return r,
                    }
                }
                SendFrame::Data { stream_id, flags } => {
                    match self.send_data(buf, stream_id, flags) {
                        Err(Error::Done) => continue,
                        r => return r,
                    }
                }
                SendFrame::GoAway(reason) => return self.send_go_away(buf, reason),
            }
        }

        Err(Error::Done)
    }

    pub fn stream_send(&mut self, stream_id: u32, buf: &[u8], fin: bool) -> Result<usize> {
        self.verify_session_status()?;

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let write_size = stream.send(buf, fin)?;

            if write_size > 0 {}

            Ok(write_size)
        } else {
            return Err(Error::InvalidStreamState(stream_id));
        }
    }

    pub fn stream_recv(&mut self, stream_id: u32, buf: &mut [u8]) -> Result<(usize, bool)> {
        self.verify_session_status()?;

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let read_size = stream.recv(buf)?;

            return Ok((read_size, stream.is_finished()));
        } else {
            return Err(Error::InvalidStreamState(stream_id));
        }
    }

    pub fn stream_writable(&self, stream_id: u32) -> Result<bool> {
        Ok(self
            .streams
            .get(&stream_id)
            .ok_or(Error::InvalidStreamState(stream_id))?
            .writable())
    }

    /// Open a new outbound stream.
    pub fn open(&mut self) -> Result<u32> {
        self.verify_session_status()?;

        let stream_id = self.next_outbound_stream_id;

        self.next_outbound_stream_id += 2;

        let stream = Stream::new(stream_id, self.window_size);

        if stream.window_size_updatable() {
            self.send_frames.push_back(SendFrame::WindowUpdate {
                stream_id,
                flags: Flags::SYN,
            });
        }

        self.streams.insert(stream_id, stream);

        Ok(stream_id)
    }

    pub fn accept(&mut self) -> Result<Option<u32>> {
        self.verify_session_status()?;
        Ok(self.incoming_stream_ids.pop_front())
    }

    /// Returns an iterator over streams that have outstanding data to read.
    pub fn readable(&self) -> impl Iterator<Item = u32> + '_ {
        self.streams
            .iter()
            .filter(|(_, stream)| stream.readable())
            .map(|(id, _)| *id)
    }

    /// Returns an iterator over streams that can be written i
    pub fn writable(&self) -> impl Iterator<Item = u32> + '_ {
        self.streams
            .iter()
            .filter(|(_, stream)| stream.writable())
            .map(|(id, _)| *id)
    }
}

#[cfg(test)]
mod tests {
    use crate::Frame;

    use super::*;

    #[test]
    fn test_recv_buf() {
        let mut recv_buf = RecvBuf::new(INIT_WINDOW_SIZE * 2);

        assert_eq!(recv_buf.delta_window_size, INIT_WINDOW_SIZE);

        assert_eq!(recv_buf.remaining(), 0);

        assert_eq!(
            recv_buf.write(&[0x0a; 100]).unwrap(),
            (INIT_WINDOW_SIZE * 2 - 100) as usize
        );

        assert_eq!(
            recv_buf
                .send_window_update_frame(&mut [0; 11], 1, Flags::SYN)
                .unwrap_err(),
            Error::BufferTooShort(12)
        );

        let mut buf = [0; 12];

        recv_buf
            .send_window_update_frame(&mut buf, 1, Flags::SYN)
            .unwrap();

        let (frame, _) = Frame::parse(&buf).unwrap();

        let flags = frame.header.flags().unwrap();

        flags.contains(Flags::SYN);

        assert_eq!(frame.header.frame_type().unwrap(), FrameType::WindowUpdate);

        assert_eq!(frame.header.stream_id(), 1);

        assert_eq!(frame.header.length(), INIT_WINDOW_SIZE);

        assert_eq!(recv_buf.delta_window_size, 0);
    }

    #[test]
    fn test_send_buf() {
        let mut send_buf = SendBuf::new(INIT_WINDOW_SIZE as usize * 2);

        // the initial window size must be 256KB.
        assert_eq!(send_buf.window_size, INIT_WINDOW_SIZE);

        let write_size = send_buf
            .write(vec![0xau8; INIT_WINDOW_SIZE as usize * 3].as_slice())
            .unwrap();

        assert_eq!(write_size, INIT_WINDOW_SIZE as usize * 2);

        // The `write()` function has no effects on window size.
        assert_eq!(send_buf.window_size, INIT_WINDOW_SIZE);

        let mut buf = vec![0x0; INIT_WINDOW_SIZE as usize * 2 + 12];

        let send_size = send_buf
            .send_data_frame(&mut buf, 1, Flags::none())
            .unwrap();

        assert_eq!(send_size, INIT_WINDOW_SIZE as usize + 12);

        let (frame, len) = Frame::parse(&buf).unwrap();
        assert_eq!(len, send_size);

        assert_eq!(frame.header.stream_id(), 1);
        assert_eq!(frame.header.frame_type().unwrap(), FrameType::Data);
        assert_eq!(frame.header.length(), INIT_WINDOW_SIZE);
        assert_eq!(frame.body.unwrap(), vec![0xau8; INIT_WINDOW_SIZE as usize]);

        assert_eq!(send_buf.window_size, 0);
        send_buf.update_window_size(INIT_WINDOW_SIZE);
        assert_eq!(send_buf.window_size, INIT_WINDOW_SIZE);

        let mut buf = vec![0x0; INIT_WINDOW_SIZE as usize * 2 + 12];

        let send_size = send_buf
            .send_data_frame(&mut buf, 1, Flags::none())
            .unwrap();

        assert_eq!(send_size, INIT_WINDOW_SIZE as usize + 12);

        let (frame, len) = Frame::parse(&buf).unwrap();
        assert_eq!(len, send_size);

        assert_eq!(frame.header.stream_id(), 1);
        assert_eq!(frame.header.frame_type().unwrap(), FrameType::Data);
        assert_eq!(frame.header.length(), INIT_WINDOW_SIZE);
        assert_eq!(frame.body.unwrap(), vec![0xau8; INIT_WINDOW_SIZE as usize]);

        assert_eq!(send_buf.window_size, 0);
    }

    #[test]
    fn test_stream() {
        let stream = Stream::new(1, INIT_WINDOW_SIZE);

        assert!(stream.state.contains(StreamState::Read));
        assert!(stream.state.contains(StreamState::Write));
        assert!(!stream.is_finished());

        assert!(!stream.window_size_updatable());

        let mut stream = Stream::new(1, INIT_WINDOW_SIZE * 2);

        assert!(stream.window_size_updatable());

        let mut buf = vec![0; 12];

        stream
            .send_window_size_update_frame(&mut buf, Flags::ACK | Flags::FIN)
            .unwrap();

        assert!(!stream.window_size_updatable());

        let (frame, _) = Frame::parse(&buf).unwrap();

        assert_eq!(frame.header.frame_type().unwrap(), FrameType::WindowUpdate);

        let flags = frame.header.flags().unwrap();

        assert!(flags.contains(Flags::ACK));
        assert!(flags.contains(Flags::FIN));

        assert_eq!(frame.header.length(), INIT_WINDOW_SIZE);

        // test read data.
        assert!(!stream.readable());

        assert!(stream.state.contains(StreamState::Ack));

        let frame = FrameBuilder::new()
            .flags(Flags::none())
            .frame_type(FrameType::Data)
            .stream_id(1)
            .create(vec![0xa; 20])
            .unwrap();

        stream.recv_data_frame(&frame).unwrap();

        assert!(stream.state.contains(StreamState::Ack));

        let frame = FrameBuilder::new()
            .flags(Flags::ACK)
            .frame_type(FrameType::Data)
            .stream_id(1)
            .create(vec![0xa; 20])
            .unwrap();

        stream.recv_data_frame(&frame).expect_err("Recv ack twice.");

        assert!(stream.readable());

        let mut buf = vec![0; 10];

        assert_eq!(stream.recv(&mut buf).unwrap(), buf.len());

        assert_eq!(buf, vec![0x0a; 10]);

        let mut buf = vec![0; 30];

        assert_eq!(stream.recv(&mut buf).unwrap(), 10);

        assert_eq!(buf[0..10], vec![0x0a; 10]);

        assert_eq!(stream.recv(&mut buf).unwrap_err(), Error::Done);

        assert!(stream.writable());

        assert_eq!(
            stream.send_data_frame(&mut buf, Flags::RST).unwrap_err(),
            Error::Done
        );

        stream.send(&[0x10; 100], false).unwrap();

        let mut buf = vec![0x0; 92];

        stream.send_data_frame(&mut buf, Flags::none()).unwrap();

        let (frame, _) = Frame::parse(&buf).unwrap();

        assert_eq!(frame.header.frame_type().unwrap(), FrameType::Data);

        assert_eq!(frame.header.length(), 80);

        assert_eq!(frame.body.unwrap(), vec![0x10; 80]);

        let mut buf = vec![0x0; 92];

        assert_eq!(stream.send_data_frame(&mut buf, Flags::none()).unwrap(), 32);

        let (frame, _) = Frame::parse(&buf).unwrap();

        assert_eq!(frame.body.unwrap(), vec![0x10; 20]);

        assert_eq!(
            stream.send_data_frame(&mut buf, Flags::RST).unwrap_err(),
            Error::Done
        );

        assert_eq!(
            stream
                .send(&[0x10; INIT_WINDOW_SIZE as usize * 3], true)
                .unwrap(),
            INIT_WINDOW_SIZE as usize * 2
        );
    }
}
