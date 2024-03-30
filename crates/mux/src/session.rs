use std::cmp::min;

use bitmask_enum::bitmask;

use crate::{
    ring_buf::RingBuf, Error, Flags, FrameBuilder, FrameHeader, FrameHeaderBuilder, FrameType,
    Result,
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
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.len() > self.ring_buf.remaining_mut() {
            return Err(Error::FlowControl);
        }

        assert_eq!(self.ring_buf.write(buf), buf.len());

        Ok(self.ring_buf.remaining_mut())
    }

    /// Returns the length of the received contiguous data.
    fn readable(&self) -> usize {
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
    /// Returns [`Error::InvalidStreamState`] if delta_window_size is zero.
    /// you should first call [`Self::window_size_updatable`] before calling
    /// this function to check if you need to send a `WINDOW_UPDATE_FRAME`.
    fn send_window_update_frame(
        &mut self,
        buf: &mut [u8],
        stream_id: u32,
        flags: Flags,
    ) -> Result<()> {
        if self.delta_window_size == 0 {
            return Err(Error::InvalidStreamState(stream_id));
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
    state: StreamState,
    recv_buf: RecvBuf,
    send_buf: SendBuf,
}

impl Stream {
    /// Create stream object with custom window size.
    fn new(window_size: u32) -> Self {
        Self {
            state: Default::default(),
            recv_buf: RecvBuf::new(window_size),
            send_buf: SendBuf::new(window_size as usize),
        }
    }
}

/// A yamux session type for handling the logical streams.
pub struct Session {}

#[cfg(test)]
mod tests {
    use crate::Frame;

    use super::*;

    #[test]
    fn test_recv_buf() {
        let mut recv_buf = RecvBuf::new(INIT_WINDOW_SIZE * 2);

        assert_eq!(recv_buf.delta_window_size, INIT_WINDOW_SIZE);

        assert_eq!(recv_buf.readable(), 0);

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
}
