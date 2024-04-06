use std::{
    borrow::Cow,
    ops::{Deref, DerefMut},
};

use bitmask_enum::bitmask;

use crate::{Error, FrameRestrictionKind, InvalidFrameKind, Result};

/// The type field is used to switch the frame message type. The following message types are supported:
/// - 0x0 Data - Used to transmit data. May transmit zero length payloads depending on the flags.
/// - 0x1 Window Update - Used to updated the senders receive window size. This is used to implement per-session flow control.
/// - 0x2 Ping - Used to measure RTT. It can also be used to heart-beat and do keep-alives over TCP.
/// - 0x3 Go Away - Used to close a session.
#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum FrameType {
    Data,
    WindowUpdate,
    Ping,
    GoAway,
}

impl TryFrom<u8> for FrameType {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(FrameType::Data),
            1 => Ok(FrameType::WindowUpdate),
            2 => Ok(FrameType::Ping),
            3 => Ok(FrameType::GoAway),
            _ => Err(Error::InvalidFrame(InvalidFrameKind::FrameType)),
        }
    }
}

/// The flags field is used to provide additional information related to the message type. The following flags are supported:
/// - 0x1 SYN - Signals the start of a new stream. May be sent with a data or window update message. Also sent with a ping to indicate outbound.
/// - 0x2 ACK - Acknowledges the start of a new stream. May be sent with a data or window update message. Also sent with a ping to indicate response.
/// - 0x4 FIN - Performs a half-close of a stream. May be sent with a data message or window update.
/// - 0x8 RST - Reset a stream immediately. May be sent with a data or window update message.
#[bitmask(u16)]
pub enum Flags {
    SYN,
    ACK,
    FIN,
    RST,
}

/// Yamux uses a streaming connection underneath, but imposes a message framing so that it can be shared between many logical streams. Each frame contains a header like:
/// - Version (8 bits)
/// - Type (8 bits)
/// - Flags (16 bits)
/// - StreamID (32 bits)
/// - Length (32 bits)
#[derive(Debug)]
pub enum FrameHeader<'a> {
    Borrowed(&'a [u8; 12]),
    Owned([u8; 12]),
}

impl<'a> From<&'a [u8; 12]> for FrameHeader<'a> {
    fn from(value: &'a [u8; 12]) -> Self {
        Self::Borrowed(value)
    }
}

impl<'a> FrameHeader<'a> {
    /// use [`FrameBuilder`] to create new `Frame` instance step by step.

    /// Get yamux verson field, should always returns 0.
    pub fn version(&self) -> u8 {
        match self {
            FrameHeader::Borrowed(buf) => buf[0],
            FrameHeader::Owned(buf) => buf[0],
        }
    }

    /// Parse frame type field.
    ///
    /// Return [`Error::InvalidFrame`] with associated data [`InvalidFrameKind::FrameType`], if the frame type field can't be parsed.
    pub fn frame_type(&self) -> Result<FrameType> {
        match self {
            FrameHeader::Borrowed(buf) => buf[1].try_into(),
            FrameHeader::Owned(buf) => buf[1].try_into(),
        }
    }

    /// Parse flags field.
    ///
    /// Return [`Error::InvalidFrame`] with associated data [`InvalidFrameKind::Flags`], if the flags field can't be parsed.
    pub fn flags(&self) -> Result<Flags> {
        let bits = match self {
            FrameHeader::Borrowed(buf) => buf[2..4].try_into().unwrap(),
            FrameHeader::Owned(buf) => buf[2..4].try_into().unwrap(),
        };

        let bits = u16::from_be_bytes(bits);

        let flags = Flags::from(bits);

        if flags != flags.truncate() {
            return Err(Error::InvalidFrame(InvalidFrameKind::Flags));
        }

        Ok(flags)
    }

    /// Returns stream id field.
    pub fn stream_id(&self) -> u32 {
        let bits = match self {
            FrameHeader::Borrowed(buf) => buf[4..8].try_into().unwrap(),
            FrameHeader::Owned(buf) => buf[4..8].try_into().unwrap(),
        };

        u32::from_be_bytes(bits)
    }

    /// Returns length field value.
    pub fn length(&self) -> u32 {
        let bits = match self {
            FrameHeader::Borrowed(buf) => buf[8..12].try_into().unwrap(),
            FrameHeader::Owned(buf) => buf[8..12].try_into().unwrap(),
        };

        u32::from_be_bytes(bits)
    }
}

/// A builder for [`FrameHeader`]
pub struct FrameHeaderBuilder<'a>(&'a mut [u8; 12]);

impl<'a> FrameHeaderBuilder<'a> {
    /// Create header builder with provided buf.
    pub fn with(buf: &'a mut [u8; 12]) -> Self {
        Self(buf)
    }

    /// Set type type field value, the default value is [`FrameType::Data`]
    pub fn frame_type(self, frame_type: FrameType) -> Self {
        self.0[1] = frame_type as u8;
        self
    }

    /// Set frame header flags field, encoded in network order(big endian).
    ///
    /// The default value is None.
    pub fn flags(self, flags: Flags) -> Self {
        self.0[2..4].copy_from_slice(flags.bits.to_be_bytes().as_slice());

        self
    }

    /// Set frame header stream_id field, encoded in network order(big endian).
    ///
    /// The default value is session stream_id(0).
    pub fn stream_id(self, stream_id: u32) -> Self {
        self.0[4..8].copy_from_slice(stream_id.to_be_bytes().as_slice());

        self
    }

    /// Set frame header stream_id field, encoded in network order(big endian).
    ///
    /// The meaning of the length field depends on the message type:
    /// - Data - provides the length of bytes following the header
    /// - Window update - provides a delta update to the window size
    /// - Ping - Contains an opaque value, echoed back
    /// - Go Away - Contains an error code
    pub fn length(self, length: u32) -> Self {
        self.0[8..12].copy_from_slice(length.to_be_bytes().as_slice());

        self
    }

    pub fn valid(self) -> Result<&'a mut [u8; 12]> {
        let header = FrameHeader::Borrowed(self.0);

        let flags = header.flags()?;

        match header.frame_type()? {
            FrameType::Ping => {
                // FIN and RST flags are not allowed in PING_FRAME.
                if flags.contains(Flags::FIN) || flags.contains(Flags::RST) {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::Body));
                }

                if header.stream_id() != 0 {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::SessionId));
                }
            }
            FrameType::GoAway => {
                // The flags field of GO_AWAY_FRAME must none.
                if !flags.is_none() {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::Body));
                }

                if header.stream_id() != 0 {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::SessionId));
                }
            }
            _ => {
                if header.stream_id() == 0 {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::SessionId));
                }
            }
        }
        Ok(self.0)
    }
}

/// A builder to create new frame instance.
pub enum FrameBuilder<'a> {
    Borrowed(&'a mut [u8; 12]),
    Owned([u8; 12]),
}

impl<'a> Deref for FrameBuilder<'a> {
    type Target = [u8; 12];
    fn deref(&self) -> &Self::Target {
        match self {
            FrameBuilder::Borrowed(buf) => *buf,
            FrameBuilder::Owned(buf) => buf,
        }
    }
}

impl<'a> DerefMut for FrameBuilder<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            FrameBuilder::Borrowed(buf) => *buf,
            FrameBuilder::Owned(buf) => buf,
        }
    }
}

impl FrameBuilder<'static> {
    pub fn new() -> FrameBuilder<'static> {
        FrameBuilder::Owned([0; 12])
    }
}
impl<'a> FrameBuilder<'a> {
    pub fn new_with(buf: &'a mut [u8; 12]) -> FrameBuilder<'a> {
        FrameBuilder::Borrowed(buf)
    }

    /// Set type type field value, the default value is [`FrameType::Data`]
    pub fn frame_type(mut self, frame_type: FrameType) -> Self {
        FrameHeaderBuilder::with(&mut self).frame_type(frame_type);
        self
    }

    /// Set frame header flags field, encoded in network order(big endian).
    ///
    /// The default value is None.
    pub fn flags(mut self, flags: Flags) -> Self {
        FrameHeaderBuilder::with(&mut self).flags(flags);

        self
    }

    /// Set frame header stream_id field, encoded in network order(big endian).
    ///
    /// The default value is session stream_id(0).
    pub fn stream_id(mut self, stream_id: u32) -> Self {
        FrameHeaderBuilder::with(&mut self).stream_id(stream_id);

        self
    }

    /// Set frame header stream_id field, encoded in network order(big endian).
    ///
    /// The meaning of the length field depends on the message type:
    /// - Data - provides the length of bytes following the header
    /// - Window update - provides a delta update to the window size
    /// - Ping - Contains an opaque value, echoed back
    /// - Go Away - Contains an error code
    pub fn length(mut self, length: u32) -> Self {
        FrameHeaderBuilder::with(&mut self).length(length);

        self
    }

    /// Consume self and create [`Frame`] instance with provided body data.
    ///
    /// Returns [Error::FrameRestriction], if call this function with frame_type is not [`FrameType::Data`]
    pub fn create<B: Into<Cow<'a, [u8]>>>(self, body: B) -> Result<Frame<'a>> {
        let header = FrameHeader::Borrowed(&self);

        if header.frame_type()? != FrameType::Data {
            return Err(Error::FrameRestriction(FrameRestrictionKind::Body));
        }

        if header.stream_id() == 0 {
            return Err(Error::FrameRestriction(FrameRestrictionKind::SessionId));
        }

        let body: Cow<'a, [u8]> = body.into();

        let this = self.length(body.len() as u32);

        Ok(Frame {
            header: this.into_header(),
            body: Some(body),
        })
    }

    fn into_header(self) -> FrameHeader<'a> {
        match self {
            FrameBuilder::Borrowed(buf) => FrameHeader::Borrowed(buf),
            FrameBuilder::Owned(buf) => FrameHeader::Owned(buf),
        }
    }

    /// Consume self and create [`Frame`] instance without frame body.
    ///
    /// This function will check the frame_type,
    /// Data frame is not allowed to call this function, use [`create`](Self::create) instead.
    pub fn create_without_body(self) -> Result<Frame<'a>> {
        let header = self.into_header();

        let flags = header.flags()?;

        match header.frame_type()? {
            FrameType::Ping => {
                // FIN and RST flags are not allowed in PING_FRAME.
                if flags.contains(Flags::FIN) || flags.contains(Flags::RST) {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::Body));
                }

                if header.stream_id() != 0 {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::SessionId));
                }
            }
            FrameType::GoAway => {
                // The flags field of GO_AWAY_FRAME must none.
                if !flags.is_none() {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::Body));
                }

                if header.stream_id() != 0 {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::SessionId));
                }
            }
            _ => {
                if header.stream_id() == 0 {
                    return Err(Error::FrameRestriction(FrameRestrictionKind::SessionId));
                }
            }
        }

        if header.frame_type()? == FrameType::Data {
            return Err(Error::FrameRestriction(FrameRestrictionKind::Body));
        }

        Ok(Frame { header, body: None })
    }
}

/// Yamux frame type.
///
/// You can frame instance using the [`build`](Self::build) function or the [`parse`](Self::parse) function.
#[derive(Debug)]
pub struct Frame<'a> {
    /// frame header fileds.
    pub header: FrameHeader<'a>,
    /// frame body buf.
    pub body: Option<Cow<'a, [u8]>>,
}

impl<'a> Frame<'a> {
    /// Create new [`FrameBuilder`] instance to build `Frame` instance.
    pub fn build() -> FrameBuilder<'static> {
        FrameBuilder::new()
    }

    /// create new [`FrameBuilder`] instance with provided buf to build `Frame` instance.
    pub fn build_with(buf: &'a mut [u8; 12]) -> FrameBuilder<'a> {
        FrameBuilder::Borrowed(buf)
    }

    /// Parse frame from input contiguous data.
    ///
    /// Returns [`Error::BufferTooShort`],if the input buf too short to parse a whole frame,
    /// The caller should check for associated data about the error, then read enough data and retry again.
    ///
    /// On success, returns parsed frame and the number of bytes processed from the input buffer.
    pub fn parse(buf: &'a [u8]) -> Result<(Frame<'a>, usize)> {
        if buf.len() < 12 {
            return Err(Error::BufferTooShort(12));
        }

        // Safety: we already check buf.len() >= 12.
        let head_buf: &[u8] = &buf[..12];
        // no need clone/copy the slice, we get a &[u8;12].
        let head_buf: &[u8; 12] = head_buf.try_into().unwrap();
        // convert array &[u8;12] to `FrameHeader`
        let header: FrameHeader<'_> = FrameHeader::from(head_buf);

        let frame_type = header.frame_type()?;

        let (body, frame_len) = if frame_type == FrameType::Data {
            let frame_len = header.length() as usize + 12;

            if buf.len() < frame_len {
                return Err(Error::BufferTooShort(frame_len as u32));
            }

            if frame_len == 12 {
                return Err(Error::InvalidFrame(InvalidFrameKind::Body));
            }

            (Some(Cow::Borrowed(&buf[12..frame_len])), frame_len)
        } else {
            (None, 12)
        };

        Ok((Frame { header, body }, frame_len))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_call_create_without_body() {
        FrameBuilder::new()
            .flags(Flags::ACK)
            .stream_id(1)
            .frame_type(FrameType::Data)
            .create_without_body()
            .expect_err("Data frame should call create fn instead.");

        FrameBuilder::new()
            .flags(Flags::SYN)
            .stream_id(1)
            .frame_type(FrameType::GoAway)
            .create_without_body()
            .expect_err("Can't set SYN flags in GO_AWAY_FRAME");

        FrameBuilder::new()
            .flags(Flags::ACK)
            .stream_id(1)
            .frame_type(FrameType::GoAway)
            .create_without_body()
            .expect_err("Can't set ACK flags in GO_AWAY_FRAME");

        FrameBuilder::new()
            .flags(Flags::FIN)
            .stream_id(1)
            .frame_type(FrameType::GoAway)
            .create_without_body()
            .expect_err("Can't set FIN flags in GO_AWAY_FRAME");

        FrameBuilder::new()
            .flags(Flags::RST)
            .stream_id(1)
            .frame_type(FrameType::GoAway)
            .create_without_body()
            .expect_err("Can't set RST flags in GO_AWAY_FRAME");

        FrameBuilder::new()
            .flags(Flags::FIN)
            .frame_type(FrameType::Ping)
            .create_without_body()
            .expect_err("Can't set FIN flags in PING_FRAME");

        FrameBuilder::new()
            .flags(Flags::RST)
            .frame_type(FrameType::Ping)
            .create_without_body()
            .expect_err("Can't set RST flags in PING_FRAME");

        FrameBuilder::new()
            .flags(Flags::ACK)
            .frame_type(FrameType::Ping)
            .create_without_body()
            .expect("Set ACK in PING_FRAME to indicate response");

        FrameBuilder::new()
            .flags(Flags::SYN)
            .frame_type(FrameType::Ping)
            .create_without_body()
            .expect("Set ACK in PING_FRAME to indicate outbound");

        FrameBuilder::new()
            .flags(Flags::full())
            .stream_id(1)
            .frame_type(FrameType::WindowUpdate)
            .create_without_body()
            .expect("All flags in WINDOW_UPDATE_FRAME are valid.");
    }

    #[test]
    fn test_call_create() {
        FrameBuilder::new()
            .flags(Flags::full())
            .stream_id(1)
            .frame_type(FrameType::Data)
            .create(b"")
            .expect("All flags in DATA_FRAME are valid.");

        FrameBuilder::new()
            .stream_id(1)
            .frame_type(FrameType::GoAway)
            .create(b"")
            .expect_err("Body data is not allowed in GO_AWAY_FRAME");

        FrameBuilder::new()
            .flags(Flags::full())
            .stream_id(1)
            .frame_type(FrameType::WindowUpdate)
            .create(b"")
            .expect_err("Body data is not allowed in WINDOW_UPDATE");

        FrameBuilder::new()
            .flags(Flags::SYN)
            .frame_type(FrameType::Ping)
            .create(b"")
            .expect_err("Body data is not allowed in PING_FRAME");
    }

    #[test]
    fn test_session_id() {
        FrameBuilder::new()
            .flags(Flags::SYN)
            .stream_id(1)
            .frame_type(FrameType::Ping)
            .create_without_body()
            .expect_err("PING_FRAME should always use 0 stream id");

        FrameBuilder::new()
            .flags(Flags::none())
            .stream_id(1)
            .frame_type(FrameType::GoAway)
            .create_without_body()
            .expect_err("GO_AWAY_FRAME should always use 0 stream id");

        FrameBuilder::new()
            .flags(Flags::SYN)
            .frame_type(FrameType::Ping)
            .create_without_body()
            .unwrap();

        FrameBuilder::new()
            .flags(Flags::none())
            .frame_type(FrameType::GoAway)
            .create_without_body()
            .unwrap();
    }
}
