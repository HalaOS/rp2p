use thiserror::Error;

/// Yamux errors type.
#[derive(Debug, Error)]
pub enum Error {
    /// The operation cannot be completed because the connection is in an invalid state.
    #[error("The operation cannot be completed because the connection is in an invalid state.")]
    InvalidState,

    /// The operation cannot be completed because the stream is in an invalid state.
    /// The stream ID is provided as associated data.
    #[error("The operation cannot be completed because the stream({0}) is in an invalid state.")]
    InvalidStreamState(u32),

    /// The peer violated the local flow control limits.
    #[error("The peer violated the local flow control limits.")]
    FlowControl,

    /// The specified stream was reset by the peer.
    ///
    /// This flag is set by the received frame with the RST flag.
    #[error("The specified stream({0}) was reset by the peer.")]
    StreamReset(u32),

    /// Call stream_send after setting the fin flag of the stream.
    #[error("Call stream_send after setting the fin flag of the stream({0}).")]
    FinalSize(u32),

    #[error("There is no more work to do")]
    Done,

    /// The expected length is provided as associated data.
    #[error("The provided buffer is too short. expected {0}")]
    BufferTooShort(u32),

    /// The provided frame cannot be parsed because its version is unknown.
    ///
    /// The frame version is provided as associated data.
    #[error("The provided packet cannot be parsed because its version is unknown({0}).")]
    UnknownVersion(u8),

    /// The provide frame can't be parsed.
    ///
    /// The [`InvalidFrameKind`] is provided as associated data.
    #[error("The provide frame can't be parsed,{0:?}")]
    InvalidFrame(InvalidFrameKind),

    /// Building frame violate the restrictions.
    ///
    /// The [`FrameRestrictionKind`] is provided as associated data.
    #[error("Building frame violate the restrictions. {0:?}")]
    FrameRestriction(FrameRestrictionKind),
}

/// Reason for not being able to parse the frame.
#[derive(Debug, Clone, Copy, Error)]
pub enum InvalidFrameKind {
    #[error("Invalid frame type.")]
    FrameType,
    #[error("The Frame Flags field contains invalid flags.")]
    Flags,
}

/// Reason for not being able to build the frame.
#[derive(Debug, Clone, Copy, Error)]
pub enum FrameRestrictionKind {
    /// Only DATA_FRAME is allowed to set the body content.
    #[error("Only DATA_FRAME is allowed to set the body content.")]
    Body,
    /// Set the invalid frame flags, see `create_without_body` for more information.
    #[error("Set the invalid frame flags, see `create_without_body` for more information.")]
    Flags,
    /// The GO_AWAY_FRAME and PING_FRAME should always use 0 StreamID.
    #[error("The GO_AWAY_FRAME and PING_FRAME should always use 0 StreamID, while other types of frames should not.")]
    SessionId,
}

/// A specialized [`Result`](std::result::Result) type for yamux operations.
pub type Result<T> = std::result::Result<T, Error>;
