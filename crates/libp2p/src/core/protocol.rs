//! A libp2p protocol has these key features:
//!
//! # Protocol IDs
//!
//! libp2p protocols have unique string identifiers, which are used in
//! the protocol negotiation process when connections are first opened.
//!
//! By convention, protocol ids have a path-like structure,
//! with a version number as the final component:
//!
//! ***/my-app/amazing-protocol/1.0.1***
//!
//! Breaking changes to your protocol’s wire format or semantics should
//! result in a new version number. See the protocol negotiation section
//! for more information about how version selection works during the
//! dialing and listening process.
//!
//! ***While libp2p will technically accept any string as a valid protocol id,
//! using the recommended path structure with a version component is both
//! developer-friendly and enables easier matching by version.***

use std::{borrow::Cow, fmt::Display, io, sync::Arc};

use rasi::{
    channel::mpsc::{self, Receiver},
    stream::StreamExt,
    syscall::Handle,
};
use semver::Version;

use crate::errors::P2pError;

use super::{switch::Switch, upgrader::Upgrader};

/// The protocol id type for libp2p protocols.
///
/// Although the semantic version is optional, it is highly recommended to specify this field,
/// as described in the official [`documentation`](https://docs.libp2p.io/concepts/fundamentals/protocols/#match-using-semver)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolId {
    /// Path-like string as a protocol identity, must start with `/`
    pub path: Cow<'static, str>,
    /// Optional semantic version to easier matching by version.
    pub semver: Option<Version>,
}

impl TryFrom<&'static str> for ProtocolId {
    type Error = P2pError;

    fn try_from(s: &'static str) -> Result<Self, Self::Error> {
        Self::try_parse_static(s)
    }
}

impl TryFrom<String> for ProtocolId {
    type Error = P2pError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_parse(value)
    }
}

impl Display for ProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(version) = &self.semver {
            write!(f, "{}/{}", self.path, version)
        } else {
            write!(f, "{}", self.path.to_string())
        }
    }
}

impl ProtocolId {
    /// Create `ProtocolId` from path-like string, the input string must start with '/'.
    pub fn from_path<P: AsRef<str>>(path: P) -> Result<Self, P2pError> {
        if !path.as_ref().starts_with('/') {
            return Err(P2pError::ProtocolIdFormat);
        }

        Ok(Self {
            path: Cow::Owned(path.as_ref().to_owned()),
            semver: None,
        })
    }

    /// Try parse protocol id string as path-like string with semver.
    pub fn try_parse<P: AsRef<str>>(path: P) -> Result<Self, P2pError> {
        let path = path.as_ref();

        if let Some(pos) = path.rfind('/') {
            // the start slash.
            if pos != 0 {
                let version = match path[(pos + 1)..].parse() {
                    Ok(version) => version,
                    Err(_) => {
                        return Self::from_path(path);
                    }
                };

                return Ok(Self {
                    path: Cow::Owned(path[..pos].to_owned()),
                    semver: Some(version),
                });
            } else {
                return Ok(Self {
                    path: Cow::Owned(path.to_owned()),
                    semver: None,
                });
            }
        }

        return Err(P2pError::ProtocolIdFormat);
    }

    /// Try parse protocol id string as path-like string with semver.
    pub fn try_parse_static(path: &'static str) -> Result<Self, P2pError> {
        if let Some(pos) = path.rfind('/') {
            // the start slash.
            if pos != 0 {
                let version = match path[(pos + 1)..].parse() {
                    Ok(version) => version,
                    Err(_) => {
                        return Self::from_path(path);
                    }
                };

                return Ok(Self {
                    path: Cow::Borrowed(&path[..pos]),
                    semver: Some(version),
                });
            } else {
                return Ok(Self {
                    path: Cow::Borrowed(path),
                    semver: None,
                });
            }
        }

        return Err(P2pError::ProtocolIdFormat);
    }
}

/// A socket for libp2p protocol to listen and accept newly incoming connection.
///
/// `The switch` will close the socket when this instance drops.
pub struct ProtocolListener {
    /// local bound protocol_id
    protocol_id: ProtocolId,
    /// the core state of libp2p instance.
    switch: Switch,
    /// newly incoming stream receiver.
    receiver: Receiver<ProtocolStream>,
}

impl ProtocolListener {
    /// Create new `protocol listener` with provided [`Switch`] instance and listen on `protocol_id`.
    pub fn bind_with<P>(protocol_id: P, switch: Switch) -> io::Result<ProtocolListener>
    where
        P: TryInto<ProtocolId>,
        io::Error: From<P::Error>,
    {
        let protocol_id = protocol_id.try_into()?;

        let (sender, receiver) = mpsc::channel(0);

        switch.register_protocol_handler(protocol_id.clone(), Self::noop_match, sender)?;

        Ok(Self {
            protocol_id,
            switch,
            receiver,
        })
    }

    fn noop_match(_: ProtocolId) -> bool {
        false
    }

    /// Get the [`ProtocolId`] that this listener is bound to.
    pub fn local_addr(&self) -> &ProtocolId {
        &self.protocol_id
    }

    /// Accept newly incoming connection.
    ///
    /// Returns none, if the listener is dropping or has been closed.
    pub async fn accept(&mut self) -> Option<ProtocolStream> {
        self.receiver.next().await
    }
}

impl Drop for ProtocolListener {
    fn drop(&mut self) {
        self.switch.unregister_protocol_handler(&self.protocol_id);
    }
}

/// bi-directional binary stream, the applicaton protocol implementor use it to commuicate with peer.
///
/// You can call the [`peer_addr`](Self::peer_addr) to get the peer request [`ProtocolId`]
#[allow(unused)]
pub struct ProtocolStream {
    /// Peer request protocol_id
    peer_addr: ProtocolId,
    /// The acceptor bound protocol_id
    local_addr: ProtocolId,
    /// protocol stream handle.
    handle: Handle,
    /// The upgrader of this stream.
    upgrader: Arc<Box<dyn Upgrader>>,
}

impl ProtocolStream {
    /// Create new `ProtocolStream` with provided parameters.
    pub fn new(
        peer_addr: ProtocolId,
        local_addr: ProtocolId,
        handle: Handle,
        upgrader: Arc<Box<dyn Upgrader>>,
    ) -> Self {
        Self {
            peer_addr,
            local_addr,
            handle,
            upgrader,
        }
    }
}

#[cfg(test)]
mod tests {
    use semver::Version;

    use super::ProtocolId;

    #[test]
    fn test_protocol_id() {
        let protocol_id: ProtocolId = "/hello".try_into().unwrap();

        assert_eq!(protocol_id.path, "/hello");

        assert_eq!(protocol_id.semver, None);

        assert_eq!(protocol_id.to_string(), "/hello");

        let protocol_id: ProtocolId = "/hello/1.0.0".try_into().unwrap();

        assert_eq!(protocol_id.path, "/hello");

        assert_eq!(protocol_id.semver, Some(Version::new(1, 0, 0)));

        assert_eq!(protocol_id.to_string(), "/hello/1.0.0");

        TryInto::<ProtocolId>::try_into("hello").expect_err("Protocol id must start with /");
    }
}
