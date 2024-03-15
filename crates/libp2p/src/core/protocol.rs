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

use std::{borrow::Cow, fmt::Display};

use semver::Version;

use crate::errors::P2pError;

use super::switch::Switch;

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

/// A trait that represents a [`libp2p protocol`],
/// that combines the two types of protocol handles described in the
/// [**official documentation**](https://docs.libp2p.io/concepts/fundamentals/protocols/)
pub trait Protocol {
    /// The exact match `protocol id`
    fn id(&self) -> ProtocolId;

    /// When a stream request comes in whose protocol id doesn’t have any exact matches,
    /// the protocol id will be passed through all of the registered `match_fn` functions.
    /// If any returns true, the associated handler Protocol trait's [`accept`](Protocol::accept) function will be invoked.
    fn match_fn(&self, request: ProtocolId) -> bool;

    /// The protocol register handler function.
    fn accept(&mut self, switch: Switch, request: ProtocolId, stream: ProtocolStream);
}

/// Wrapping `protocol handle function` into [`protocol`] types
pub struct ProtocolHandler {
    id: ProtocolId,
    match_f: Option<Box<dyn Fn(ProtocolId) -> bool>>,
    accept: Box<dyn FnMut(Switch, ProtocolId, ProtocolStream)>,
}

impl ProtocolHandler {
    pub fn new<ID, H>(id: ID, handle: H) -> Result<Self, P2pError>
    where
        ID: TryInto<ProtocolId>,
        P2pError: From<ID::Error>,
        H: FnMut(Switch, ProtocolId, ProtocolStream) + 'static,
    {
        Ok(Self {
            id: id.try_into()?,
            match_f: None,
            accept: Box::new(handle),
        })
    }

    pub fn new_with_match<ID, M, H>(id: ID, match_f: M, handle: H) -> Result<Self, P2pError>
    where
        ID: TryInto<ProtocolId>,
        P2pError: From<ID::Error>,
        M: Fn(ProtocolId) -> bool + 'static,
        H: FnMut(Switch, ProtocolId, ProtocolStream) + 'static,
    {
        Ok(Self {
            id: id.try_into()?,
            match_f: Some(Box::new(match_f)),
            accept: Box::new(handle),
        })
    }
}

impl<ID, H> TryFrom<(ID, H)> for ProtocolHandler
where
    ID: TryInto<ProtocolId>,
    P2pError: From<ID::Error>,
    H: FnMut(Switch, ProtocolId, ProtocolStream) + 'static,
{
    type Error = P2pError;
    fn try_from(value: (ID, H)) -> Result<Self, Self::Error> {
        Self::new(value.0, value.1)
    }
}

impl<ID, M, H> TryFrom<(ID, M, H)> for ProtocolHandler
where
    ID: TryInto<ProtocolId>,
    P2pError: From<ID::Error>,
    M: Fn(ProtocolId) -> bool + 'static,
    H: FnMut(Switch, ProtocolId, ProtocolStream) + 'static,
{
    type Error = P2pError;
    fn try_from(value: (ID, M, H)) -> Result<Self, Self::Error> {
        Self::new_with_match(value.0, value.1, value.2)
    }
}

impl Protocol for ProtocolHandler {
    fn id(&self) -> ProtocolId {
        self.id.clone()
    }

    fn match_fn(&self, request: ProtocolId) -> bool {
        if let Some(match_f) = self.match_f.as_ref() {
            match_f(request)
        } else {
            false
        }
    }

    fn accept(&mut self, switch: Switch, request: ProtocolId, stream: ProtocolStream) {
        (self.accept)(switch, request, stream)
    }
}
/// The protocol layer bi-directional data stream.
///
/// The protocol `handler` reads and writes unencrypted binary data over the stream.
pub struct ProtocolStream {}

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
