use std::{borrow::Cow, fmt::Display};

use crate::errors::{Error, Result};

/// The protocol id type for libp2p protocols.
///
/// Although the semantic version is optional, it is highly recommended to specify this field,
/// as described in the official [`documentation`](https://docs.libp2p.io/concepts/fundamentals/protocols/#match-using-semver)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolId {
    /// Path-like string as a protocol identity, must start with `/`
    pub path: Cow<'static, str>,
    /// Optional semantic version to easier matching by version.
    pub semver: Option<semver::Version>,
}

impl TryFrom<&'static str> for ProtocolId {
    type Error = Error;

    fn try_from(s: &'static str) -> std::result::Result<Self, Self::Error> {
        Self::try_parse_static(s)
    }
}

impl TryFrom<String> for ProtocolId {
    type Error = Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
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
    pub fn from_path<P: AsRef<str>>(path: P) -> std::result::Result<Self, Error> {
        if !path.as_ref().starts_with('/') {
            return Err(Error::ParseProtocolId);
        }

        Ok(Self {
            path: Cow::Owned(path.as_ref().to_owned()),
            semver: None,
        })
    }

    /// Try parse protocol id string as path-like string with semver.
    pub fn try_parse<P: AsRef<str>>(path: P) -> Result<Self> {
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

        return Err(Error::ParseProtocolId);
    }

    /// Try parse protocol id string as path-like string with semver.
    pub fn try_parse_static(path: &'static str) -> Result<Self> {
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

        return Err(Error::ParseProtocolId);
    }
}
