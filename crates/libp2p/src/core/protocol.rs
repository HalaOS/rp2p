use std::{borrow::Cow, fmt::Display};

use futures::{AsyncReadExt, AsyncWriteExt};
use identity::{PeerId, PublicKey};
use multiaddr::Multiaddr;
use multistream_select::Negotiated;
use protobuf::Message;
use rasi_ext::utils::ReadBuf;
use semver::Version;

use crate::{
    errors::{P2pError, Result},
    proto::identify::Identify,
};

use super::{P2pConn, Switch, SwitchStream};

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

    fn try_from(s: &'static str) -> std::result::Result<Self, Self::Error> {
        Self::try_parse_static(s)
    }
}

impl TryFrom<String> for ProtocolId {
    type Error = P2pError;

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
    pub fn from_path<P: AsRef<str>>(path: P) -> std::result::Result<Self, P2pError> {
        if !path.as_ref().starts_with('/') {
            return Err(P2pError::ParseProtocolId);
        }

        Ok(Self {
            path: Cow::Owned(path.as_ref().to_owned()),
            semver: None,
        })
    }

    /// Try parse protocol id string as path-like string with semver.
    pub fn try_parse<P: AsRef<str>>(path: P) -> std::result::Result<Self, P2pError> {
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

        return Err(P2pError::ParseProtocolId);
    }

    /// Try parse protocol id string as path-like string with semver.
    pub fn try_parse_static(path: &'static str) -> std::result::Result<Self, P2pError> {
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

        return Err(P2pError::ParseProtocolId);
    }
}

/// client-side use this function to execute identify request.
pub(super) async fn identity_request(switch: Switch, conn: P2pConn) -> Result<PeerId> {
    let identify = {
        let stream = conn.open().await?;

        let (mut stream, _) = stream
            .client_select_protocol(&["/ipfs/id/1.0.0".try_into().unwrap()])
            .await?;

        let mut buf = ReadBuf::with_capacity(switch.immutable_switch.max_identity_packet_len);

        loop {
            let read_size = stream.read(buf.chunk_mut()).await?;

            if read_size == 0 {
                break;
            }

            buf.advance_mut(read_size);
        }

        Identify::parse_from_bytes(buf.chunk())?
    };

    let conn_peer_id = conn
        .public_key()
        .expect("Upgraded connection must has pubkey.")
        .to_peer_id();

    let pubkey = PublicKey::try_decode_protobuf(identify.publicKey())?;

    let peer_id = pubkey.to_peer_id();

    if conn_peer_id != peer_id {
        return Err(P2pError::UnexpectPeerId);
    }

    let raddrs = identify
        .listenAddrs
        .into_iter()
        .map(|buf| Multiaddr::try_from(buf).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    switch.neighbors_put(peer_id, &raddrs).await?;

    Ok(peer_id)
}

/// The responsor of identify request.
pub(super) async fn identity_response(
    switch: &Switch,
    stream: &mut Negotiated<SwitchStream>,
    raddr: Multiaddr,
) -> Result<()> {
    let mut identity = Identify::new();

    identity.set_observedAddr(raddr.to_vec());

    identity.set_publicKey(switch.public_key().encode_protobuf());

    identity.set_agentVersion(switch.agent_version().to_owned());

    identity.listenAddrs = switch
        .local_addrs()
        .iter()
        .map(|addr| addr.to_vec())
        .collect::<Vec<_>>();

    let buf = identity.write_to_bytes()?;

    stream.write_all(&buf).await?;

    Ok(())
}

/// Handle `/ipfs/id/push/1.0.0` request.
pub(super) async fn identity_push(
    switch: &mut Switch,
    stream: &mut Negotiated<SwitchStream>,
    peer_id: PeerId,
) -> Result<PeerId> {
    let identify = {
        let mut buf = ReadBuf::with_capacity(switch.immutable_switch.max_identity_packet_len);

        loop {
            let read_size = stream.read(buf.chunk_mut()).await?;

            if read_size == 0 {
                break;
            }

            buf.advance_mut(read_size);
        }

        Identify::parse_from_bytes(buf.chunk())?
    };

    let raddrs = identify
        .listenAddrs
        .into_iter()
        .map(|buf| Multiaddr::try_from(buf).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    switch.neighbors_put(peer_id, &raddrs).await?;

    Ok(peer_id)
}
