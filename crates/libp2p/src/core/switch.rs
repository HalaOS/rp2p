//! libp2p maintains some state about known peers and existing connections
//! in a component known as the switch (or “swarm”, depending on the implementation).
//! The switch provides a dialing and listening interface that abstracts the details
//! of which stream multiplexer is used for a given connection.
//!
//! When configuring libp2p, applications enable stream muxing modules,
//! which the switch will use when dialing peers and listening for connections.
//! If the remote peers support any of the same stream muxing implementations,
//! the switch will select and use it when establishing the connection.
//! If you dial a peer that the switch already has an open connection to,
//! the new stream will automatically be multiplexed over the existing connection.
//!
//! Reaching agreement on which stream multiplexer to use happens early in the connection establishment process.
//! Peers use protocol negotiation to agree on a commonly supported multiplexer,
//! which upgrades a “raw” transport connection into a muxed connection capable of opening new streams.

use std::{collections::HashMap, io, sync::Arc};

use rasi::channel::mpsc::Sender;
use rasi_ext::utils::{Lockable, SpinMutex};

use crate::errors::{P2pError, P2pResult};

use super::{
    protocol::{ProtocolId, ProtocolStream},
    transport::Transport,
    upgrader::{NoopUpgrader, Upgrader},
};

type BoxMatchFn = Arc<Box<dyn Fn(ProtocolId) -> bool>>;

#[derive(Default)]
struct SwitchDispatch {
    exact_match_handlers: HashMap<ProtocolId, (BoxMatchFn, Sender<ProtocolStream>)>,
}

impl SwitchDispatch {
    fn register<F>(
        &mut self,
        protocol_id: ProtocolId,
        match_f: F,
        sender: Sender<ProtocolStream>,
    ) -> P2pResult<()>
    where
        F: Fn(ProtocolId) -> bool + 'static,
    {
        if self
            .exact_match_handlers
            .insert(
                protocol_id.clone(),
                (Arc::new(Box::new(match_f)), sender.clone()),
            )
            .is_some()
        {
            return Err(P2pError::RegisterProtocolId);
        }

        Ok(())
    }

    fn unregister(&mut self, protocol_id: &ProtocolId) {
        self.exact_match_handlers.remove(protocol_id);
    }
}

/// The main state of a libp2p application.
///
/// You can use `swtich` to dial peers or listen for connections.
#[derive(Clone)]
pub struct Switch {
    #[allow(unused)]
    immutable_state: Arc<SwitchBuilder>,
    /// dispatcher for newly incoming protocol stream.
    dispatch: Arc<SpinMutex<SwitchDispatch>>,
}

impl Switch {
    /// Create a [`switch builder`] to build a new `Switch` instance.
    pub fn new() -> SwitchBuilder {
        SwitchBuilder::new(NoopUpgrader {})
    }

    /// Register handler for newly incoming protocol stream.
    ///
    /// Returns error [`P2pError::RegisterProtocolId`], if register same `protocol_id` more than once.
    pub fn register_protocol_handler<F>(
        &self,
        protocol_id: ProtocolId,
        match_f: F,
        sender: Sender<ProtocolStream>,
    ) -> P2pResult<()>
    where
        F: Fn(ProtocolId) -> bool + 'static,
    {
        self.dispatch.lock().register(protocol_id, match_f, sender)
    }

    /// Unregister protocol stream handler by `protocol_id`
    pub fn unregister_protocol_handler(&self, protocol_id: &ProtocolId) {
        self.dispatch.lock().unregister(protocol_id)
    }
}

/// A builder for libp2p [`Switch`] instance.
pub struct SwitchBuilder {
    /// registered libp2p transport.
    transports: Vec<Box<dyn Transport>>,
    /// upgrader for the transport connection.
    upgrader: Arc<Box<dyn Upgrader>>,
}

impl SwitchBuilder {
    fn new<U: Upgrader + 'static>(upgrader: U) -> Self {
        Self {
            transports: Default::default(),
            upgrader: Arc::new(Box::new(upgrader)),
        }
    }

    /// Consume the builder and create the final product [`Switch`].
    pub fn create(self) -> io::Result<Switch> {
        Ok(Switch {
            immutable_state: Arc::new(self),
            dispatch: Default::default(),
        })
    }

    /// Register new libp2p transport to this switch.
    pub fn register_transport<T>(mut self, transport: T) -> Self
    where
        T: Transport + 'static,
    {
        self.transports.push(Box::new(transport));
        self
    }
}
