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

use std::{collections::HashMap, fmt::Debug, io, sync::Arc};

use super::{
    protocol::{Protocol, ProtocolHandler, ProtocolId},
    transport::Transport,
};

/// The main state of a libp2p application.
///
/// You can use `swtich` to dial peers or listen for connections.
#[derive(Clone)]
pub struct Switch {
    #[allow(unused)]
    inner: Arc<SwitchBuilder>,
}

impl Switch {
    /// Create a [`switch builder`] to build a new `Switch` instance.
    pub fn new() -> SwitchBuilder {
        SwitchBuilder::default()
    }
}

/// A builder for libp2p [`Switch`] instance.
pub struct SwitchBuilder {
    /// registered libp2p application protocols.
    protocols: HashMap<ProtocolId, Box<dyn Protocol>>,
    /// registered libp2p transport.
    transports: Vec<Box<dyn Transport>>,
}

impl Default for SwitchBuilder {
    fn default() -> Self {
        Self {
            protocols: Default::default(),
            transports: Default::default(),
        }
    }
}

impl SwitchBuilder {
    /// Consume the builder and create the final product [`Switch`].
    pub fn create(self) -> io::Result<Switch> {
        Ok(Switch {
            inner: Arc::new(self),
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

    /// Register new libp2p protocol handler to this switch
    ///
    /// # panic
    ///
    /// If register protocol with same [`protocol id`](Protocol::id) twice.
    pub fn register_protocol<P>(mut self, protocol: P) -> Self
    where
        P: Protocol + 'static,
    {
        let protocol_id = protocol.id();
        if self
            .protocols
            .insert(protocol.id(), Box::new(protocol))
            .is_some()
        {
            panic!("Register protocol {} twice", protocol_id);
        }

        self
    }

    /// See [`register_protocol`](Self::register_protocol) for more information.
    pub fn register_protocol_handler<P>(self, protocol: P) -> Self
    where
        P: TryInto<ProtocolHandler>,
        P::Error: Debug,
    {
        self.register_protocol(protocol.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::Switch;

    #[test]
    fn test_register_protocol() {
        Switch::new().register_protocol_handler(("/test", |_, _, _| {}));

        Switch::new().register_protocol_handler(("/test/1.0", |_| true, |_, _, _| {}));
    }
}
