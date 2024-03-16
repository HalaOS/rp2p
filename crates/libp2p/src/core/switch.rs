use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use rasi::syscall::Handle;

use super::{KeyPairManager, Multiplexing, SecureUpgrade, TlsHandshake, Transport, Yamux};

/// Switch object reference id.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SwitchId(usize);

impl SwitchId {
    /// Generate a new `SwitchId`
    pub fn next() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// A transport handle that combine the `upgrade` context information.
pub enum SwitchHandle {
    /// Native transport handle.
    Transport(SwitchId, Handle),

    /// With secure upgraded handle.
    SecureUpgrade(SwitchId, Handle),

    /// With muxing upgraded handle.
    MuxingUpgrade(SwitchId, Handle),
}

pub struct SwitchStream {}

#[allow(unused)]
/// The immutable context data of switch.
struct SwitchImmutable {
    keypair: Box<dyn KeyPairManager>,
    transports: Vec<Box<dyn Transport>>,
    muxing: Box<dyn Multiplexing>,
    secure_upgrade: Box<dyn SecureUpgrade>,
}

/// A switch is the context of all other libp2p objects.
///
/// This is the first thing you create when using libp2p.
/// Its primary use is to dail an outbound connection and accept newly incoming connection.
///
/// Creates a switch [`builder`](SwitchBuilder) by calling the function [`new`](Switch::new),
/// with this `builder`, the developer can control the configuration details of the `Switch`:
///
/// * configure the transport stack.
/// * configure the secure upgrader instance.
/// * configure the muxing upgrader instance.
#[allow(unused)]
pub struct Switch {
    immutable: Arc<SwitchImmutable>,
}

impl Switch {
    /// Create a new switch [`builder`](SwitchBuilder) with provided `keypair` to configure the new `Switch`.
    pub fn new<K: KeyPairManager + 'static>(keypair: K) -> SwitchBuilder {
        SwitchBuilder {
            keypair_manager: Box::new(keypair),
            transports: Default::default(),
            muxing: Default::default(),
            secure_upgrade: Default::default(),
        }
    }
}

/// A builder pattern implementation for [`Switch`] type.
///
/// You can create a `builder` using the [`new`](Switch::new) function.
#[allow(unused)]
pub struct SwitchBuilder {
    keypair_manager: Box<dyn KeyPairManager>,
    transports: Vec<Box<dyn Transport>>,
    muxing: Option<Box<dyn Multiplexing>>,
    secure_upgrade: Option<Box<dyn SecureUpgrade>>,
}

impl SwitchBuilder {
    /// Add a new transport type to the switch.
    pub fn register_transport<T: Transport + 'static>(mut self, transport: T) -> Self {
        self.transports.push(Box::new(transport));
        self
    }

    /// Set the switch's default muxing service provider.
    pub fn muxing<M: Multiplexing + 'static>(mut self, value: M) -> Self {
        self.muxing = Some(Box::new(value));

        self
    }

    /// Set the switch's default secure upgrade service provider.
    pub fn secure_upgrade<S: SecureUpgrade + 'static>(mut self, value: S) -> Self {
        self.secure_upgrade = Some(Box::new(value));

        self
    }

    /// Consume the `builder` and generate a new [`Switch`] instance.
    pub fn create(self) -> Switch {
        Switch {
            immutable: Arc::new(SwitchImmutable {
                keypair: self.keypair_manager,
                transports: self.transports,
                muxing: self.muxing.unwrap_or(Box::new(Yamux::default())),
                secure_upgrade: self
                    .secure_upgrade
                    .unwrap_or(Box::new(TlsHandshake::default())),
            }),
        }
    }
}
