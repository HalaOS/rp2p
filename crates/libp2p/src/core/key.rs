/// A manager for `Switch`'s keypair.
///
/// libp2p use public key to generate peer ID, and use private key to secure transport channel,
/// so we need a service to manage switch's keypair.
pub trait KeyPairManager: Sync + Send {}
