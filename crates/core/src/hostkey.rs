use std::io;

use async_trait::async_trait;

/// Another plugin for `Switch`.
///
/// The `HostKey` provider the ability that `Switch` can access the host node keypair.
///
/// thanks to this additional layer of abstraction,
/// it is possible to extend more different types of key provisioning,
/// for example:
///
/// * use os keychain to save the origin keypair data.
/// * use private network to access the keypair in the `citadel`
#[async_trait]
pub trait HostKey: Sync + Send {
    /// Get the public key of host keypair.
    async fn public_key(&self) -> io::Result<identity::PublicKey>;

    /// Sign the unhashed data using the private key.
    async fn sign(&self, data: &[u8]) -> io::Result<Vec<u8>>;
}

/// Type alias of [`Box<dyn HostKey>`]
pub type BoxHostKey = Box<dyn HostKey>;
