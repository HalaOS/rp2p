//! A [`HostKey`](rp2p_core::HostKey) implementation for test purposes.

use std::io;

use async_trait::async_trait;
use rp2p_core::{HostKey, Keypair, PublicKey};

pub struct MemoryHostKey(Keypair);

impl Default for MemoryHostKey {
    fn default() -> Self {
        Self(Keypair::generate_ecdsa())
    }
}

impl MemoryHostKey {
    /// Create [`HostKey`] with provided [`Keypair`]
    pub fn new(keypair: Keypair) -> Self {
        Self(keypair)
    }
}

#[async_trait]
impl HostKey for MemoryHostKey {
    /// Get the public key of host keypair.
    async fn public_key(&self) -> io::Result<PublicKey> {
        Ok(self.0.public())
    }

    /// Sign the unhashed data using the private key.
    async fn sign(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        self.0
            .sign(data)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }
}
