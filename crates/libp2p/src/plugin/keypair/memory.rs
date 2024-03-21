use std::io;

use identity::Keypair;
use rasi::syscall::{CancelablePoll, PendingHandle};

use crate::KeypairProvider;

/// This type of [`KeypairProvider`] creates an in-memory temporary key pair when the application starts.
pub struct MemoryKeyProvider(Keypair);

impl MemoryKeyProvider {
    /// Create a `MemoryKeyProvider` instance with random [`Keypair`].
    pub fn random() -> Self {
        Self(Keypair::generate_ed25519())
    }
}

impl Default for MemoryKeyProvider {
    fn default() -> Self {
        Self::random()
    }
}

impl KeypairProvider for MemoryKeyProvider {
    fn public_key(
        &self,
        _cx: &mut std::task::Context<'_>,
        _: Option<PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<identity::PublicKey>> {
        CancelablePoll::Ready(Ok(self.0.public()))
    }

    fn sign(
        &self,
        _cx: &mut std::task::Context<'_>,
        sign_data: &[u8],
        _pending_handle: Option<PendingHandle>,
    ) -> CancelablePoll<std::io::Result<Vec<u8>>> {
        CancelablePoll::Ready(self.0.sign(sign_data).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("identity key sign with error: {}", err,),
            )
        }))
    }
}
