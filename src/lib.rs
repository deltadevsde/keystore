pub mod file;
pub mod os;

use anyhow::Result;
use ed25519_consensus::SigningKey;
use mockall::automock;
use rand::rngs::OsRng;

pub use file::FileStore;
pub use os::KeyChain;

pub fn create_signing_key() -> SigningKey {
    SigningKey::new(OsRng)
}

#[automock]
pub trait KeyStore {
    fn add_signing_key(&self, id: &str, signing_key: &SigningKey) -> Result<()>;
    fn get_signing_key(&self, id: &str) -> Result<SigningKey>;
    fn get_or_create_signing_key(&self, id: &str) -> Result<SigningKey>;
}
