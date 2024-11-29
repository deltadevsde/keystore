use anyhow::{Context, Result};
use ed25519_consensus::SigningKey;

#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;

#[cfg(target_os = "linux")]
use base64::{engine::general_purpose, Engine as _};
#[cfg(target_os = "linux")]
use keyring::Entry;

use crate::{create_signing_key, KeyStore};

pub struct KeyChain;
impl KeyStore for KeyChain {
    fn add_signing_key(&self, id: &str, signing_key: &SigningKey) -> Result<()> {
        add_signing_key_to_keychain(id, signing_key).context(format!(
            "failed to store signing key for id {} in keychain",
            id
        ))
    }

    fn get_signing_key(&self, id: &str) -> Result<SigningKey> {
        get_signing_key_from_keychain(id).context(format!(
            "failed to load signing key for id {} from keychain",
            id
        ))
    }

    fn get_or_create_signing_key(&self, id: &str) -> Result<SigningKey> {
        match self.get_signing_key(id) {
            Ok(key) => Ok(key),
            Err(_) => {
                let new_key = create_signing_key();
                self.add_signing_key(id, &new_key).with_context(|| {
                    format!("Failed to create and store new key for id: {}", id)
                })?;
                Ok(new_key)
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub fn add_signing_key_to_keychain(
    id: &str,
    signing_key: &SigningKey,
) -> Result<(), security_framework::base::Error> {
    let signing_key_bytes = signing_key.to_bytes();

    let keychain = SecKeychain::default()?;
    keychain.add_generic_password(id, "signing_key", &signing_key_bytes)
}

#[cfg(target_os = "linux")]
pub fn add_signing_key_to_keychain(id: &str, signing_key: &SigningKey) -> Result<()> {
    let signing_key_bytes = signing_key.to_bytes();
    let signing_key_str = general_purpose::STANDARD.encode(&signing_key_bytes);

    let entry = Entry::new(id, "signing_key").context("failed to create new keyring entry")?;
    entry.set_password(&signing_key_str)?;

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn get_signing_key_from_keychain(id: &str) -> Result<SigningKey> {
    let keychain = SecKeychain::default()?;

    let (signing_key_bytes, _) = keychain
        .find_generic_password(id, "signing_key")
        .context(format!("Failed to find signing key for id: {}", id))?;

    let mut signing_key_array = [0u8; 32];
    signing_key_array.copy_from_slice(&signing_key_bytes[..32]);
    Ok(SigningKey::from(signing_key_array))
}

#[cfg(target_os = "linux")]
pub fn get_signing_key_from_keychain(id: &str) -> Result<SigningKey> {
    let keyring = Entry::new(id, "signing_key")?;

    let signing_key_str = keyring
        .get_password()
        .context("failed to get password from keyring")?;

    let signing_key_bytes = general_purpose::STANDARD.decode(&signing_key_str)?;
    let mut signing_key_array = [0u8; 32];
    signing_key_array.copy_from_slice(&signing_key_bytes[..32]);
    Ok(SigningKey::from(signing_key_array))
}
