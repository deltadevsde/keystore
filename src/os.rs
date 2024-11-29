use ed25519_consensus::SigningKey;
use std::error::Error;

#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;

#[cfg(target_os = "linux")]
use base64::{engine::general_purpose, Engine as _};
#[cfg(target_os = "linux")]
use keyring::Entry;

use crate::{create_signing_key, KeyStore};

pub struct KeyChain;
impl KeyStore for KeyChain {
    fn add_signing_key(&self, id: &str, signing_key: &SigningKey) -> Result<(), String> {
        add_signing_key_to_keychain(id, signing_key).map_err(|e| e.to_string())
    }

    fn get_signing_key(&self, id: &str) -> Result<SigningKey, String> {
        get_signing_key_from_keychain(id).map_err(|e| e.to_string())
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
pub fn add_signing_key_to_keychain(
    id: &str,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn Error>> {
    let signing_key_bytes = signing_key.to_bytes();
    let signing_key_str = general_purpose::STANDARD.encode(signing_key_bytes);

    let entry = Entry::new(id, "signing_key").unwrap();
    entry.set_password(&signing_key_str)?;

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn get_signing_key_from_keychain(id: &str) -> Result<SigningKey, Box<dyn Error>> {
    let keychain = SecKeychain::default()?;

    // get signing key or add it if it doesn't exist
    let signing_key_bytes: Vec<u8> = match keychain.find_generic_password(id, "signing_key") {
        Ok(value) => value.0.to_vec(),
        Err(_) => {
            let signing_key = create_signing_key();
            add_signing_key_to_keychain(id, &signing_key)?;
            signing_key.to_bytes().to_vec()
        }
    };

    let mut signing_key_array = [0u8; 32];
    signing_key_array.copy_from_slice(&signing_key_bytes[..32]);
    Ok(SigningKey::from(signing_key_array))
}

#[cfg(target_os = "linux")]
pub fn get_signing_key_from_keychain(id: &str) -> Result<SigningKey, Box<dyn Error>> {
    let keyring = Entry::new(id, "signing_key")?;

    let signing_key_str = match keyring.get_password() {
        Ok(password) => password,
        Err(_) => {
            let signing_key = create_signing_key();
            add_signing_key_to_keychain(id, &signing_key)?;
            general_purpose::STANDARD.encode(signing_key.to_bytes())
        }
    };

    let signing_key_bytes = general_purpose::STANDARD.decode(&signing_key_str)?;
    let mut signing_key_array = [0u8; 32];
    signing_key_array.copy_from_slice(&signing_key_bytes[..32]);
    Ok(SigningKey::from(signing_key_array))
}
