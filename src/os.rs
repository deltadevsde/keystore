use ed25519_dalek::SigningKey;
use std::error::Error;

#[cfg(feature = "macos")]
use security_framework::os::macos::keychain::SecKeychain;

#[cfg(feature = "linux")]
use base64::{engine::general_purpose, Engine as _};
#[cfg(feature = "linux")]
use keyring::Entry;

use crate::create_signing_key;

#[cfg(feature = "macos")]
pub fn add_signing_key_to_keychain(
    signing_key: &SigningKey,
) -> Result<(), security_framework::base::Error> {
    let signing_key_bytes = signing_key.to_bytes();

    let keychain = SecKeychain::default()?;
    keychain.add_generic_password("deimos", "signing_key", &signing_key_bytes)
}

#[cfg(feature = "linux")]
pub fn add_signing_key_to_keychain(signing_key: &SigningKey) -> Result<(), Box<dyn Error>> {
    let signing_key_bytes = signing_key.to_bytes();
    let signing_key_str = general_purpose::STANDARD.encode(&signing_key_bytes);

    let entry = Entry::new("deimos", "signing_key").unwrap();
    entry.set_password(&signing_key_str)?;

    Ok(())
}

#[cfg(feature = "macos")]
pub fn get_signing_key_from_keychain() -> Result<SigningKey, Box<dyn Error>> {
    let keychain = SecKeychain::default()?;

    // get signing key or add it if it doesn't exist
    let signing_key_bytes: Vec<u8> = match keychain.find_generic_password("deimos", "signing_key") {
        Ok(value) => value.0.to_vec(),
        Err(_) => {
            let signing_key = create_signing_key();
            add_signing_key_to_keychain(&signing_key)?;
            signing_key.to_bytes().to_vec()
        }
    };

    let mut signing_key_array = [0u8; 32];
    signing_key_array.copy_from_slice(&signing_key_bytes[..32]);
    Ok(SigningKey::from_bytes(&signing_key_array))
}

#[cfg(feature = "linux")]
pub fn get_signing_key_from_keychain() -> Result<SigningKey, Box<dyn Error>> {
    let keyring = Entry::new("deimos", "signing_key")?;

    let signing_key_str = match keyring.get_password() {
        Ok(password) => password,
        Err(_) => {
            let signing_key = create_signing_key();
            add_signing_key_to_keychain(&signing_key)?;
            general_purpose::STANDARD.encode(signing_key.to_bytes())
        }
    };

    let signing_key_bytes = general_purpose::STANDARD.decode(&signing_key_str)?;
    let mut signing_key_array = [0u8; 32];
    signing_key_array.copy_from_slice(&signing_key_bytes[..32]);
    Ok(SigningKey::from_bytes(&signing_key_array))
}
