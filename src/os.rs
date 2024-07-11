use ed25519_dalek::SigningKey;
use std::error::Error;

#[cfg(feature = "macos")]
use security_framework::os::macos::keychain::SecKeychain;

#[cfg(target_os = "linux")]
use keyring::{Entry, Keyring};

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
    let signing_key_str = base64::encode(&signing_key_bytes);

    let keyring = Keyring::new("deimos", "signing_key");
    keyring.set_password(&signing_key_str)?;

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
    let keyring = Keyring::new("deimos", "signing_key");

    let signing_key_str = match keyring.get_password() {
        Ok(password) => password,
        Err(_) => {
            let signing_key = create_signing_key();
            add_signing_key_to_keychain(&signing_key)?;
            base64::encode(signing_key.to_bytes())
        }
    };

    let signing_key_bytes = base64::decode(&signing_key_str)?;
    let mut signing_key_array = [0u8; 32];
    signing_key_array.copy_from_slice(&signing_key_bytes[..32]);
    Ok(SigningKey::from_bytes(&signing_key_array))
}
