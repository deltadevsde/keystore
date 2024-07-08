use ed25519_dalek::SigningKey;
use security_framework::os::macos::keychain::SecKeychain;
use std::error::Error;

use crate::create_signing_key;

// macOS keychain support

pub fn add_signing_key_to_keychain(
    signing_key: &SigningKey,
) -> Result<(), security_framework::base::Error> {
    let signing_key_bytes = signing_key.to_bytes();

    let keychain = SecKeychain::default()?;
    keychain.add_generic_password("deimos", "signing_key", &signing_key_bytes)
}

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
