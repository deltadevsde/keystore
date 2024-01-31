use ed25519_dalek::SigningKey;
use security_framework::os::macos::keychain::SecKeychain;
use std::error::Error;



// macOS keychain support

pub fn add_signing_key_to_keychain(signing_key: &SigningKey) -> Result<(), security_framework::base::Error> {
    let signing_key_bytes = signing_key.to_bytes();

    let keychain = SecKeychain::default()?;
    keychain.add_generic_password("deimos", "signing_key", &signing_key_bytes)
}

pub fn get_signing_key_from_keychain() -> Result<SigningKey, Box<dyn Error>> {
    let keychain = SecKeychain::default()?;
    let signing_key_bytes = keychain.find_generic_password("deimos", "signing_key")?;
    
    let mut singing_key_array = [0u8; 32];
    singing_key_array.copy_from_slice(&signing_key_bytes.0[..32]);
    println!("singing_key_array: {:?}", singing_key_array);
    Ok(SigningKey::from_bytes(&singing_key_array))
}


