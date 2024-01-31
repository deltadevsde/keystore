pub mod os;
pub mod file;

use os::{add_signing_key_to_keychain, get_signing_key_from_keychain};
use file::{encrypt_and_store_private_key, load_and_decrypt_private_key};
use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;

pub fn create_signing_key() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

pub trait KeyStore {
    fn add_signing_key(&self, signing_key: &SigningKey) -> Result<(), String>;
    fn get_signing_key(&self) -> Result<SigningKey, String>;
}

// TODO: keychain is only for macos, should there be another abstraction to handle linux and windows as well
pub struct KeyChain;
impl KeyStore for KeyChain {
    fn add_signing_key(&self, signing_key: &SigningKey) -> Result<(), String> {
        add_signing_key_to_keychain(signing_key).map_err(|e| e.to_string())
    }

    fn get_signing_key(&self) -> Result<SigningKey, String> {
        get_signing_key_from_keychain().map_err(|e| e.to_string())
    }
}

pub struct FileStore;
impl KeyStore for FileStore {
    // TODO: how to handle filepaths better / the right way?
    fn add_signing_key(&self, signing_key: &SigningKey) -> Result<(), String> {
        encrypt_and_store_private_key(signing_key, "signing_key").map_err(|e| e.to_string())
    }

    fn get_signing_key(&self) -> Result<SigningKey, String> {
        load_and_decrypt_private_key("signing_key").map_err(|e| e.to_string())
    }
}