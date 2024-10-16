pub mod file;
pub mod os;

use ed25519_consensus::SigningKey;
use file::{encrypt_and_store_private_key, load_and_decrypt_private_key};
use mockall::automock;
use os::{add_signing_key_to_keychain, get_signing_key_from_keychain};
use rand::rngs::OsRng;

pub fn create_signing_key() -> SigningKey {
    SigningKey::new(OsRng)
}

#[automock]
pub trait KeyStore {
    fn add_signing_key(&self, signing_key: &SigningKey) -> Result<(), String>;
    fn get_signing_key(&self) -> Result<SigningKey, String>;
}

pub enum KeyStoreType {
    KeyChain(KeyChain),
    FileStore(FileStore),
    // tbd
}

impl KeyStore for KeyStoreType {
    fn add_signing_key(&self, signing_key: &SigningKey) -> Result<(), String> {
        match self {
            KeyStoreType::KeyChain(store) => store.add_signing_key(signing_key),
            KeyStoreType::FileStore(store) => store.add_signing_key(signing_key),
            // more to come
        }
    }

    fn get_signing_key(&self) -> Result<SigningKey, String> {
        match self {
            KeyStoreType::KeyChain(store) => store.get_signing_key(),
            KeyStoreType::FileStore(store) => store.get_signing_key(),
            // todo: more cases
        }
    }
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

pub struct FileStore {
    file_path: String,
}

impl FileStore {
    // using impl Into<String> to allow for &str and String here
    pub fn new(file_path: impl Into<String>) -> Self {
        FileStore {
            file_path: file_path.into(),
        }
    }
}

impl KeyStore for FileStore {
    // TODO: how to handle filepaths better / the right way?
    fn add_signing_key(&self, signing_key: &SigningKey) -> Result<(), String> {
        encrypt_and_store_private_key(signing_key, &self.file_path).map_err(|e| e.to_string())
    }

    fn get_signing_key(&self) -> Result<SigningKey, String> {
        load_and_decrypt_private_key(&self.file_path).map_err(|e| e.to_string())
    }
}
