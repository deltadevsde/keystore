use crate::{create_signing_key, KeyStore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use dotenvy::dotenv;
use ed25519_consensus::SigningKey;
use hex;
use std::fs;
use std::{borrow::Cow, env};

pub struct FileStore {
    file_path: Cow<'static, str>,
}

impl FileStore {
    // using impl Into<String> to allow for &str and String here
    pub fn new(file_path: Cow<'static, str>) -> Self {
        FileStore { file_path }
    }
}

impl KeyStore for FileStore {
    fn add_signing_key(&self, id: &str, signing_key: &SigningKey) -> Result<()> {
        let path = self.file_path.clone() + id;
        encrypt_and_store_private_key(signing_key, &path)
            .context(format!("failed to store signing key for id {}", id))
    }

    fn get_signing_key(&self, id: &str) -> Result<SigningKey> {
        let path = self.file_path.clone() + id;
        load_and_decrypt_private_key(&path)
            .context(format!("failed to load signing key for id {}", id))
    }

    fn get_or_create_signing_key(&self, id: &str) -> Result<SigningKey> {
        match self.get_signing_key(id) {
            Ok(key) => Ok(key),
            Err(_) => {
                let new_key = create_signing_key();
                self.add_signing_key(id, &new_key)?;
                Ok(new_key)
            }
        }
    }
}

fn load_symmetric_key() -> Result<Aes256Gcm> {
    dotenv().ok();
    let key = env::var("SYMMETRIC_KEY").context("Failed to load symmetric key")?;
    let cipher = Aes256Gcm::new_from_slice(&hex::decode(key)?)
        .map_err(|e| anyhow!("Failed to create symmetric key: {}", e))?;
    Ok(cipher)
}

pub fn encrypt_and_store_private_key(signing_key: &SigningKey, file_path: &str) -> Result<()> {
    let symmetric_key = load_symmetric_key()?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = symmetric_key
        .encrypt(&nonce, signing_key.to_bytes().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to encrypt private key: {}", e))?;

    let mut data_to_store = Vec::new();
    data_to_store.extend_from_slice(&nonce);
    data_to_store.extend_from_slice(&ciphertext);

    fs::write(file_path, &data_to_store)?;

    Ok(())
}

pub fn load_and_decrypt_private_key(file_path: &str) -> Result<SigningKey> {
    let encrypted_data = std::fs::read(file_path)?;
    let symmetric_key = load_symmetric_key()?;

    let (nonce, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce);

    let decrypted_plaintext = symmetric_key
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Failed to decrypt private key: {}", e))?;

    if decrypted_plaintext.len() != 32 {
        bail!("Decrypted data has incorrect length for ed25519 key");
    }

    let mut singing_key_array = [0u8; 32];
    singing_key_array.copy_from_slice(&decrypted_plaintext);
    Ok(SigningKey::from(singing_key_array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_signing_key;

    #[test]
    fn test_encrypt_and_decrypt_private_key() {
        let signing_key = create_signing_key();
        let file_path = "test_encrypted_key_1";

        encrypt_and_store_private_key(&signing_key, file_path)
            .expect("Failed to encrypt and store key");

        let decrypted_key =
            load_and_decrypt_private_key(file_path).expect("Failed to load and decrypt key");

        assert_eq!(
            signing_key.to_bytes(),
            decrypted_key.to_bytes(),
            "Decrypted key is not the same as the original key"
        );

        std::fs::remove_file(file_path).expect("Failed to remove test file");
    }

    #[test]
    fn test_encrypt_and_decrypt_private_key_with_wrong_nonce() {
        let signing_key = create_signing_key();
        let file_path = "test_encrypted_key_2";

        encrypt_and_store_private_key(&signing_key, file_path)
            .expect("Failed to encrypt and store key");

        let encrypted_data = std::fs::read(file_path).unwrap();
        let symmetric_key = load_symmetric_key().unwrap();

        let (_nonce, ciphertext) = encrypted_data.split_at(12);
        let new_nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let decryption_result = symmetric_key
            .decrypt(&new_nonce, ciphertext)
            .map_err(|e| e.to_string());

        assert!(decryption_result.is_err(), "cant decrypt with wrong nonce");

        std::fs::remove_file(file_path).expect("Failed to remove test file");
    }
}
