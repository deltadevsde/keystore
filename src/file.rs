use crate::KeyStore;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use dotenvy::dotenv;
use ed25519_consensus::SigningKey;
use hex;
use hex::ToHex;
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
    fn add_signing_key(&self, id: &str, signing_key: &SigningKey) -> Result<(), String> {
        let path = self.file_path.clone() + id;
        encrypt_and_store_private_key(signing_key, &path).map_err(|e| e.to_string())
    }

    fn get_signing_key(&self, id: &str) -> Result<SigningKey, String> {
        let path = self.file_path.clone() + id;
        load_and_decrypt_private_key(&path).map_err(|e| e.to_string())
    }
}

fn load_symmetric_key() -> Result<Aes256Gcm, Box<dyn std::error::Error>> {
    dotenv().ok();
    let key = env::var("SYMMETRIC_KEY").unwrap_or_else(|_| {
        let symmetric_key = Aes256Gcm::generate_key(OsRng);
        let key_hex = symmetric_key.encode_hex();

        let mut env_content = fs::read_to_string(".env").unwrap_or_default();
        env_content.push_str(&format!("\nSYMMETRIC_KEY={}\n", key_hex));
        fs::write(".env", env_content).unwrap();

        key_hex
    });

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&hex::decode(key)?));

    Ok(cipher)
}

pub fn encrypt_and_store_private_key(
    signing_key: &SigningKey,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let symmetric_key = load_symmetric_key()?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = symmetric_key
        .encrypt(&nonce, signing_key.to_bytes().as_ref())
        .unwrap();

    let mut data_to_store = Vec::new();
    data_to_store.extend_from_slice(&nonce);
    data_to_store.extend_from_slice(&ciphertext);

    fs::write(file_path, &data_to_store)?;

    Ok(())
}

pub fn load_and_decrypt_private_key(
    file_path: &str,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let encrypted_data = std::fs::read(file_path)?;
    let symmetric_key = load_symmetric_key()?;

    let (nonce, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce);

    let decrypted_plaintext = symmetric_key
        .decrypt(nonce, ciphertext)
        .map_err(|e| e.to_string())?;

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
        // generate a signing key
        let signing_key = create_signing_key();

        let file_path = "test_encrypted_key";

        // encrypt and store the private key
        encrypt_and_store_private_key(&signing_key, file_path)
            .expect("Fehler beim Verschlüsseln und Speichern");

        // load and decrypt the private key
        let decrypted_key =
            load_and_decrypt_private_key(file_path).expect("Fehler beim Laden und Entschlüsseln");

        // check if the keys are the same
        assert_eq!(
            signing_key.to_bytes(),
            decrypted_key.to_bytes(),
            "Die Schlüssel stimmen nicht überein"
        );

        // remove the test file
        std::fs::remove_file(file_path).expect("Fehler beim Löschen der Testdatei");
    }

    #[test]
    fn test_encrypt_and_decrypt_private_key_with_wrong_nonce() {
        // generate a signing key
        let signing_key = create_signing_key();

        let file_path = "test_encrypted_key";

        // encrypt and store the private key
        encrypt_and_store_private_key(&signing_key, file_path)
            .expect("Fehler beim Verschlüsseln und Speichern");

        let encrypted_data = std::fs::read(file_path).unwrap();
        let symmetric_key = load_symmetric_key().unwrap();

        let (_nonce, ciphertext) = encrypted_data.split_at(12);
        let new_nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let decryption_result = symmetric_key
            .decrypt(&new_nonce, ciphertext)
            .map_err(|e| e.to_string());

        assert!(decryption_result.is_err(), "cant decrypt with wrong nonce");

        // remove the test file
        std::fs::remove_file(file_path).expect("Fehler beim Löschen der Testdatei");
    }
}
