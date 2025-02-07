# keystore

Keystore-rs is a Rust library for securely storing and managing cryptographic keys.

## Features

- Secure ED25519 key generation
- Key storage and retrieval
- Supports macOS and Linux keychain integration

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
keystore-rs = "0.3.0"
```

or

```bash
cargo add keystore-rs
```

## Usage

The library provides two main storage implementations:

- FileStore: Encrypted file-based storage using AES-256-GCM
- KeyChain: System keychain integration (macOS/Linux)

### File-based Storage

```rust
use keystore_rs::{create_signing_key, KeyStore, FileStore};
use anyhow::Result;

fn main() -> Result<()> {
    // Set up symmetric key for file encryption (required for FileStore)
    std::env::set_var("SYMMETRIC_KEY", "your-32-byte-hex-encoded-key");
    
    // Create a file-based keystore
    let file_store = FileStore::new("~/.keystore/keys.json")?;

    // Create and store a new signing key
    let signing_key = create_signing_key();
    file_store.add_signing_key("my-key-1", &signing_key)?;

    // Retrieve the signing key (will return an error if it doesnt exist)
    let retrieved_key = file_store.get_signing_key("my-key-1")?;

    // Get or create a key (creates the key if it doesn't exist)
    let key = file_store.get_or_create_signing_key("my-key-2")?;
    
    Ok(())
}
```

### System Keychain

```rust
use keystore_rs::{create_signing_key, KeyStore, KeyChain};
use anyhow::Result;

fn main() -> Result<()> {
    let keychain = KeyChain;
    
    // Create and store a new signing key
    let signing_key = create_signing_key();
    keychain.add_signing_key("my-key-1", &signing_key)?;

    // Retrieve the signing key
    let retrieved_key = keychain.get_signing_key("my-key-1")?;

    // Get or create a key (creates if doesn't exist)
    let key = keychain.get_or_create_signing_key("my-key-2")?;
    
    Ok(())
}
```

## Contributing

Contributions are welcome! Please feel free to get in touch.

## License

This project is licensed under the MIT License.
