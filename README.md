# keystore

Keystore-rs is a Rust library for securely storing and managing cryptographic keys.

## Features

- Secure key generation
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

Here is a basic example of how to use Keystore:

```rust
use keystore_rs::{create_signing_key, KeyStore, KeyStoreType, FileStore};

fn main() {
    // Create a new signing key
    let signing_key = create_signing_key();

    // Create a file-based keystore
    let file_store = FileStore::new("keyfile");

    // Create a keystore enum
    let keystore = KeyStoreType::FileStore(file_store);

    // Add the signing key to the keystore
    keystore.add_signing_key("my-key-1", &signing_key)?;

    // Retrieve the signing key from the keystore
    let retrieved_key = keystore.get_signing_key("my-key-1")?;

    // Get a key, creating it if it doesn't exist
    let key = file_store.get_or_create_signing_key("my-key-2")?;
}
```

## Contributing

Contributions are welcome! Please feel free to get in touch.

## License

This project is licensed under the MIT License.
