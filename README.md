# gcm_rs

Low level implentation of AES-256 GCM in Rust with Python bindings. Explicit, and opinionated.

> [!Warning]
>
> This create is **still experimental**, it's **not** audited. The API is still moving, the internals are still in flux, and breaking changes ~~can~~ will happen at any minor or patch release.

## What it does

- AES-256 in CTR-32 mode with GHASH as specified in NIST SP 800-38D
- 256 bit key, 96 bit nonce, 128 bit authentication tag
- Streaming interface for GHASH so you can process arbitrarily sized messages
- Constant time authentication tag verification
- Zeroization of sensitive buffers
- Rust crate for direct use
- Python bindings that expose safe random key and nonce helpers

## Install

### Rust

```bash
cargo add gcm_rs
```

### Python

```bash
pip install gcm_rs
```

The Python package ships prebuilt wheels for common architectures when available. If that fails, it will build the extension from source, so you need a Rust toolchain installed.

## Quickstart

### Rust example

```rust
use gcm_rs::gcm::{Aes256Gcm, Encrypt, Decrypt};
use gcm_rs::random::{gen_key, gen_nonce};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = gen_key();            // 32 bytes
    let nonce = gen_nonce();        // 12 bytes
    let ad = b"header";             // associated data, optional but must match

    let mut pt = b"attack at dawn".to_vec();

    // encrypt in place
    let mut enc = Aes256Gcm::new(&key, &nonce, ad)?;
    let mut ct = pt.clone();
    enc.encrypt(&mut ct);
    let tag = enc.compute_tag();    // 16 byte authentication tag

    // decrypt and verify
    let mut dec = Aes256Gcm::new(&key, &nonce, ad)?;
    let mut out = ct.clone();
    dec.decrypt(&mut out);
    dec.verify_tag(&tag)?;

    assert_eq!(out, pt);
    Ok(())
}
```

### Python example

The Rust core already implements full AES-GCM. Higher level Python encryption and decryption helpers are being designed and are **not** considered stable yet. Expect the Python API to change more than the Rust core while the project is in super beta. These are the only two exported functions as of now, simply as a POC.

```python
from gcm_rs import gen_key, gen_nonce

key = gen_key()     # 32 bytes
nonce = gen_nonce() # 12 bytes

print(len(key), len(nonce))  # 32 12
```

## Rust API overview

### One shot encrypt / decrypt

```rust
use gcm_rs::gcm::{Aes256Gcm, Encrypt, Decrypt};
use gcm_rs::random::{gen_key, gen_nonce};
use gcm_rs::constants::{TAG_SIZE, NONCE_SIZE};

fn encrypt_one_shot(
    key: &[u8],
    nonce: &[u8; NONCE_SIZE],
    ad: &[u8],
    pt: &[u8],
) -> (Vec<u8>, [u8; TAG_SIZE]) {
    let mut ct = pt.to_vec();
    let mut enc = Aes256Gcm::new(key, nonce, ad).unwrap();
    enc.encrypt(&mut ct);
    let tag = enc.compute_tag();
    (ct, tag)
}

fn decrypt_one_shot(
    key: &[u8],
    nonce: &[u8; NONCE_SIZE],
    ad: &[u8],
    ct: &mut [u8],
    tag: &[u8],
) -> Result<(), gcm_rs::error::Error> {
    let mut dec = Aes256Gcm::new(key, nonce, ad)?;
    dec.decrypt(ct);
    dec.verify_tag(tag)
}
```

### Streaming usage

You can feed arbitrarily large buffers in chunks. GHASH keeps internal state and only finalizes in `compute_tag` / `verify_tag`.

```rust
use gcm_rs::gcm::{Aes256Gcm, Encrypt, Decrypt};
use gcm_rs::random::{gen_key, gen_nonce};

let key = gen_key();
let nonce = gen_nonce();
let ad = b"hdr";

let mut chunks = vec![
    b"hello ".to_vec(),
    b"world ".to_vec(),
    b"and beyond".to_vec(),
];

// encrypt in chunks
let mut enc = Aes256Gcm::new(&key, &nonce, ad).unwrap();
for chunk in &mut chunks {
    enc.encrypt(chunk);
}
let tag = enc.compute_tag();

// join ciphertext back together
let mut ct = chunks.concat();

// decrypt
let mut dec = Aes256Gcm::new(&key, &nonce, ad).unwrap();
dec.decrypt(&mut ct);
dec.verify_tag(&tag).unwrap();
```

## Security notes

- **Nonce handling**
  `NONCE_SIZE` is 12 bytes. Nonce size is checked. You're responsible for choosing nonces correctly.

- **Associated data (AD)**
  AD is fully authenticated but not encrypted. Any single bit mismatch between the AD used for encryption and the AD used for decryption will cause `InvalidTag`.

- **Constant time tag check**
  Tag verification uses `subtle::ConstantTimeEq`. If a tag is wrong, you still need to treat that as an authentication failure and discard the plaintext.

- **Zeroization**
  Internal buffers that hold keystream material and GHASH state are wiped on drop where possible. That doesn't magically protect against all side channels, process dumps, or kernel level attacks.

- **No misuse resistance**
  This crate is a direct implementation of AES-GCM. It does not provide misuse resistant APIs. There is no key hierarchy, no automatic nonce management, and no protocol guidance. It's your responsibility to build a safe protocol around it.

## License

Licensed under **GPL-3.0**. See [`LICENSE`](./LICENSE) for details.
