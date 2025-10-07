<div align="center">

# gcm_rs

AES-256-GCM in Rust with a Python extension via PyO3. Safe internals, zeroize on sensitive buffers, and a simple API for authenticated encryption.
</div>

## What It Does

- AES-256 in CTR-32 mode with GHASH per NIST SP 800-38D
- 12 byte nonce, 16 byte tag
- Constant time tag verification
- Zeroize for sensitive in-memory data
- Rust crate for direct use
- Python wheels built with maturin


## Setup

### Python

```bash
pip install gcm_rs
```

### Rust

```bash
cargo add gcm_rs
```

## Usage

### Rust

```rust
use gcm_rs::gcm::{Aes256Gcm, Encrypt, Decrypt};
use gcm_rs::random::{gen_key, gen_nonce};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = gen_key();            // 32 bytes
    let nonce = gen_nonce();        // 12 bytes
    let ad = b"header";             // associated data

    let mut pt = b"attack at dawn".to_vec();

    // encrypt
    let mut enc = Aes256Gcm::new(&key, &nonce, ad)?;
    let mut ct = pt.clone();
    enc.encrypt(&mut ct);
    let tag = enc.compute_tag();

    // decrypt and verify
    let mut dec = Aes256Gcm::new(&key, &nonce, ad)?;
    let mut out = ct.clone();
    dec.decrypt(&mut out);
    dec.verify_tag(&tag)?;
    assert_eq!(out, pt);

    Ok(())
}
```

### Python

Current helpers:

```python
from gcm_rs import gen_key, gen_nonce

key = gen_key()     # 32 bytes
nonce = gen_nonce() # 12 bytes
print(len(key), len(nonce))
```

> Planned in the next release: a `Gcm` class with `new`, `encrypt`, `decrypt`, `compute_tag`, and `verify_tag` that returns and accepts `bytes`.


## API overview (rs)

```rust
use gcm_rs::gcm::{Aes256Gcm, Encrypt, Decrypt};

// construct
let mut gcm = Aes256Gcm::new(key, nonce, associated_data)?;

// streaming style
gcm.encrypt(buf_chunk_1);
gcm.encrypt(buf_chunk_2);
let tag = gcm.compute_tag();

// decrypt + verify
let mut gcm2 = Aes256Gcm::new(key, nonce, associated_data)?;
gcm2.decrypt(buf_all);
gcm2.verify_tag(tag)?;
```

- `key`: `&[u8]` length 32
- `nonce`: `&[u8]` length 12
- `associated_data`: `&[u8]` any length
- `tag`: 16 bytes

Internals
- CTR starts at block `J0 + 1` per the spec.
- GHASH runs over associated data and ciphertext, then final length block, then pads with the precomputed keystream block.


## License

GPL-3.0

