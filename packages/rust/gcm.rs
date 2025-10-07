use crate::constants::TAG_SIZE;
use crate::constants::{BLOCK_SIZE, NONCE_SIZE, ZEROED_BLOCK};
use crate::ctr::Aes256Ctr32;
use crate::error::Error;
use crate::types::{BlockBytes, Bytes, Key, Nonce, Result};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use ghash::universal_hash::UniversalHash;
use ghash::GHash;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct GcmGhash {
    ghash: GHash,
    // sensitive buffers
    ghash_padding: BlockBytes,
    msg_buffer: BlockBytes,
    // non-sensitive counters/lengths
    msg_buffer_offset: usize,
    ad_len: usize,
    msg_len: usize,
}

impl GcmGhash {
    fn new(
        h: &BlockBytes,
        ghash_padding: BlockBytes,
        associated_data: &Bytes,
    ) -> Result<Self> {
        let mut ghash = GHash::new(h.into());

        ghash.update_padded(associated_data);

        Ok(Self {
            ghash,
            ghash_padding,
            msg_buffer: ZEROED_BLOCK,
            msg_buffer_offset: 0,
            ad_len: associated_data.len(),
            msg_len: 0,
        })
    }

    pub fn update(&mut self, msg: &Bytes) {
        if self.msg_buffer_offset > 0 {
            let taking = std::cmp::min(
                msg.len(),
                BLOCK_SIZE - self.msg_buffer_offset,
            );
            self.msg_buffer[self.msg_buffer_offset
                ..self.msg_buffer_offset + taking]
                .copy_from_slice(&msg[..taking]);
            self.msg_buffer_offset += taking;
            assert!(self.msg_buffer_offset <= BLOCK_SIZE);

            self.msg_len += taking;

            if self.msg_buffer_offset == BLOCK_SIZE {
                self.ghash.update(std::slice::from_ref(
                    ghash::Block::from_slice(&self.msg_buffer),
                ));
                self.msg_buffer_offset = 0;
                return self.update(&msg[taking..]);
            } else {
                return;
            }
        }

        self.msg_len += msg.len();

        assert_eq!(self.msg_buffer_offset, 0);
        let full_blocks = msg.len() / BLOCK_SIZE;
        let leftover = msg.len() - BLOCK_SIZE * full_blocks;
        assert!(leftover < BLOCK_SIZE);
        if full_blocks > 0 {
            let blocks = unsafe {
                std::slice::from_raw_parts(
                    msg[..BLOCK_SIZE * full_blocks].as_ptr().cast(),
                    full_blocks,
                )
            };
            assert_eq!(
                std::mem::size_of_val(blocks) + leftover,
                std::mem::size_of_val(msg)
            );
            self.ghash.update(blocks);
        }

        self.msg_buffer[0..leftover]
            .copy_from_slice(&msg[full_blocks * BLOCK_SIZE..]);
        self.msg_buffer_offset = leftover;
        assert!(self.msg_buffer_offset < BLOCK_SIZE);
    }

    /// Finalize GHASH and return the authentication subtag.
    /// Does not consume `self` to avoid moving fields out of a type that implements Drop.
    pub fn finalize_tag(&mut self) -> BlockBytes {
        if self.msg_buffer_offset > 0 {
            self.ghash.update_padded(
                &self.msg_buffer[..self.msg_buffer_offset],
            );
        }

        let mut final_block = ZEROED_BLOCK;
        final_block[..8]
            .copy_from_slice(&(8 * self.ad_len as u64).to_be_bytes());
        final_block[8..].copy_from_slice(
            &(8 * self.msg_len as u64).to_be_bytes(),
        );

        self.ghash.update(&[final_block.into()]);
        let mut hash = self.ghash.clone().finalize();

        for (i, b) in hash.iter_mut().enumerate() {
            *b ^= self.ghash_padding[i];
        }

        hash.into()
    }
}

impl Zeroize for GcmGhash {
    fn zeroize(&mut self) {
        self.ghash_padding.zeroize();
        self.msg_buffer.zeroize();
        // integers do not implement Zeroize; wipe manually
        self.msg_buffer_offset = 0;
        self.ad_len = 0;
        self.msg_len = 0;
    }
}

impl Drop for GcmGhash {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn setup(
    key: &Key,
    nonce: &Nonce,
    associated_data: &Bytes,
) -> Result<(Aes256Ctr32, GcmGhash)> {
    if nonce.len() != NONCE_SIZE {
        return Err(Error::InvalidNonceSize {
            expected_size: NONCE_SIZE,
        });
    }

    let aes256: Aes256 = Aes256::new_from_slice(key)
        .map_err(|_| Error::InvalidKeySize)?;
    let mut h = ZEROED_BLOCK;
    aes256.encrypt_block(GenericArray::from_mut_slice(&mut h));

    // Start CTR at block 1 per GCM spec
    let mut ctr = Aes256Ctr32::new(aes256, nonce, 1)?;

    let mut ghash_padding = ZEROED_BLOCK;
    // This contains keystream derived from key and nonce. Consider it sensitive.
    ctr.xor(&mut ghash_padding);

    let ghash = GcmGhash::new(&h, ghash_padding, associated_data)?;
    Ok((ctr, ghash))
}

pub struct Aes256Gcm {
    ctr: Aes256Ctr32,
    ghash: GcmGhash,
}

impl Aes256Gcm {
    pub fn new(
        key: &Key,
        nonce: &Nonce,
        associated_data: &Bytes,
    ) -> Result<Self> {
        let (ctr, ghash) = setup(key, nonce, associated_data)?;
        Ok(Self { ctr, ghash })
    }

    pub fn finalize(mut self) -> BlockBytes {
        self.ghash.finalize_tag()
    }
}

// Ensure buffers are wiped on drop if tag was not computed.
impl Drop for Aes256Gcm {
    fn drop(&mut self) {
        // ctr state and AES internals are handled by their crates with "zeroize" features.
        self.ghash.zeroize();
    }
}

pub trait Encrypt {
    fn encrypt(&mut self, buf: &mut Bytes);
    fn compute_tag(self) -> BlockBytes;
}

pub trait Decrypt {
    fn decrypt(&mut self, buf: &mut Bytes);
    fn verify_tag(self, tag: &Bytes) -> Result<()>;
}

impl Encrypt for Aes256Gcm {
    fn encrypt(&mut self, buf: &mut Bytes) {
        self.ctr.xor(buf);
        self.ghash.update(buf);
    }

    fn compute_tag(self) -> BlockBytes {
        self.finalize()
    }
}

impl Decrypt for Aes256Gcm {
    fn decrypt(&mut self, buf: &mut Bytes) {
        self.ghash.update(buf);
        self.ctr.xor(buf);
    }

    fn verify_tag(self, tag: &Bytes) -> Result<()> {
        if tag.len() != TAG_SIZE {
            return Err(Error::InvalidTag);
        }

        let computed_tag = self.finalize();
        let tag_ok: subtle::Choice = tag.ct_eq(&computed_tag);

        if !bool::from(tag_ok) {
            return Err(Error::InvalidTag);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::{gen_key, gen_nonce};

    #[test]
    fn test_aes256_gcm_encryption_decryption() {
        let key = gen_key();
        let nonce = gen_nonce();
        let associated_data = b"associated_data";
        let plaintext = b"plaintext";

        let mut gcm =
            Aes256Gcm::new(&key, &nonce, associated_data).unwrap();

        let mut ciphertext = plaintext.to_vec();
        gcm.encrypt(&mut ciphertext);

        let tag = gcm.compute_tag();

        let mut gcm_decrypt =
            Aes256Gcm::new(&key, &nonce, associated_data).unwrap();
        gcm_decrypt.decrypt(&mut ciphertext);

        assert_eq!(&ciphertext, plaintext);
        assert!(gcm_decrypt.verify_tag(&tag).is_ok());
    }

    #[test]
    fn test_zeroize_gcmghash_buffers() {
        // Build a GHASH with non-zero buffers
        let key = gen_key();
        let nonce = gen_nonce();
        let ad = b"ad";
        let (_ctr, mut ghash) = setup(&key, &nonce, ad).unwrap();

        // Dirty the internal buffers
        ghash.msg_buffer.copy_from_slice(&[0xAAu8; BLOCK_SIZE]);
        ghash.ghash_padding.copy_from_slice(&[0xBBu8; BLOCK_SIZE]);
        ghash.msg_buffer_offset = 7;
        ghash.ad_len = 123;
        ghash.msg_len = 456;

        ghash.zeroize();
        assert_eq!(ghash.msg_buffer, [0u8; BLOCK_SIZE]);
        assert_eq!(ghash.ghash_padding, [0u8; BLOCK_SIZE]);
        assert_eq!(ghash.msg_buffer_offset, 0);
        assert_eq!(ghash.ad_len, 0);
        assert_eq!(ghash.msg_len, 0);
    }
}
