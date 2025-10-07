use crate::constants::{BLOCK_SIZE, NONCE_SIZE};
use crate::error::Error;
use crate::types::{Bytes, Key, Nonce, Result, StartBlock};
use aes::cipher::KeyInit;
use aes::cipher::{InnerIvInit, StreamCipher, StreamCipherSeek};
use aes::Aes256;

pub struct Aes256Ctr32(ctr::Ctr32BE<Aes256>);

impl Aes256Ctr32 {
    /// Create a CTR-32 counter starting at `start_block`.
    ///
    /// Per NIST SP 800-38D GCM, payload processing uses the keystream that
    /// begins at counter block J0 + 1. When integrating with GCM pass `start_block = 1`.
    pub fn new(
        algo: Aes256,
        nonce: &Nonce,
        start_block: StartBlock,
    ) -> Result<Self> {
        if !is_valid_nonce_size(nonce, NONCE_SIZE) {
            return Err(Error::InvalidNonceSize {
                expected_size: NONCE_SIZE,
            });
        }
        let mut _nonce_block = [0u8; BLOCK_SIZE];
        _nonce_block[0..NONCE_SIZE].copy_from_slice(nonce);

        let mut ctr = ctr::Ctr32BE::from_core(
            ctr::CtrCore::inner_iv_init(algo, &_nonce_block.into()),
        );
        ctr.seek(BLOCK_SIZE * (start_block as usize));
        Ok(Self(ctr))
    }

    pub fn from_key(
        key: &Key,
        nonce: &Nonce,
        start_block: StartBlock,
    ) -> Result<Self> {
        Self::new(
            Aes256::new_from_slice(key)
                .map_err(|_| Error::InvalidKeySize)?,
            nonce,
            start_block,
        )
    }

    pub fn xor(&mut self, buf: &mut Bytes) {
        self.0.apply_keystream(buf);
    }
}

fn is_valid_nonce_size(nonce: &Nonce, expected_size: usize) -> bool {
    nonce.len() == expected_size
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_aes256_ctr32_encryption_decryption() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let start_block: StartBlock = 0;
        let plaintext = b"plaintext";

        let mut encryption =
            Aes256Ctr32::from_key(&key, &nonce, start_block).unwrap();

        let mut ciphertext = plaintext.to_vec();
        encryption.xor(&mut ciphertext);

        let mut decryption =
            Aes256Ctr32::from_key(&key, &nonce, start_block).unwrap();

        decryption.xor(&mut ciphertext);

        assert_eq!(&ciphertext, plaintext);
    }
}
