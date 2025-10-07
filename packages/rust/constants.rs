pub const BLOCK_SIZE: usize = 16;
pub const NONCE_SIZE: usize = BLOCK_SIZE - 4;
pub const TAG_SIZE: usize = BLOCK_SIZE;
pub const ZEROED_BLOCK: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
