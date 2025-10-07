use crate::constants::BLOCK_SIZE;
use crate::error::Error;
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

pub type Bytes = [u8];
pub type BlockBytes = [u8; BLOCK_SIZE];
pub type Nonce = Bytes;
pub type Key = Bytes;
pub type StartBlock = u32;
