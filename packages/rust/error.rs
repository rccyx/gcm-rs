use std::fmt::{self, Display, Formatter};

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidNonceSize { expected_size: usize },
    InvalidKeySize,
    InvalidTag,
}

impl Display for Error {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self {
            Error::InvalidNonceSize { expected_size } => {
                write!(
                    fmt,
                    "invalid nonce size, expected {}",
                    expected_size
                )
            }
            Error::InvalidKeySize => {
                write!(fmt, "invalid key size")
            }
            Error::InvalidTag => {
                write!(fmt, "invalid authentication tag")
            }
        }
    }
}

impl std::error::Error for Error {}
