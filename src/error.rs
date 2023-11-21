use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error("serialization error")]
    Serialization,

    #[error("deserialization error")]
    Deserialization,

    #[error("read error")]
    Read,

    #[error("write error")]
    Write,

    #[error("seek error")]
    Seek,

    #[error("encryption error")]
    Encrypt,

    #[error("decryption error")]
    Decrypt,

    #[error("storage error")]
    Storage,

    #[error("unknown error")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, Error>;
