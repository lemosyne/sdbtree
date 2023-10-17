use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error<E> {
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

    #[error(transparent)]
    Storage(#[from] E),

    #[error("unknown error")]
    Unknown,
}

pub type Result<T, E> = std::result::Result<T, Error<E>>;
