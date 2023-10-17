use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Serde(#[from] bincode::Error),

    #[error("storage error")]
    Storage,

    #[error("unknown error")]
    Unknown,
}
