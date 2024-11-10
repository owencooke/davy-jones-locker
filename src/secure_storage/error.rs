use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Item not found")]
    NotFound,
    #[error("Platform error: {0}")]
    Platform(String),
}
