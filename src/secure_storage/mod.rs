pub mod error;
pub mod item;
pub mod native_messaging;

#[cfg(target_os = "linux")]
mod linux;

pub use error::StorageError;
pub use item::EncryptedItem;

pub trait SecureStorage {
    async fn save(&self, item: &EncryptedItem) -> Result<(), StorageError>;
    async fn load(&self, id: &str) -> Result<EncryptedItem, StorageError>;
    async fn delete(&self, id: &str) -> Result<(), StorageError>;
}
