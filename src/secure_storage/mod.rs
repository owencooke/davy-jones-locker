pub mod error;
pub mod item;
pub mod native_messaging;

#[cfg(target_os = "linux")]
mod linux;

pub use error::StorageError;
pub use item::EncryptedItem;

pub trait SecureStorage {
    fn save(&self, item: &EncryptedItem) -> Result<(), StorageError>;
    fn load(&self, id: &str) -> Result<EncryptedItem, StorageError>;
    fn delete(&self, id: &str) -> Result<(), StorageError>;
}
