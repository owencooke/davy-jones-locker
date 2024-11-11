use super::{item::SERVICE_NAME, EncryptedItem, SecureStorage, StorageError};

use base64::{engine::general_purpose::STANDARD as b64_engine, Engine};
use libsecret::{self, Schema, SchemaAttributeType};
use std::collections::HashMap;

pub struct LinuxStorage {
    schema: Schema,
}

impl LinuxStorage {
    pub fn new() -> Self {
        // Create schema with required attributes
        let mut attribute_types = HashMap::new();
        attribute_types.insert("service", SchemaAttributeType::String);
        attribute_types.insert("id", SchemaAttributeType::String);

        let schema = Schema::new(
            "org.freedesktop.Secret.Generic",
            libsecret::SchemaFlags::NONE,
            attribute_types,
        );

        Self { schema }
    }
}

impl SecureStorage for LinuxStorage {
    fn save(&self, item: &EncryptedItem) -> Result<(), StorageError> {
        // Convert the encrypted item to base64 to store as string
        let b64 = b64_engine.encode(&item.encrypted_data);

        // Store the password using libsecret
        libsecret::password_store_sync(
            Some(&self.schema),
            get_attributes_with_id(item.id.as_str()),
            Some(&libsecret::COLLECTION_DEFAULT),
            &format!("{}/{}", SERVICE_NAME, item.id),
            &b64,
            gio::Cancellable::NONE,
        )
        .map_err(|e| StorageError::Storage(e.to_string()))?;

        Ok(())
    }

    fn load(&self, id: &str) -> Result<EncryptedItem, StorageError> {
        let secret = libsecret::password_lookup_sync(
            Some(&self.schema),
            get_attributes_with_id(id),
            gio::Cancellable::NONE,
        )
        .map_err(|e| StorageError::Storage(e.to_string()))?
        .ok_or(StorageError::NotFound)?;

        // Convert base64 string back to bytes
        let encrypted_data = b64_engine
            .decode(secret.as_str())
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        Ok(EncryptedItem {
            id: id.to_string(),
            encrypted_data,
            nonce: vec![], // You'll need to handle nonce storage separately
        })
    }

    fn delete(&self, id: &str) -> Result<(), StorageError> {
        libsecret::password_clear_sync(
            Some(&self.schema),
            get_attributes_with_id(id),
            gio::Cancellable::NONE,
        )
        .map_err(|e| StorageError::Storage(e.to_string()))?;

        Ok(())
    }
}

fn get_attributes_with_id(id: &str) -> HashMap<&str, &str> {
    let mut attributes = HashMap::new();
    attributes.insert("service", SERVICE_NAME);
    attributes.insert("id", id);
    attributes
}

// Add tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_load_delete() {
        let storage = LinuxStorage::new();

        let test_item = EncryptedItem {
            id: "test-id".to_string(),
            encrypted_data: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7, 8],
        };

        // Test save
        storage.save(&test_item).unwrap();

        // Test load
        let loaded_item = storage.load(&test_item.id).unwrap();
        assert_eq!(loaded_item.id, test_item.id);
        assert_eq!(loaded_item.encrypted_data, test_item.encrypted_data);

        // Test delete
        storage.delete(&test_item.id).unwrap();

        // Verify deletion
        assert!(storage.load(&test_item.id).is_err());
    }
}
