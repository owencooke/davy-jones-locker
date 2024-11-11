use super::{EncryptedItem, SecureStorage, StorageError};

use libsecret::{self, Schema, SchemaAttributeType};
use std::collections::HashMap;

pub struct LinuxStorage {
    schema: Schema,
    service_name: String,
}

impl LinuxStorage {
    pub fn new(service_name: String) -> Self {
        // Create schema with required attributes
        let mut attributes = HashMap::new();
        attributes.insert("service", SchemaAttributeType::String);
        attributes.insert("id", SchemaAttributeType::String);

        let schema = Schema::new(
            "org.freedesktop.Secret.Generic",
            libsecret::SchemaFlags::NONE,
            attributes,
        );

        Self {
            schema,
            service_name,
        }
    }
}

impl SecureStorage for LinuxStorage {
    async fn save(&self, item: &EncryptedItem) -> Result<(), StorageError> {
        let mut attributes = HashMap::new();
        attributes.insert("service", self.service_name.as_str());
        attributes.insert("id", &item.id);

        // Convert the encrypted item to base64 to store as string
        let serialized_data = base64::encode(&item.encrypted_data);

        // Store the password using libsecret
        libsecret::password_store_future(
            Some(&self.schema),
            attributes,
            Some(&libsecret::COLLECTION_DEFAULT),
            &format!("{}/{}", self.service_name, item.id),
            &serialized_data,
        )
        .await
        .map_err(|e| StorageError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn load(&self, id: &str) -> Result<EncryptedItem, StorageError> {
        let mut attributes = HashMap::new();
        attributes.insert("service", self.service_name.as_str());
        attributes.insert("id", id);

        let secret = libsecret::password_lookup_future(Some(&self.schema), attributes)
            .await
            .map_err(|e| StorageError::Storage(e.to_string()))?
            .ok_or(StorageError::NotFound)?;

        // Convert base64 string back to bytes
        let encrypted_data = base64::decode(secret.as_str())
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        Ok(EncryptedItem {
            id: id.to_string(),
            encrypted_data,
            nonce: vec![], // You'll need to handle nonce storage separately
        })
    }

    async fn delete(&self, id: &str) -> Result<(), StorageError> {
        let mut attributes = HashMap::new();
        attributes.insert("service", self.service_name.as_str());
        attributes.insert("id", id);

        libsecret::password_clear_future(Some(&self.schema), attributes)
            .await
            .map_err(|e| StorageError::Storage(e.to_string()))?;

        Ok(())
    }
}

// Add tests
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_save_load_delete() {
        let storage = LinuxStorage::new("test-service".to_string());

        let test_item = EncryptedItem {
            id: "test-id".to_string(),
            encrypted_data: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7, 8],
        };

        // Test save
        storage.save(&test_item).await.unwrap();

        // Test load
        let loaded_item = storage.load(&test_item.id).await.unwrap();
        assert_eq!(loaded_item.id, test_item.id);
        assert_eq!(loaded_item.encrypted_data, test_item.encrypted_data);

        // Test delete
        storage.delete(&test_item.id).await.unwrap();

        // Verify deletion
        assert!(storage.load(&test_item.id).await.is_err());
    }
}
