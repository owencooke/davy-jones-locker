use super::{EncryptedItem, SecureStorage, StorageError};
use libsecret::{Attribute, Collection, Item};

pub struct LinuxStorage {
    service_name: String,
}

impl LinuxStorage {
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }
}

impl SecureStorage for LinuxStorage {
    fn save(&self, _key: &[u8], item: &EncryptedItem) -> Result<(), StorageError> {
        let schema = libsecret::Schema::new(
            "org.freedesktop.Secret.Generic",
            libsecret::SchemaFlags::NONE,
            &[("service", Attribute::String)],
        );

        let serialized_item =
            serde_json::to_vec(&item).map_err(|e| StorageError::Serialization(e.to_string()))?;

        Collection::default()
            .create_item(
                &schema,
                &item.id,
                &[("service", &self.service_name)],
                &serialized_item,
                true,
                "text/plain",
            )
            .map_err(|e| StorageError::Storage(e.to_string()))?;

        Ok(())
    }

    fn load(&self, _key: &[u8], id: &str) -> Result<EncryptedItem, StorageError> {
        let schema = libsecret::Schema::new(
            "org.freedesktop.Secret.Generic",
            libsecret::SchemaFlags::NONE,
            &[("service", Attribute::String)],
        );

        let item = Item::search(&schema, &[("service", &self.service_name), ("id", id)])
            .map_err(|_| StorageError::NotFound)?
            .get_secret()
            .map_err(|_| StorageError::NotFound)?;

        let encrypted_item: EncryptedItem = serde_json::from_slice(&item)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        Ok(encrypted_item)
    }

    fn delete(&self, id: &str) -> Result<(), StorageError> {
        let schema = libsecret::Schema::new(
            "org.freedesktop.Secret.Generic",
            libsecret::SchemaFlags::NONE,
            &[("service", Attribute::String)],
        );

        let item = Item::search(&schema, &[("service", &self.service_name), ("id", id)])
            .map_err(|_| StorageError::NotFound)?;

        item.delete()
            .map_err(|e| StorageError::Storage(e.to_string()))
    }
}
