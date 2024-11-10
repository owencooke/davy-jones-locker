use super::error::StorageError;
use super::{item::Credentials, linux, EncryptedItem, SecureStorage};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use getrandom;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
pub use linux::LinuxStorage;

pub struct NativeMessaging {
    storage: Box<dyn SecureStorage>,
    cipher: Aes256Gcm,
}

#[derive(Serialize, Deserialize)]
pub enum ExtensionMessage {
    GetPassword { url: String },
    SavePassword { credentials: Credentials },
    DeletePassword { url: String },
}

#[derive(Serialize, Deserialize)]
pub enum NativeResponse {
    Password(Credentials),
    Success,
    Error(String),
}

impl NativeMessaging {
    pub fn new(master_key: &[u8]) -> Self {
        let storage: Box<dyn SecureStorage> = if cfg!(target_os = "linux") {
            Box::new(LinuxStorage::new("password_manager_service"))
        } else {
            unimplemented!("Platform not supported")
        };

        let cipher = Aes256Gcm::new_from_slice(master_key).expect("Invalid key length");

        Self { storage, cipher }
    }

    pub async fn handle_message(&self, message: ExtensionMessage) -> NativeResponse {
        match message {
            ExtensionMessage::GetPassword { url } => match self.get_password(&url) {
                Ok(creds) => NativeResponse::Password(creds),
                Err(e) => NativeResponse::Error(e.to_string()),
            },
            ExtensionMessage::SavePassword { credentials } => {
                match self.save_password(&credentials) {
                    Ok(()) => NativeResponse::Success,
                    Err(e) => NativeResponse::Error(e.to_string()),
                }
            }
            ExtensionMessage::DeletePassword { url } => match self.storage.delete(&url) {
                Ok(()) => NativeResponse::Success,
                Err(e) => NativeResponse::Error(e.to_string()),
            },
        }
    }

    fn get_password(&self, url: &str) -> Result<Credentials, StorageError> {
        let encrypted = self.storage.load(&[], url)?;

        let nonce = Nonce::from_slice(&encrypted.nonce);
        let decrypted = self
            .cipher
            .decrypt(nonce, encrypted.encrypted_data.as_slice())
            .map_err(|e| StorageError::Encryption(e.to_string()))?;

        let credentials: Credentials = serde_json::from_slice(&decrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        Ok(credentials)
    }

    fn save_password(&self, credentials: &Credentials) -> Result<(), StorageError> {
        let data = serde_json::to_vec(&credentials)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| StorageError::Encryption(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .encrypt(nonce, data.as_slice())
            .map_err(|e| StorageError::Encryption(e.to_string()))?;

        let item = EncryptedItem {
            id: credentials.url.clone(),
            encrypted_data: encrypted,
            nonce: nonce_bytes.to_vec(),
        };

        self.storage.save(&[], &item)
    }
}
