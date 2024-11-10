use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedItem {
    pub id: String,
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub url: String,
}
