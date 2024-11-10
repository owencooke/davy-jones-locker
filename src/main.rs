mod secure_storage;

use secure_storage::native_messaging::{ExtensionMessage, NativeMessaging};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    let native_messaging = NativeMessaging::new(&master_key);

    let (tx, mut rx) = mpsc::channel(32);

    while let Some(message) = rx.recv().await {
        let response = native_messaging.handle_message(message).await;
        println!("{}", serde_json::to_string(&response)?);
    }

    Ok(())
}
