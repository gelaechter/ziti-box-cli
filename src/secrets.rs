use color_eyre::eyre::{Context, Result, eyre};
use keyring::KeyringEntry;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{LazyLock, OnceLock},
};

use async_trait::async_trait;

use crate::config::Serializable;

static KEY_STORE: OnceLock<Box<dyn KeyStore>> = OnceLock::new();

const NO_ENTRY_ERROR: &str =
    "secret not in keystore despite previous configuration... did you change your keystore mode?
    rerun first time configuration using the configure command";

/// File used when in basic keystore mode
static SECRETS_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    dirs_next::config_dir()
        .unwrap()
        .join("zitibox/secrets.json")
});

/// Gives you access to the Keystore
pub fn key_store() -> &'static dyn KeyStore {
    KEY_STORE
        .get()
        .expect("The key store should be initalized at program startup")
        .as_ref()
}

pub fn init_key_store(key_store: Box<dyn KeyStore>) {
    KEY_STORE
        .set(key_store)
        .ok()
        .expect("The key store should be initialized exactly once at program startup");
}

/// A Key Value store for credentials
/// There currently are BasicKeyStore and FreeDesktopKeystore available
#[async_trait] // We have to use async trait because async fns are not dyn compatible
pub trait KeyStore: Send + Sync {
    /// Lets read a secret stored for a key
    async fn get_secret(&self, key: &str) -> Result<String>;
    async fn set_secret(&self, key: &str, secret: &str) -> Result<()>;
}

/// KeyStore that stores secrets in plaintext inside the config directory
pub struct BasicKeystore {}
/// KeyStore that stores secrets using the FreeDesktop Secret Service
pub struct FreeDesktopKeystore {}

impl BasicKeystore {
    pub fn new() -> Self {
        BasicKeystore {}
    }
}

impl FreeDesktopKeystore {
    pub fn new() -> Self {
        FreeDesktopKeystore {}
    }
}

#[async_trait]
impl KeyStore for BasicKeystore {
    async fn get_secret(&self, key: &str) -> Result<String> {
        let keys = HashMap::<String, String>::load_from_file(&SECRETS_PATH).await?;

        keys
            // The way to take/consume a value (not reference) from a HashMap is removing it
            .and_then(|mut map| map.remove(key))
            // It is possible that the user changes the key store mode when having already created a config
            // This would result in requesting keys that dont exist (yet)
            .ok_or(eyre!(NO_ENTRY_ERROR))
    }

    async fn set_secret(&self, key: &str, secret: &str) -> Result<()> {
        let mut keys = HashMap::<String, String>::load_from_file(&SECRETS_PATH)
            .await?
            .unwrap_or_default();

        keys.insert(key.to_string(), secret.to_string());

        keys.save_to_file(&SECRETS_PATH).await
    }
}

#[async_trait]
impl KeyStore for FreeDesktopKeystore {
    async fn get_secret(&self, key: &str) -> Result<String> {
        let entry = KeyringEntry::try_new(key)?;

        let secret = entry.get_secret().await;

        match secret {
            Ok(secret) => Ok(secret),
            // It is possible that the user changes the key store mode when having already created a config
            // This would result in requesting keys that dont exist (yet)
            Err(keyring::Error::GetSecretError(keyring::native::Error::NoEntry, _)) => {
                Err(eyre!(NO_ENTRY_ERROR))
            }
            Err(e) => Err(eyre!(
                "Couldn't get secret from the FreeDesktop Secret Service.
                If no Secret Service is available use the --basic-keystore option.\n{e:#?}"
            )),
        }
    }

    async fn set_secret(&self, key: &str, secret: &str) -> Result<()> {
        let entry = KeyringEntry::try_new(key)?;
        entry.set_secret(secret).await.wrap_err(
            "Couldn't set a secret in the FreeDesktop Secret Service.
            If no Secret Service is available use the --basic-keystore option.",
        )
    }
}
