//! Contains the logic for secret management. This currently includes the account password and the session token.
//!
//! It provides a [`KeyStore`] which can either be [`KeyStore::Basic`] or a [`KeyStore::FreeDesktop`]
//!
//! # [`KeyStore`]
//!
//! A [`KeyStore`] stores credentials in a Key-Value manner, meaning that for a key (e.g. username) you can store a value (e.g. password)
//!
//! Secrets can be stored using [`set_secret`]:
//! ```
//! let key = "my_user";
//! let secret = "my_users_password"
//!
//! let key2 = "my_user2"
//! let secret2 = "my_user2_password"
//!
//! key_store.set_secret(key, secret).await?; // Returns Future with a Result<()>
//! key_store.set_secret("my_user2", "other password").await?
//! ```
//!
//! Secrets can be retrieved using [`get_secret`]:
//! ```
//! let key = "my_user";
//! let password: String = key_store.get_secret(key).await?; // Returns Future with a Result<String>
//! println!("My users password is: {}", password);
//! ```
//!
//! At the start of the Program a KeyStore should be initalized once using [`init_key_store`]:
//! ```
//! let key_store = KeyStore::freedesktop(); // or if required KeyStore::basic()
//! secrets::init_key_store(key_store);
//! ```
//!
//! After that it can be retrieved by using [`key_store`]:
//! ```
//! secrets::init_key_store(KeyStore::freedesktop());
//! let key_store = secrets::key_store(); // Returns the previously initialized FreeDesktop KeyStore
//! ```
//!
//! ## [`KeyStore::Basic`]
//!
//! A [`KeyStore`] variant that uses a plain json file in the config directory to store credentials.
//! Since all credentials are stored unencrypted in plaintext this should only be used when there is no way to provide a Secret Service.
//!
//! It can be initialized using [`KeyStore::basic()`]
//!
//! ## [`KeyStore::FreeDesktop`]
//!
//! A [`KeyStore`] variant that uses the [FreeDesktop Secret Service API](https://specifications.freedesktop.org/secret-service/latest/) to store credentials.
//! This is the recommended [`KeyStore`] variant since the Secret Service API was designed for exactly that purpose.
//!
//! It can be initialized using [`KeyStore::freedesktop()`]

use color_eyre::eyre::Result;
use oo7::Secret;
use std::{
    collections::HashMap,
    error::Error,
    path::PathBuf,
    sync::{LazyLock, OnceLock},
};

use crate::config::Serializable;

/// Global [`KeyStore`] instance
///
/// It must be initialized once using [`crate::secrets::init_key_store`]\
/// After that it can be accessed using [`crate::secrets::key_store`]
static KEY_STORE: OnceLock<KeyStore> = OnceLock::new();

/// service attribute of our FreeDesktop Secret Service entries
const ZBC_SERVICE_NAME: &str = "Ziti Box CLI";

/// Alias for any boxed type that impls Error
type BoxedError = Box<dyn Error + Send + Sync + 'static>;

#[derive(thiserror::Error, Debug)]
pub enum KeyStoreError {
    /// It is possible that the user changes the key store mode
    /// This would cause the CLI to request keys that don't exist in the new key store
    #[error("No entry")]
    NoEntry,
    #[error("Key `{0}` has been defined more than once (this shouldn't be possible)")]
    DuplicateKey(String),
    #[error("The Secret stored for key `{0}` is not of variant Text")]
    NonTextSecret(String),
    #[error(transparent)]
    Other(#[from] BoxedError),
}

impl From<oo7::Error> for KeyStoreError {
    fn from(err: oo7::Error) -> Self {
        KeyStoreError::Other(err.into())
    }
}

/// File used by the [`BasicSecretManager`]
static SECRETS_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    dirs_next::config_dir()
        .unwrap()
        .join("zitibox/secrets.json")
});

/// Initializes the global [`KeyStore`]
pub fn init_key_store(key_store: KeyStore) {
    KEY_STORE
        .set(key_store)
        .ok()
        .expect("The key store should be initialized exactly once at program startup");
}

/// Gives access to the global [`KeyStore`]
pub fn key_store<'a>() -> &'a KeyStore {
    KEY_STORE
        .get()
        .expect("The key store should be initalized at program startup")
}

// ============== public wrapper ==============

#[allow(private_interfaces)] // In this case we want the interfaces to be private, we only want access to the wrapper
/// A [`KeyStore`] stores credentials in a Key-Value manner, meaning that for a key (e.g. username) you can store a value (e.g. password)
pub enum KeyStore {
    Basic(BasicSecretManager),
    FreeDesktop(FreeDesktopSecretManager),
}

impl KeyStore {
    /// Creates a keystore storing the secrets in a plaintext file
    pub const fn basic() -> Self {
        Self::Basic(BasicSecretManager {})
    }

    /// Creates a keystore leveraging FreeDesktop Secret Service to store its secrets
    pub async fn freedesktop() -> Result<Self> {
        let key_store = Self::FreeDesktop(FreeDesktopSecretManager {
            keyring: oo7::Keyring::new().await?,
        });

        Ok(key_store)
    }
}

// Forward KeyStore Trait
impl SecretManager for KeyStore {
    async fn set_secret(&self, key: &str, secret: &str) -> Result<(), KeyStoreError> {
        match self {
            Self::Basic(s) => s.set_secret(key, secret).await,
            Self::FreeDesktop(s) => s.set_secret(key, secret).await,
        }
    }

    async fn get_secret(&self, key: &str) -> Result<String, KeyStoreError> {
        match self {
            Self::Basic(s) => s.get_secret(key).await,
            Self::FreeDesktop(s) => s.get_secret(key).await,
        }
    }
}

// ============== private underlying structs ==============

/// The underlying storage mechanism
/// There currently are [`BasicSecretManager`] and [`FreeDesktopSecretManager`] available
pub trait SecretManager: Send + Sync {
    /// Lets read a secret stored for a key
    async fn get_secret(&self, key: &str) -> Result<String, KeyStoreError>;
    async fn set_secret(&self, key: &str, secret: &str) -> Result<(), KeyStoreError>;
}

/// [`SecretManager`] that stores secrets in plaintext inside the config directory
struct BasicSecretManager {}

/// [`SecretManager`] that stores secrets using the FreeDesktop Secret Service
struct FreeDesktopSecretManager {
    /// The underlying oo7 keyring used for interaction with the FreeDesktop Secret Service
    keyring: oo7::Keyring,
}

/// Basic implementation that simply stores secrets in a JSON file
impl SecretManager for BasicSecretManager {
    async fn get_secret(&self, key: &str) -> Result<String, KeyStoreError> {
        let keys = HashMap::<String, String>::load_from_file(&SECRETS_PATH).await?;

        keys
            // The way to take/consume a value (not reference) from a HashMap is removing it
            .and_then(|mut map| map.remove(key))
            // It is possible that the user changes the key store mode when having already created a config
            // This would result in requesting keys that dont exist (yet)
            .ok_or(KeyStoreError::NoEntry)
    }

    async fn set_secret(&self, key: &str, secret: &str) -> Result<(), KeyStoreError> {
        let mut keys = HashMap::<String, String>::load_from_file(&SECRETS_PATH)
            .await?
            .unwrap_or_default();

        keys.insert(key.to_string(), secret.to_string());

        keys.save_to_file(&SECRETS_PATH).await?;

        Ok(())
    }
}

impl SecretManager for FreeDesktopSecretManager {
    async fn get_secret(&self, key: &str) -> Result<String, KeyStoreError> {
        let entry = self
            .keyring
            .search_items(&HashMap::from([
                ("service", ZBC_SERVICE_NAME),
                ("key", key),
            ]))
            .await
            .map_err(KeyStoreError::from)?;

        match entry.len() {
            // It is possible that the user changes the key store mode when having already created a config
            // This would result in requesting keys that dont exist (yet)
            0 => Err(KeyStoreError::NoEntry),
            // Take the entry, assume it is a Text variant Secret
            1 => entry[0] // Guaranteed non-panic through len=1
                .secret()
                .await
                .map_err(KeyStoreError::from) // pass through error if we can't get the secret
                .and_then(|s| match s {
                    Secret::Text(ref t) => Ok(t.clone()), // Either return the Text variant
                    Secret::Blob(_) => Err(KeyStoreError::NonTextSecret(key.to_owned())), // Or error out
                })
                .map_err(KeyStoreError::from),
            // I shouldn't need to check this since Secret Service attributes collections are unique, but you never know
            2.. => Err(KeyStoreError::DuplicateKey(key.to_owned())),
        }
    }

    async fn set_secret(&self, key: &str, secret: &str) -> Result<(), KeyStoreError> {
        self.keyring
            .create_item(
                &format!("{ZBC_SERVICE_NAME} - {key}"),
                // Since attributes work as identifier in the Secret Service they need to be a unique collection
                // In this case we guarantee this by including the service (Ziti Box CLI) and then adding the key
                &HashMap::from([("service", ZBC_SERVICE_NAME), ("key", key)]),
                secret,
                true,
            )
            .await
            .map_err(KeyStoreError::from);

        Ok(())
    }
}
