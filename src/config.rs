use std::{error::Error, path::Path};

use serde::{Deserialize, Serialize};
use color_eyre::Result;

type BoxedError = Box<dyn Error + Send + Sync + 'static>;

pub trait Serializable: Serialize + for<'de> Deserialize<'de> {
    async fn load_from_file(path: &Path) -> Result<Option<Self>, BoxedError>;
    async fn save_to_file(&self, path: &Path) -> Result<(), BoxedError>;
}

impl<T> Serializable for T
where
    T: Serialize + for<'de> Deserialize<'de> + Sync,
{
    /// Saves this API to the default config location
    async fn save_to_file(&self, path: &Path) -> Result<(), BoxedError> {
        let json_bytes = serde_json::to_vec_pretty(self)?; // or to_string()

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(path, json_bytes).await?;
        Ok(())
    }

    /// Loads the API from the default config location \
    /// Returns `None` if there is no configuration and `Some(Serializable)` if successfully read
    async fn load_from_file(path: &Path) -> Result<Option<Self>, BoxedError> {
        // return none if the config doesnt exist
        if !path.exists() {
            return Ok(None);
        }

        let json_bytes = tokio::fs::read(path).await?;
        let api: Self = serde_json::from_slice(&json_bytes)?;

        Ok(Some(api))
    }
}
