use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Credentials stored in ~/.cashu-wallet-enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub keycloak_url: String,
    pub realm: String,
    pub client_id: String,
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_expiry: i64,
    pub refresh_expiry: i64,
    pub updated_at: String,
}

impl Credentials {
    /// Load credentials from the default location (~/.cashu-wallet-enclave)
    pub fn load() -> Result<Self> {
        let path = Self::default_path()?;
        Self::load_from_path(&path)
    }

    /// Load credentials from a specific path
    pub fn load_from_path(path: &PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read credentials file: {}", path.display()))?;

        let credentials: Credentials = serde_json::from_str(&contents)
            .context("Failed to parse credentials file")?;

        Ok(credentials)
    }

    /// Get the default credentials file path
    pub fn default_path() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .context("Could not determine home directory")?;

        Ok(PathBuf::from(home).join(".cashu-wallet-enclave"))
    }

    /// Check if the access token is expired
    pub fn is_access_token_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        now >= self.access_expiry
    }

    /// Get the access token, or return an error if expired
    pub fn get_valid_access_token(&self) -> Result<String> {
        if self.is_access_token_expired() {
            anyhow::bail!(
                "Access token has expired. Please run the authentication script again:\n  \
                ./scripts/keycloak-auth.sh"
            );
        }

        Ok(self.access_token.clone())
    }
}
