use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Client-side session data for a wallet
/// Contains the session key and metadata needed for subsequent operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSession {
    /// Hex-encoded wallet ID
    pub wallet_id: String,

    /// Hex-encoded session ID from enclave
    pub session_id: String,

    /// Base64-encoded AES-256 session key
    /// This key is used to encrypt/decrypt all communications with the enclave
    #[serde(with = "base64_serde")]
    pub session_key: [u8; 32],

    /// Base64-encoded wallet seed (decrypted from InitWallet response)
    /// Stored for mnemonic recovery and wallet restoration
    #[serde(with = "base64_vec_serde")]
    pub seed: Vec<u8>,

    /// Unix timestamp when session was created
    pub created_at: i64,

    /// Unix timestamp when session expires (1 hour from creation)
    pub expires_at: i64,
}

/// Helper module for base64 serialization of fixed-size arrays
mod base64_serde {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64.decode(&s).map_err(serde::de::Error::custom)?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid session key length"))?;
        Ok(array)
    }
}

/// Helper module for base64 serialization of Vec<u8>
mod base64_vec_serde {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64.decode(&s).map_err(serde::de::Error::custom)
    }
}

impl WalletSession {
    /// Create a new wallet session
    pub fn new(
        wallet_id: String,
        session_id: String,
        session_key: [u8; 32],
        seed: Vec<u8>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            wallet_id,
            session_id,
            session_key,
            seed,
            created_at: now,
            expires_at: now + 3600, // 1 hour expiry
        }
    }

    /// Check if the session is expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        now >= self.expires_at
    }

    /// Get time remaining until expiry in seconds
    pub fn time_remaining(&self) -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        (self.expires_at - now).max(0)
    }

    /// Save session to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::session_path(&self.wallet_id)?;

        // Create sessions directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create sessions directory")?;
        }

        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize session")?;

        fs::write(&path, json)
            .with_context(|| format!("Failed to write session file: {}", path.display()))?;

        Ok(())
    }

    /// Load session from disk
    pub fn load(wallet_id: &str) -> Result<Self> {
        let path = Self::session_path(wallet_id)?;

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read session file: {}", path.display()))?;

        let session: Self = serde_json::from_str(&contents)
            .context("Failed to parse session file")?;

        // Check if session is expired
        if session.is_expired() {
            anyhow::bail!(
                "Session has expired. Please re-initialize the wallet with:\n  \
                cashu-enclave-wallet init"
            );
        }

        Ok(session)
    }

    /// Get the sessions directory path
    fn sessions_dir() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .context("Could not determine home directory")?;

        Ok(PathBuf::from(home).join(".cashu-enclave-wallet").join("sessions"))
    }

    /// Get the path to a session file
    fn session_path(wallet_id: &str) -> Result<PathBuf> {
        Ok(Self::sessions_dir()?.join(format!("{}.json", wallet_id)))
    }

    /// Find the most recent valid session
    /// Returns the wallet_id from the most recently modified session file
    pub fn find_active_wallet() -> Result<String> {
        let sessions_dir = Self::sessions_dir()?;

        if !sessions_dir.exists() {
            anyhow::bail!(
                "No sessions found. Please initialize a wallet first with:\n  \
                cashu-enclave-wallet init"
            );
        }

        let mut sessions = Vec::new();

        // Read all session files
        for entry in fs::read_dir(&sessions_dir)
            .with_context(|| format!("Failed to read sessions directory: {}", sessions_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                // Try to load the session to verify it's valid
                if let Ok(contents) = fs::read_to_string(&path) {
                    if let Ok(session) = serde_json::from_str::<WalletSession>(&contents) {
                        // Only include non-expired sessions
                        if !session.is_expired() {
                            let modified = entry.metadata()?.modified()?;
                            sessions.push((session.wallet_id.clone(), modified));
                        }
                    }
                }
            }
        }

        if sessions.is_empty() {
            anyhow::bail!(
                "No active sessions found (all sessions have expired). Please initialize a wallet with:\n  \
                cashu-enclave-wallet init"
            );
        }

        // Sort by modification time, most recent first
        sessions.sort_by(|a, b| b.1.cmp(&a.1));

        Ok(sessions[0].0.clone())
    }
}
