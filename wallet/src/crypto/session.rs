use crate::error::{EnclaveError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Nonce,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 12; // 96 bits for AES-GCM
const SESSION_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour

/// Session ID type (32 bytes)
pub type SessionId = [u8; 32];

/// Session data containing encryption key and metadata
#[derive(Clone)]
pub struct SessionData {
    /// AES-256 encryption key for this session
    session_key: Zeroizing<[u8; 32]>,
    /// Last activity timestamp for session expiration
    last_activity: Instant,
}

impl SessionData {
    pub fn new(session_key: [u8; 32]) -> Self {
        Self {
            session_key: Zeroizing::new(session_key),
            last_activity: Instant::now(),
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TIMEOUT
    }

    pub fn session_key(&self) -> &[u8; 32] {
        &self.session_key
    }
}

/// Manager for session keys and encryption
pub struct SessionKeyManager {
    sessions: Arc<RwLock<HashMap<SessionId, SessionData>>>,
}

impl SessionKeyManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session with the provided session key
    pub async fn create_session(&self, session_key: [u8; 32]) -> SessionId {
        use sha2::{Digest, Sha256};

        // Generate session ID from hash of (session_key + random nonce)
        let mut hasher = Sha256::new();
        hasher.update(&session_key);

        // Add random nonce for uniqueness
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        hasher.update(&nonce);

        let session_id: [u8; 32] = hasher.finalize().into();

        // Store session data
        let session_data = SessionData::new(session_key);
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session_data);

        tracing::info!("Created new session: {}", hex::encode(session_id));

        session_id
    }

    /// Get session data by ID and update activity
    pub async fn get_session(&self, session_id: &SessionId) -> Result<SessionData> {
        let mut sessions = self.sessions.write().await;

        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| EnclaveError::Auth("Invalid or expired session".to_string()))?;

        if session.is_expired() {
            sessions.remove(session_id);
            return Err(EnclaveError::Auth("Session expired".to_string()));
        }

        session.update_activity();
        Ok(session.clone())
    }

    /// Encrypt data with session key
    pub async fn encrypt_with_session(
        &self,
        session_id: &SessionId,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self.get_session(session_id).await?;
        let session_key = session.session_key();

        let cipher = Aes256Gcm::new(session_key.into());

        // Generate random nonce
        let nonce_bytes = aes_gcm::aead::rand_core::RngCore::next_u64(&mut AesOsRng).to_le_bytes();
        let mut nonce_vec = vec![0u8; NONCE_SIZE];
        nonce_vec[..8].copy_from_slice(&nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_vec);

        // Encrypt and authenticate
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| EnclaveError::Crypto(format!("AES-GCM encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_vec;
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data with session key
    pub async fn decrypt_with_session(
        &self,
        session_id: &SessionId,
        encrypted_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if encrypted_data.len() < NONCE_SIZE {
            return Err(EnclaveError::Crypto(
                "Encrypted data too short".to_string(),
            ));
        }

        let session = self.get_session(session_id).await?;
        let session_key = session.session_key();

        let cipher = Aes256Gcm::new(session_key.into());

        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&encrypted_data[..NONCE_SIZE]);
        let ciphertext = &encrypted_data[NONCE_SIZE..];

        // Decrypt and verify
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EnclaveError::Crypto(format!("AES-GCM decryption failed: {}", e)))?;

        Ok(Zeroizing::new(plaintext))
    }

    /// Encrypt JSON with session key and return base64
    pub async fn encrypt_json_with_session<T: serde::Serialize>(
        &self,
        session_id: &SessionId,
        data: &T,
    ) -> Result<String> {
        let plaintext = serde_json::to_vec(data)?;
        let encrypted = self.encrypt_with_session(session_id, &plaintext).await?;

        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        Ok(BASE64.encode(&encrypted))
    }

    /// Decrypt base64 JSON with session key
    pub async fn decrypt_json_with_session<T: serde::de::DeserializeOwned>(
        &self,
        session_id: &SessionId,
        encrypted_base64: &str,
    ) -> Result<T> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let encrypted_data = BASE64
            .decode(encrypted_base64)
            .map_err(|e| EnclaveError::Crypto(format!("Base64 decode failed: {}", e)))?;

        let plaintext = self.decrypt_with_session(session_id, &encrypted_data).await?;
        let data = serde_json::from_slice(&plaintext)?;
        Ok(data)
    }

    /// Decrypt base64 string with session key (without JSON parsing)
    pub async fn decrypt_string_with_session(
        &self,
        session_id: &SessionId,
        encrypted_base64: &str,
    ) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let encrypted_data = BASE64
            .decode(encrypted_base64)
            .map_err(|e| EnclaveError::Crypto(format!("Base64 decode failed: {}", e)))?;

        let plaintext = self.decrypt_with_session(session_id, &encrypted_data).await?;
        String::from_utf8(plaintext.to_vec())
            .map_err(|e| EnclaveError::Crypto(format!("Invalid UTF-8: {}", e)))
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let before_count = sessions.len();

        sessions.retain(|session_id, session| {
            if session.is_expired() {
                tracing::info!("Removing expired session: {}", hex::encode(session_id));
                false
            } else {
                true
            }
        });

        let removed = before_count - sessions.len();
        if removed > 0 {
            tracing::info!("Cleaned up {} expired sessions", removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation_and_retrieval() {
        let manager = SessionKeyManager::new();
        let session_key = [42u8; 32];

        let session_id = manager.create_session(session_key).await;

        let session = manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.session_key(), &session_key);
    }

    #[tokio::test]
    async fn test_encryption_decryption() {
        let manager = SessionKeyManager::new();
        let session_key = [42u8; 32];

        let session_id = manager.create_session(session_key).await;

        let plaintext = b"test secret data";
        let encrypted = manager.encrypt_with_session(&session_id, plaintext).await.unwrap();
        let decrypted = manager.decrypt_with_session(&session_id, &encrypted).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_invalid_session() {
        let manager = SessionKeyManager::new();
        let invalid_session_id = [0u8; 32];

        let result = manager.get_session(&invalid_session_id).await;
        assert!(result.is_err());
    }

}
