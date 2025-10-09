use crate::error::{EnclaveError, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Size of the seed in bytes (512 bits for BIP39)
pub const SEED_SIZE: usize = 64;

/// Result of seed encryption operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSeedData {
    /// The encrypted seed bytes
    pub encrypted_seed: Vec<u8>,
    /// KMS key ID (production only, None for dev mode)
    pub kms_key_id: Option<String>,
    /// Encryption context for additional verification
    pub encryption_context: Option<serde_json::Value>,
}

/// KMS service for encrypting and decrypting wallet seeds
pub struct KmsService {
    #[cfg(feature = "local-dev")]
    dev_master_key: Zeroizing<[u8; 32]>,
}

impl KmsService {
    /// Create a new KMS service
    pub fn new() -> Result<Self> {
        #[cfg(feature = "local-dev")]
        {
            let dev_master_key = Self::get_or_create_dev_master_key()?;
            tracing::warn!(
                "⚠️  LOCAL DEV MODE: Using development master key for seed encryption"
            );
            tracing::warn!(
                "⚠️  This is INSECURE and should NEVER be used in production!"
            );
            Ok(Self { dev_master_key })
        }

        #[cfg(feature = "nsm")]
        {
            tracing::info!("KMS service initialized for production mode with AWS KMS");
            Ok(Self {})
        }

        #[cfg(not(any(feature = "local-dev", feature = "nsm")))]
        {
            compile_error!("Either 'local-dev' or 'nsm' feature must be enabled");
        }
    }

    /// Encrypt a seed for storage
    ///
    /// # Production (NSM mode)
    /// Uses AWS KMS with Nitro Enclave attestation document.
    /// The KMS key encrypts the response using the enclave's public key,
    /// ensuring only this enclave instance can decrypt the seed.
    ///
    /// # Local Dev mode
    /// Uses a local AES-256-GCM key stored in ~/.cashu-enclave-wallet/dev-master-key
    /// or the DEV_SEED_MASTER_KEY environment variable.
    pub async fn encrypt_seed(&self, seed: &[u8; SEED_SIZE]) -> Result<EncryptedSeedData> {
        if seed.len() != SEED_SIZE {
            return Err(EnclaveError::Crypto(format!(
                "Invalid seed size: expected {}, got {}",
                SEED_SIZE,
                seed.len()
            )));
        }

        #[cfg(feature = "local-dev")]
        {
            tracing::debug!("Encrypting seed with local dev key");
            let encrypted_seed = self.encrypt_with_dev_key(seed)?;
            Ok(EncryptedSeedData {
                encrypted_seed,
                kms_key_id: None,
                encryption_context: Some(serde_json::json!({
                    "mode": "local-dev",
                    "warning": "Development mode - not secure for production"
                })),
            })
        }

        #[cfg(feature = "nsm")]
        {
            self.encrypt_with_kms(seed).await
        }
    }

    /// Decrypt a seed from storage
    pub async fn decrypt_seed(&self, data: &EncryptedSeedData) -> Result<Zeroizing<[u8; SEED_SIZE]>> {
        #[cfg(feature = "local-dev")]
        {
            tracing::debug!("Decrypting seed with local dev key");
            self.decrypt_with_dev_key(&data.encrypted_seed)
        }

        #[cfg(feature = "nsm")]
        {
            self.decrypt_with_kms(data).await
        }
    }

    // ========================================================================
    // Local Development Mode Implementation
    // ========================================================================

    #[cfg(feature = "local-dev")]
    fn get_or_create_dev_master_key() -> Result<Zeroizing<[u8; 32]>> {
        use std::fs;

        // Try environment variable first
        if let Ok(key_hex) = std::env::var("DEV_SEED_MASTER_KEY") {
            tracing::info!("Using DEV_SEED_MASTER_KEY from environment");
            let key_bytes = hex::decode(&key_hex)
                .map_err(|e| EnclaveError::Crypto(format!("Invalid DEV_SEED_MASTER_KEY hex: {}", e)))?;

            if key_bytes.len() != 32 {
                return Err(EnclaveError::Crypto(format!(
                    "DEV_SEED_MASTER_KEY must be 32 bytes, got {}",
                    key_bytes.len()
                )));
            }

            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&key_bytes);
            return Ok(key);
        }

        // Otherwise use file-based key
        let key_path = Self::dev_master_key_path()?;

        if key_path.exists() {
            tracing::info!("Loading dev master key from {:?}", key_path);
            let key_hex = fs::read_to_string(&key_path)
                .map_err(|e| EnclaveError::Crypto(format!("Failed to read dev key file: {}", e)))?;

            let key_bytes = hex::decode(key_hex.trim())
                .map_err(|e| EnclaveError::Crypto(format!("Invalid dev key hex in file: {}", e)))?;

            if key_bytes.len() != 32 {
                return Err(EnclaveError::Crypto(format!(
                    "Dev key file must contain 32 bytes, got {}",
                    key_bytes.len()
                )));
            }

            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&key_bytes);
            Ok(key)
        } else {
            tracing::warn!("Generating new dev master key at {:?}", key_path);
            tracing::warn!("⚠️  Store this key securely if you want to persist seeds across restarts!");

            // Generate new key
            use rand::RngCore;
            let mut key = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut *key);

            // Create directory if needed
            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| EnclaveError::Crypto(format!("Failed to create key directory: {}", e)))?;
            }

            // Write to file
            fs::write(&key_path, hex::encode(&*key))
                .map_err(|e| EnclaveError::Crypto(format!("Failed to write dev key file: {}", e)))?;

            tracing::info!("Dev master key generated and saved to {:?}", key_path);
            Ok(key)
        }
    }

    #[cfg(feature = "local-dev")]
    fn dev_master_key_path() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| EnclaveError::Crypto("Cannot determine home directory".to_string()))?;

        Ok(PathBuf::from(home).join(".cashu-enclave-wallet").join("dev-master-key"))
    }

    #[cfg(feature = "local-dev")]
    fn encrypt_with_dev_key(&self, seed: &[u8; SEED_SIZE]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new((&*self.dev_master_key).into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, seed.as_ref())
            .map_err(|e| EnclaveError::Crypto(format!("AES-GCM encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut encrypted = nonce.to_vec();
        encrypted.extend_from_slice(&ciphertext);

        Ok(encrypted)
    }

    #[cfg(feature = "local-dev")]
    fn decrypt_with_dev_key(&self, encrypted: &[u8]) -> Result<Zeroizing<[u8; SEED_SIZE]>> {
        const NONCE_SIZE: usize = 12;

        if encrypted.len() < NONCE_SIZE {
            return Err(EnclaveError::Crypto("Encrypted data too short".to_string()));
        }

        let cipher = Aes256Gcm::new((&*self.dev_master_key).into());
        let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        let ciphertext = &encrypted[NONCE_SIZE..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EnclaveError::Crypto(format!("AES-GCM decryption failed: {}", e)))?;

        if plaintext.len() != SEED_SIZE {
            return Err(EnclaveError::Crypto(format!(
                "Decrypted seed has invalid size: expected {}, got {}",
                SEED_SIZE,
                plaintext.len()
            )));
        }

        let mut seed = Zeroizing::new([0u8; SEED_SIZE]);
        seed.copy_from_slice(&plaintext);

        Ok(seed)
    }

    // ========================================================================
    // Production AWS KMS Mode Implementation
    // ========================================================================

    #[cfg(feature = "nsm")]
    async fn encrypt_with_kms(&self, seed: &[u8; SEED_SIZE]) -> Result<EncryptedSeedData> {
        use aws_nitro_enclaves_nsm_api::{api::Request, driver as nsm_driver};

        tracing::info!("Encrypting seed with AWS KMS using attestation document");

        // Get attestation document from NSM
        let nsm_fd = nsm_driver::nsm_init();
        let request = Request::Attestation {
            public_key: None,
            user_data: None,
            nonce: None,
        };
        let response = nsm_driver::nsm_process_request(nsm_fd, request);
        nsm_driver::nsm_exit(nsm_fd);

        let attestation_doc = match response {
            aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => document,
            aws_nitro_enclaves_nsm_api::api::Response::Error(err) => {
                return Err(EnclaveError::Attestation(format!(
                    "NSM attestation failed: {:?}",
                    err
                )))
            }
            _ => {
                return Err(EnclaveError::Attestation(
                    "Unexpected NSM response".to_string(),
                ))
            }
        };

        // TODO: Call AWS KMS GenerateDataKey with attestation document
        // The KMS service will verify the attestation and return a data key
        // encrypted with the enclave's public key from the attestation

        // For now, return an error indicating this needs AWS SDK integration
        Err(EnclaveError::Crypto(
            "AWS KMS integration not yet implemented. See https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html".to_string()
        ))

        // Pseudocode for implementation:
        // 1. Create AWS KMS client with attestation
        // 2. Call kms.GenerateDataKey() with:
        //    - KeyId: configured KMS key ARN
        //    - Recipient.AttestationDocument: attestation_doc
        // 3. KMS returns:
        //    - PlaintextDataKey (for immediate use)
        //    - CiphertextForRecipient (encrypted with enclave public key)
        // 4. Encrypt seed with PlaintextDataKey
        // 5. Return EncryptedSeedData with ciphertext and KMS key ID
    }

    #[cfg(feature = "nsm")]
    async fn decrypt_with_kms(&self, data: &EncryptedSeedData) -> Result<Zeroizing<[u8; SEED_SIZE]>> {
        // TODO: Call AWS KMS Decrypt with attestation document
        // The KMS service will verify the attestation and return the decrypted data key

        Err(EnclaveError::Crypto(
            "AWS KMS integration not yet implemented. See https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html".to_string()
        ))

        // Pseudocode for implementation:
        // 1. Get attestation document from NSM
        // 2. Call kms.Decrypt() with:
        //    - CiphertextBlob: data.encrypted_seed
        //    - Recipient.AttestationDocument: attestation_doc
        // 3. KMS verifies attestation and returns plaintext data key
        // 4. Use data key to decrypt the actual seed
        // 5. Return decrypted seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "local-dev")]
    #[tokio::test]
    async fn test_dev_mode_encrypt_decrypt() {
        let kms = KmsService::new().unwrap();
        let seed = [42u8; SEED_SIZE];

        // Encrypt
        let encrypted = kms.encrypt_seed(&seed).await.unwrap();
        assert!(encrypted.encrypted_seed.len() > SEED_SIZE);
        assert!(encrypted.kms_key_id.is_none());

        // Decrypt
        let decrypted = kms.decrypt_seed(&encrypted).await.unwrap();
        assert_eq!(&*decrypted, &seed);
    }

    #[cfg(feature = "local-dev")]
    #[tokio::test]
    async fn test_dev_mode_different_seeds() {
        let kms = KmsService::new().unwrap();

        let seed1 = [1u8; SEED_SIZE];
        let seed2 = [2u8; SEED_SIZE];

        let encrypted1 = kms.encrypt_seed(&seed1).await.unwrap();
        let encrypted2 = kms.encrypt_seed(&seed2).await.unwrap();

        // Different seeds produce different ciphertexts
        assert_ne!(encrypted1.encrypted_seed, encrypted2.encrypted_seed);

        // Each decrypts correctly
        let decrypted1 = kms.decrypt_seed(&encrypted1).await.unwrap();
        let decrypted2 = kms.decrypt_seed(&encrypted2).await.unwrap();

        assert_eq!(&*decrypted1, &seed1);
        assert_eq!(&*decrypted2, &seed2);
    }
}
