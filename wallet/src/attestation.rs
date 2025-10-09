use crate::error::{EnclaveError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

// AWS Nitro NSM API types
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};

// Production mode: use real AWS Nitro NSM driver
#[cfg(feature = "nsm")]
use aws_nitro_enclaves_nsm_api::{api::{Request, Response}, driver as nsm_driver};

const RSA_KEY_SIZE: usize = 2048;

/// Attestation service for generating attestation documents
pub struct AttestationService {
    /// Private key for decrypting seeds and JWTs
    private_key: Arc<RwLock<RsaPrivateKey>>,
    /// Public key (DER encoded) for attestation
    public_key_der: Vec<u8>,
}

impl AttestationService {
    /// Create a new attestation service with a generated key pair
    pub fn new() -> Result<Self> {
        tracing::info!("Generating RSA key pair for attestation");

        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)
            .map_err(|e| EnclaveError::Crypto(format!("Failed to generate RSA key: {}", e)))?;

        let public_key = RsaPublicKey::from(&private_key);

        // Encode public key to DER format
        use rsa::pkcs8::EncodePublicKey;
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| EnclaveError::Crypto(format!("Failed to encode public key: {}", e)))?
            .as_bytes()
            .to_vec();

        tracing::info!("RSA key pair generated successfully");

        Ok(Self {
            private_key: Arc::new(RwLock::new(private_key)),
            public_key_der,
        })
    }

    /// Get attestation document from NSM with public key included
    pub fn get_attestation_document(&self, nonce: Option<Vec<u8>>, jwks_url: &str) -> Result<Vec<u8>> {
        #[cfg(feature = "local-dev")]
        {
            tracing::warn!("LOCAL DEV MODE: Creating fake AttestationDoc");

            // Create user_data with JWKS URL
            let user_data_json = serde_json::json!({
                "jwks_url": jwks_url
            });
            let user_data_bytes = serde_json::to_vec(&user_data_json)
                .map_err(|e| EnclaveError::Attestation(format!("Failed to serialize user_data: {}", e)))?;

            // Create a fake AttestationDoc matching the real NSM format
            use serde_bytes::ByteBuf;
            let fake_doc = AttestationDoc {
                module_id: "local-dev-mode".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                digest: Digest::SHA384,
                pcrs: Default::default(),
                certificate: ByteBuf::from(vec![]),  // Empty certificate chain for local dev
                cabundle: vec![],
                public_key: Some(ByteBuf::from(self.public_key_der.clone())),
                user_data: Some(ByteBuf::from(user_data_bytes)),
                nonce: nonce.map(ByteBuf::from),
            };

            // Serialize to CBOR using to_binary helper (matching NSM format)
            let cbor_bytes = fake_doc.to_binary();

            tracing::info!("Fake AttestationDoc created, CBOR size: {} bytes", cbor_bytes.len());
            return Ok(cbor_bytes);
        }

        #[cfg(feature = "nsm")]
        {
            tracing::info!("Requesting attestation document from NSM");

            // Create user_data with JWKS URL
            let user_data_json = serde_json::json!({
                "jwks_url": jwks_url
            });
            let user_data_bytes = serde_json::to_vec(&user_data_json)
                .map_err(|e| EnclaveError::Attestation(format!("Failed to serialize user_data: {}", e)))?;

            // Open NSM device
            let nsm_fd = nsm_driver::nsm_init();

            // Create attestation request with public key, user_data, and nonce
            use serde_bytes::ByteBuf;
            let request = Request::Attestation {
                public_key: Some(ByteBuf::from(self.public_key_der.clone())),
                user_data: Some(ByteBuf::from(user_data_bytes)),
                nonce: nonce.map(ByteBuf::from),
            };

            // Get response from NSM
            let response = nsm_driver::nsm_process_request(nsm_fd, request);
            nsm_driver::nsm_exit(nsm_fd);

            // Extract attestation document
            match response {
                Response::Attestation { document } => {
                    tracing::info!("Attestation document received, size: {} bytes", document.len());
                    Ok(document)
                }
                Response::Error(err) => {
                    Err(EnclaveError::Attestation(format!(
                        "NSM returned error: {:?}",
                        err
                    )))
                }
                _ => Err(EnclaveError::Attestation(
                    "Unexpected response from NSM".to_string(),
                )),
            }
        }

        // Fallback for when neither feature is enabled (should never happen with default features)
        #[cfg(not(any(feature = "local-dev", feature = "nsm")))]
        {
            compile_error!("Either 'local-dev' or 'nsm' feature must be enabled");
        }
    }

    /// Decrypt data encrypted with the public key from attestation
    pub async fn decrypt(&self, encrypted_data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let private_key = self.private_key.read().await;

        let decrypted = private_key
            .decrypt(Pkcs1v15Encrypt, encrypted_data)
            .map_err(|e| EnclaveError::Crypto(format!("RSA decryption failed: {}", e)))?;

        Ok(Zeroizing::new(decrypted))
    }

    /// Decrypt base64-encoded data
    pub async fn decrypt_base64(&self, encrypted_base64: &str) -> Result<Zeroizing<Vec<u8>>> {
        let encrypted_data = BASE64
            .decode(encrypted_base64)
            .map_err(|e| EnclaveError::Crypto(format!("Base64 decode failed: {}", e)))?;

        self.decrypt(&encrypted_data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encryption_decryption() {
        // Create attestation service
        let service = AttestationService::new().unwrap();

        // Get public key for encryption
        let public_key_der = service.public_key_der();
        let public_key = RsaPublicKey::from_public_key_der(public_key_der).unwrap();

        // Test data
        let plaintext = b"test secret data";

        // Encrypt with public key
        let mut rng = OsRng;
        let encrypted = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext).unwrap();

        // Decrypt with private key
        let decrypted = service.decrypt(&encrypted).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
