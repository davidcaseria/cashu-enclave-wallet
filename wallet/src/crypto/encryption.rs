use crate::error::{EnclaveError, Result};
use crate::types::EncryptedBlob;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 12; // 96 bits for AES-GCM

/// Encrypt data using AES-256-GCM
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob> {
    let cipher = Aes256Gcm::new(key.into());

    // Generate random nonce
    let nonce_bytes = aes_gcm::aead::rand_core::RngCore::next_u64(&mut OsRng).to_le_bytes();
    let mut nonce_vec = vec![0u8; NONCE_SIZE];
    nonce_vec[..8].copy_from_slice(&nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_vec);

    // Encrypt and authenticate
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EnclaveError::Crypto(format!("AES-GCM encryption failed: {}", e)))?;

    Ok(EncryptedBlob::new(nonce_vec, ciphertext))
}

/// Decrypt data using AES-256-GCM
pub fn decrypt(key: &[u8; 32], blob: &EncryptedBlob) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(key.into());

    if blob.nonce.len() != NONCE_SIZE {
        return Err(EnclaveError::Crypto(format!(
            "Invalid nonce size: expected {}, got {}",
            NONCE_SIZE,
            blob.nonce.len()
        )));
    }

    let nonce = Nonce::from_slice(&blob.nonce);

    // Decrypt and verify
    let plaintext = cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| EnclaveError::Crypto(format!("AES-GCM decryption failed: {}", e)))?;

    Ok(Zeroizing::new(plaintext))
}

/// Encrypt JSON data
pub fn encrypt_json<T: serde::Serialize>(key: &[u8; 32], data: &T) -> Result<EncryptedBlob> {
    let plaintext = serde_json::to_vec(data)?;
    encrypt(key, &plaintext)
}

/// Decrypt JSON data
pub fn decrypt_json<T: serde::de::DeserializeOwned>(
    key: &[u8; 32],
    blob: &EncryptedBlob,
) -> Result<T> {
    let plaintext = decrypt(key, blob)?;
    let data = serde_json::from_slice(&plaintext)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; 32];
        let plaintext = b"test data";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_json() {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestData {
            field1: String,
            field2: u64,
        }

        let key = [42u8; 32];
        let data = TestData {
            field1: "test".to_string(),
            field2: 12345,
        };

        let encrypted = encrypt_json(&key, &data).unwrap();
        let decrypted: TestData = decrypt_json(&key, &encrypted).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [42u8; 32];
        let key2 = [43u8; 32];
        let plaintext = b"test data";

        let encrypted = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &encrypted);

        assert!(result.is_err());
    }
}
