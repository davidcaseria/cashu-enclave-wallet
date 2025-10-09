use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bip39::Mnemonic;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

/// Extract public key from attestation document
/// Parses CBOR-encoded AWS Nitro Enclave attestation document and extracts the public key
pub fn extract_public_key_from_attestation(attestation_document: &str) -> Result<RsaPublicKey> {
    use aws_nitro_enclaves_nsm_api::api::AttestationDoc;

    // Decode the base64-encoded attestation document
    let doc_bytes = BASE64
        .decode(attestation_document)
        .context("Failed to decode attestation document")?;

    // Parse CBOR-encoded attestation document using from_binary helper
    let doc = AttestationDoc::from_binary(&doc_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse CBOR attestation document: {:?}", e))?;

    // Extract public key bytes
    let public_key_der = doc
        .public_key
        .context("Attestation document missing public_key field")?;

    // Parse DER-encoded public key
    RsaPublicKey::from_public_key_der(&public_key_der)
        .context("Failed to parse DER-encoded public key from attestation")
}

/// Encrypt data with RSA public key and return base64-encoded ciphertext
/// Used only for encrypting the session key during InitWallet
pub fn encrypt_with_public_key(data: &[u8], public_key: &RsaPublicKey) -> Result<String> {
    let mut rng = OsRng;
    let encrypted = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .context("RSA encryption failed")?;

    Ok(BASE64.encode(&encrypted))
}


/// Generate a random AES-256 session key
pub fn generate_session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt data with AES-256-GCM session key (returns nonce + ciphertext)
pub fn encrypt_with_session_key(session_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    const NONCE_SIZE: usize = 12;

    let cipher = Aes256Gcm::new(session_key.into());

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt and authenticate
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with AES-256-GCM session key (expects nonce + ciphertext)
pub fn decrypt_with_session_key(session_key: &[u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    const NONCE_SIZE: usize = 12;

    if encrypted_data.len() < NONCE_SIZE {
        anyhow::bail!("Encrypted data too short");
    }

    let cipher = Aes256Gcm::new(session_key.into());

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&encrypted_data[..NONCE_SIZE]);
    let ciphertext = &encrypted_data[NONCE_SIZE..];

    // Decrypt and verify
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))?;

    Ok(plaintext)
}

/// Encrypt protobuf message with session key and return base64
/// This is used for encrypting WalletOperationPayload messages
pub fn encrypt_protobuf_with_session_key<T: prost::Message>(
    session_key: &[u8; 32],
    message: &T,
) -> Result<String> {
    let mut plaintext = Vec::new();
    message.encode(&mut plaintext)
        .context("Failed to encode protobuf message")?;
    let encrypted = encrypt_with_session_key(session_key, &plaintext)?;
    Ok(BASE64.encode(&encrypted))
}

/// Decrypt base64 JSON with session key
pub fn decrypt_json_with_session_key<T: serde::de::DeserializeOwned>(
    session_key: &[u8; 32],
    encrypted_base64: &str,
) -> Result<T> {
    let encrypted_data = BASE64.decode(encrypted_base64)?;
    let plaintext = decrypt_with_session_key(session_key, &encrypted_data)?;
    let data = serde_json::from_slice(&plaintext)?;
    Ok(data)
}

/// Convert seed bytes to BIP39 mnemonic
pub fn seed_to_mnemonic(seed: &[u8]) -> Result<String> {
    // BIP39 seed is 512 bits (64 bytes), but we need entropy for the mnemonic
    // Take first 32 bytes (256 bits) as entropy for a 24-word mnemonic
    if seed.len() < 32 {
        anyhow::bail!("Seed too short: expected at least 32 bytes, got {}", seed.len());
    }

    let entropy = &seed[..32];
    let mnemonic = Mnemonic::from_entropy(entropy)
        .context("Failed to create mnemonic from seed")?;

    Ok(mnemonic.to_string())
}

/// Encrypt string with session key and return base64
pub fn encrypt_string_with_session_key(
    session_key: &[u8; 32],
    data: &str,
) -> Result<String> {
    let encrypted = encrypt_with_session_key(session_key, data.as_bytes())?;
    Ok(BASE64.encode(&encrypted))
}
