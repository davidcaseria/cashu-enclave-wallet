use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Wallet ID derived from seed hash (SHA-128 - first 16 bytes of SHA-256)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WalletId(pub [u8; 16]);

impl WalletId {
    /// Derive wallet ID from seed using SHA-128 (first 16 bytes of SHA-256)
    /// This provides 128-bit security which is sufficient for a routing identifier
    pub fn from_seed(seed: &[u8]) -> Self {
        let hash = Sha256::digest(seed);
        // Take first 16 bytes for SHA-128
        let mut wallet_id = [0u8; 16];
        wallet_id.copy_from_slice(&hash[..16]);
        Self(wallet_id)
    }

    /// Get as bytes slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string (expects 32 hex characters for 16 bytes)
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes: Vec<u8> = hex::decode(s)?;
        if bytes.len() != 16 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Display for WalletId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Encrypted blob containing sensitive data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Nonce used for encryption (12 bytes for AES-GCM)
    pub nonce: Vec<u8>,
    /// Ciphertext with authentication tag appended
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Serialize to bytes for database storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.nonce.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("Invalid encrypted blob: too short".to_string());
        }

        let nonce_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + nonce_len {
            return Err("Invalid encrypted blob: truncated nonce".to_string());
        }

        let nonce = bytes[4..4 + nonce_len].to_vec();
        let ciphertext = bytes[4 + nonce_len..].to_vec();

        Ok(Self { nonce, ciphertext })
    }
}

/// JWT token claims for wallet authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user ID) - standard JWT claim
    pub sub: String,
    /// Issued at timestamp
    pub iat: u64,
    /// Expiration timestamp
    pub exp: u64,
    /// Permissions
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// Request types sent from parent to enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EnclaveRequest {
    /// Get attestation document
    GetAttestation {
        nonce: Option<Vec<u8>>, // Optional nonce for attestation
    },

    /// Initialize wallet - enclave generates seed internally
    /// Session key is encrypted with RSA public key from attestation
    /// JWT is provided in encrypted_jwt field (encrypted with session key)
    InitWallet {
        encrypted_session_key: String, // base64-encoded RSA-encrypted session key
        encrypted_jwt: String, // base64-encoded AES-encrypted JWT (encrypted with session_key)
    },

    /// Execute wallet operation
    /// Session ID identifies the session key to use for decryption
    /// JWT is provided in encrypted_jwt field (encrypted with session key)
    WalletOperation {
        wallet_id: String,
        session_id: String, // hex-encoded session ID
        encrypted_jwt: String, // base64-encoded AES-encrypted JWT
        encrypted_request: String, // base64-encoded AES-encrypted operation
    },
}

/// Response types sent from enclave to parent
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum EnclaveResponse {
    Success {
        data: serde_json::Value,
    },
    Error {
        message: String,
    },
}

/// Wallet operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation")]
pub enum WalletOperation {
    /// Get wallet balance
    GetBalance {
        mint_url: Option<String>,
    },

    /// Send tokens
    Send {
        amount: u64,
        mint_url: Option<String>,
    },

    /// Receive tokens
    Receive {
        token: String,
    },

    /// Create mint quote
    MintQuote {
        amount: u64,
        mint_url: String,
    },

    /// Mint tokens
    Mint {
        quote_id: String,
    },

    /// Create melt quote
    MeltQuote {
        bolt11: String, // Lightning invoice
        mint_url: String,
    },

    /// Melt tokens
    Melt {
        quote_id: String,
        mint_url: String,
    },

    /// Add mint
    AddMint {
        mint_url: String,
    },

    /// List mints
    ListMints,

    /// Get transaction history
    GetTransactions {
        mint_url: Option<String>,
    },

    /// Add user to wallet
    AddUser {
        user_id: String,
    },

    /// Remove user from wallet
    RemoveUser {
        user_id: String,
    },

    /// List users for wallet
    ListUsers,
}
