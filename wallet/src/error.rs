use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnclaveError {
    #[error("Attestation error: {0}")]
    Attestation(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Wallet error: {0}")]
    Wallet(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Configuration error: {0}")]
    #[allow(dead_code)]
    Configuration(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Wallet not found: {0}")]
    WalletNotFound(String),

    #[error("Seed derivation error: {0}")]
    SeedDerivation(String),

    #[error("JWT error: {0}")]
    Jwt(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQL error: {0}")]
    Sql(#[from] sqlx::Error),

    #[error("CDK error: {0}")]
    Cdk(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, EnclaveError>;

// Conversion from cdk::Error
impl From<cdk::Error> for EnclaveError {
    fn from(err: cdk::Error) -> Self {
        EnclaveError::Cdk(err.to_string())
    }
}

// Conversion from jwt errors
impl From<jsonwebtoken::errors::Error> for EnclaveError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        EnclaveError::Jwt(err.to_string())
    }
}
