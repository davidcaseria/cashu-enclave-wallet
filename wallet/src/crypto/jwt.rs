use crate::crypto::jwks::JwksValidator;
use crate::error::{EnclaveError, Result};
use crate::types::{JwtClaims, WalletId};

/// JWT validator for authenticating wallet operations using JWKS
pub struct JwtValidator {
    jwks_validator: JwksValidator,
}

impl JwtValidator {
    /// Create a new JWT validator with JWKS support
    pub async fn new(jwks_url: String) -> Result<Self> {
        let jwks_validator = JwksValidator::new(jwks_url).await?;
        Ok(Self { jwks_validator })
    }

    /// Validate JWT token using RS256 with JWKS and extract claims
    pub async fn validate(&self, token: &str) -> Result<JwtClaims> {
        self.jwks_validator
            .validate::<JwtClaims>(token)
            .await
    }

    /// Verify that the user (from sub claim) owns the wallet
    /// Checks the user_wallets database table for a valid mapping
    pub async fn verify_user_owns_wallet(
        &self,
        claims: &JwtClaims,
        expected_wallet_id: &WalletId,
        db: &crate::database::EncryptedPostgresDatabase,
    ) -> Result<()> {
        // Check if user owns this wallet via database
        let owns_wallet = db.verify_user_owns_wallet(&claims.sub).await?;

        if !owns_wallet {
            return Err(EnclaveError::Auth(format!(
                "User '{}' does not own wallet {}",
                claims.sub, expected_wallet_id
            )));
        }

        Ok(())
    }
}

