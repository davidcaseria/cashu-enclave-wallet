use crate::error::{EnclaveError, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

/// JSON Web Key from JWKS endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA")
    pub kty: String,
    /// Key ID
    pub kid: String,
    /// Algorithm (e.g., "RS256")
    #[serde(default)]
    pub alg: Option<String>,
    /// RSA modulus (base64url encoded)
    pub n: String,
    /// RSA exponent (base64url encoded)
    pub e: String,
}

/// JSON Web Key Set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Cached JWKS data
struct CachedJwks {
    keys: HashMap<String, DecodingKey>,
    last_refresh: Instant,
}

/// JWKS validator for RS256 JWT validation
pub struct JwksValidator {
    jwks_url: String,
    cache: Arc<RwLock<CachedJwks>>,
    client: reqwest::Client,
}

impl JwksValidator {
    /// Create a new JWKS validator
    pub async fn new(jwks_url: String) -> Result<Self> {
        tracing::info!("Initializing JWKS validator with URL: {}", jwks_url);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| EnclaveError::Jwt(format!("Failed to create HTTP client: {}", e)))?;

        let cache = Arc::new(RwLock::new(CachedJwks {
            keys: HashMap::new(),
            last_refresh: Instant::now() - JWKS_REFRESH_INTERVAL, // Force initial fetch
        }));

        let validator = Self {
            jwks_url,
            cache,
            client,
        };

        // Initial fetch
        validator.refresh_jwks().await?;

        tracing::info!("JWKS validator initialized successfully");
        Ok(validator)
    }

    /// Fetch JWKS from the configured URL
    async fn fetch_jwks(&self) -> Result<JwkSet> {
        tracing::info!("Fetching JWKS from {}", self.jwks_url);

        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| EnclaveError::Jwt(format!("Failed to fetch JWKS: {}", e)))?;

        if !response.status().is_success() {
            return Err(EnclaveError::Jwt(format!(
                "JWKS fetch failed with status: {}",
                response.status()
            )));
        }

        let jwk_set: JwkSet = response
            .json()
            .await
            .map_err(|e| EnclaveError::Jwt(format!("Failed to parse JWKS: {}", e)))?;

        tracing::info!("Fetched {} keys from JWKS", jwk_set.keys.len());
        Ok(jwk_set)
    }

    /// Refresh JWKS cache
    async fn refresh_jwks(&self) -> Result<()> {
        let jwk_set = self.fetch_jwks().await?;

        let mut keys = HashMap::new();
        for jwk in jwk_set.keys {
            // Only support RSA keys
            if jwk.kty != "RSA" {
                tracing::warn!("Skipping non-RSA key: {}", jwk.kid);
                continue;
            }

            // Decode base64url modulus and exponent
            let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                .map_err(|e| {
                    EnclaveError::Jwt(format!("Failed to create decoding key for {}: {}", jwk.kid, e))
                })?;

            keys.insert(jwk.kid.clone(), decoding_key);
            tracing::debug!("Loaded RSA key: {}", jwk.kid);
        }

        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.last_refresh = Instant::now();

        tracing::info!("JWKS cache refreshed with {} keys", cache.keys.len());
        Ok(())
    }

    /// Get decoding key for a specific key ID, refreshing if necessary
    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey> {
        // Check if refresh is needed
        {
            let cache = self.cache.read().await;
            if cache.last_refresh.elapsed() < JWKS_REFRESH_INTERVAL {
                if let Some(key) = cache.keys.get(kid) {
                    return Ok(key.clone());
                }
            }
        }

        // Refresh cache and try again
        tracing::info!("Key {} not found or cache expired, refreshing JWKS", kid);
        self.refresh_jwks().await?;

        let cache = self.cache.read().await;
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| EnclaveError::Jwt(format!("Key ID '{}' not found in JWKS", kid)))
    }

    /// Validate RS256 JWT token and extract claims
    pub async fn validate<T: serde::de::DeserializeOwned>(&self, token: &str) -> Result<T> {
        // Decode header to get key ID
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| EnclaveError::Jwt(format!("Failed to decode JWT header: {}", e)))?;

        let kid = header
            .kid
            .ok_or_else(|| EnclaveError::Jwt("JWT missing 'kid' header".to_string()))?;

        // Verify algorithm
        if header.alg != Algorithm::RS256 {
            return Err(EnclaveError::Jwt(format!(
                "Unsupported JWT algorithm: {:?}, expected RS256",
                header.alg
            )));
        }

        // Get decoding key
        let decoding_key = self.get_decoding_key(&kid).await?;

        // Validate token
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.leeway = 60; // 60 seconds leeway for clock skew
        validation.validate_aud = false; // Don't validate audience - we only care about signature and expiry

        let token_data = jsonwebtoken::decode::<T>(token, &decoding_key, &validation)
            .map_err(|e| EnclaveError::Jwt(format!("JWT validation failed: {}", e)))?;

        tracing::debug!("JWT validated successfully with key ID: {}", kid);
        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_deserialization() {
        let jwk_json = r#"{
            "kty": "RSA",
            "kid": "test-key-1",
            "alg": "RS256",
            "n": "xGOr-H7A-PWFVAjYCvlzhGM8M5rvRjZH8H5xPO8pKE_example",
            "e": "AQAB"
        }"#;

        let jwk: Jwk = serde_json::from_str(jwk_json).unwrap();
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.kid, "test-key-1");
        assert_eq!(jwk.alg, Some("RS256".to_string()));
    }

    #[test]
    fn test_jwk_set_deserialization() {
        let jwk_set_json = r#"{
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "key-1",
                    "n": "test-n",
                    "e": "AQAB"
                },
                {
                    "kty": "RSA",
                    "kid": "key-2",
                    "n": "test-n-2",
                    "e": "AQAB"
                }
            ]
        }"#;

        let jwk_set: JwkSet = serde_json::from_str(jwk_set_json).unwrap();
        assert_eq!(jwk_set.keys.len(), 2);
        assert_eq!(jwk_set.keys[0].kid, "key-1");
        assert_eq!(jwk_set.keys[1].kid, "key-2");
    }
}
