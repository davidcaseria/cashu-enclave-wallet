use crate::attestation::AttestationService;
use crate::crypto::kms::KmsService;
use crate::crypto::seed::SeedManager;
use crate::crypto::session::{SessionKeyManager, SessionId};
use crate::database::{EncryptedPostgresDatabase, EncryptedSeedRecord};
use crate::error::{EnclaveError, Result};
use crate::types::{WalletId, WalletOperation};
use cdk::wallet::multi_mint_wallet::{MultiMintWallet, MultiMintReceiveOptions, MultiMintSendOptions};
use cdk::nuts::CurrencyUnit;
use cdk::Amount;
use cdk::mint_url::MintUrl;
use sqlx::PgPool;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use prost::Message;

const SESSION_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour

/// User session containing wallet instance and seed
struct UserSession {
    seed_manager: SeedManager,
    wallet: MultiMintWallet,
    last_activity: Instant,
}

impl UserSession {
    async fn new(
        seed_manager: SeedManager,
        pool: PgPool,
        unit: CurrencyUnit,
    ) -> Result<Self> {
        let wallet_id = seed_manager.wallet_id();

        // Create encrypted database
        let db = EncryptedPostgresDatabase::new(
            pool,
            wallet_id,
            *seed_manager.db_encryption_key(),
        );

        // Create multi-mint wallet
        let mut seed_array = [0u8; 64];
        seed_array.copy_from_slice(seed_manager.seed());
        let wallet = MultiMintWallet::new(
            Arc::new(db),
            seed_array,
            unit,
        ).await?;

        tracing::info!("Created new user session for wallet_id: {}", wallet_id);

        Ok(Self {
            seed_manager,
            wallet,
            last_activity: Instant::now(),
        })
    }

    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TIMEOUT
    }
}

/// Wallet manager handling multiple user sessions
pub struct WalletManager {
    attestation: Arc<AttestationService>,
    pool: PgPool,
    sessions: Arc<RwLock<HashMap<WalletId, UserSession>>>,
    session_key_manager: Arc<SessionKeyManager>,
    kms_service: Arc<KmsService>,
    default_unit: CurrencyUnit,
    jwt_validator: Arc<crate::crypto::jwt::JwtValidator>,
    jwks_url: String,
}

impl WalletManager {
    /// Create a new wallet manager
    pub async fn new(
        attestation: Arc<AttestationService>,
        pool: PgPool,
        jwks_url: String,
    ) -> Result<Self> {
        tracing::info!("Initializing JWKS validator with URL: {}", jwks_url);
        let jwt_validator = Arc::new(crate::crypto::jwt::JwtValidator::new(jwks_url.clone()).await?);
        tracing::info!("JWKS validator initialized successfully");

        let session_key_manager = Arc::new(SessionKeyManager::new());
        tracing::info!("Session key manager initialized");

        let kms_service = Arc::new(KmsService::new()?);
        tracing::info!("KMS service initialized");

        Ok(Self {
            attestation,
            pool,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_key_manager,
            kms_service,
            default_unit: CurrencyUnit::Sat,
            jwt_validator,
            jwks_url,
        })
    }

    /// Get attestation document
    pub fn get_attestation(&self, nonce: Option<Vec<u8>>) -> Result<Vec<u8>> {
        self.attestation.get_attestation_document(nonce, &self.jwks_url)
    }

    /// Initialize a new wallet
    /// Generates seed in enclave, establishes session key, and adds user as owner
    pub async fn init_wallet(
        &self,
        encrypted_session_key_base64: &str,
        encrypted_jwt_base64: &str,
    ) -> Result<(WalletId, String, SessionId)> {
        tracing::info!("Initializing new wallet with session-based encryption");

        // Step 1: Decrypt session key using RSA private key from attestation
        let session_key_bytes = self
            .attestation
            .decrypt_base64(encrypted_session_key_base64)
            .await?;

        if session_key_bytes.len() != 32 {
            return Err(EnclaveError::Crypto(format!(
                "Invalid session key size: expected 32 bytes, got {}",
                session_key_bytes.len()
            )));
        }

        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_key_bytes);

        // Step 2: Decrypt JWT using session key
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        let encrypted_jwt_bytes = BASE64
            .decode(encrypted_jwt_base64)
            .map_err(|e| EnclaveError::Crypto(format!("Base64 decode failed: {}", e)))?;

        // Decrypt JWT with session key (AES-256-GCM with prepended nonce)
        let jwt_plaintext = self.decrypt_with_key(&session_key, &encrypted_jwt_bytes)?;
        let jwt_str = String::from_utf8(jwt_plaintext.to_vec())
            .map_err(|e| EnclaveError::Auth(format!("Invalid JWT encoding: {}", e)))?;

        // Step 3: Validate JWT with JWKS
        let claims = self.jwt_validator.validate(&jwt_str).await?;
        let user_id = claims.sub.clone();

        tracing::info!("JWT validated for user: {}", user_id);

        // Step 4: Generate new seed using secure entropy
        let seed_manager = SeedManager::generate_new()?;
        let wallet_id = seed_manager.wallet_id();

        tracing::info!("Generated new seed for wallet_id: {}", wallet_id);

        // Step 5: Create wallet session
        let session = UserSession::new(
            seed_manager.clone(),
            self.pool.clone(),
            self.default_unit.clone(),
        )
        .await?;

        // Step 6: Add user as owner of the wallet
        let db = EncryptedPostgresDatabase::new(
            self.pool.clone(),
            wallet_id,
            *seed_manager.db_encryption_key(),
        );
        db.link_user_to_wallet(&user_id).await?;

        tracing::info!("Added user '{}' as owner of wallet {}", user_id, wallet_id);

        // Step 7: Store wallet session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(wallet_id, session);
        }

        // Step 8: Create session key entry
        let session_id = self
            .session_key_manager
            .create_session(session_key)
            .await;

        tracing::info!("Created session: {}", hex::encode(session_id));

        // Step 9: Encrypt seed with KMS for database storage
        let kms_encrypted = self.kms_service.encrypt_seed(seed_manager.seed()).await?;
        EncryptedPostgresDatabase::store_encrypted_seed(
            &self.pool,
            wallet_id,
            &kms_encrypted.encrypted_seed,
            kms_encrypted.kms_key_id.as_deref(),
            kms_encrypted.encryption_context.as_ref(),
        )
        .await?;

        tracing::info!("Encrypted seed stored in database for wallet {}", wallet_id);

        // Step 10: Encrypt seed with session key for return to client
        let encrypted_seed = self
            .session_key_manager
            .encrypt_with_session(&session_id, seed_manager.seed())
            .await?;
        let encrypted_seed_base64 = BASE64.encode(&encrypted_seed);

        tracing::info!("Wallet {} initialized successfully", wallet_id);

        Ok((wallet_id, encrypted_seed_base64, session_id))
    }

    /// Helper: Decrypt data with AES-256-GCM session key (nonce prepended)
    fn decrypt_with_key(&self, key: &[u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        const NONCE_SIZE: usize = 12;

        if encrypted_data.len() < NONCE_SIZE {
            return Err(EnclaveError::Crypto("Encrypted data too short".to_string()));
        }

        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(&encrypted_data[..NONCE_SIZE]);
        let ciphertext = &encrypted_data[NONCE_SIZE..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EnclaveError::Crypto(format!("AES-GCM decryption failed: {}", e)))
    }

    /// Load wallet from database if it exists
    /// This allows wallets to be auto-loaded from encrypted seeds stored in the database
    async fn load_wallet_from_database(&self, wallet_id: WalletId) -> Result<UserSession> {
        tracing::info!("Attempting to load wallet {} from database", wallet_id);

        // Fetch encrypted seed from database
        let seed_record = EncryptedPostgresDatabase::get_encrypted_seed(&self.pool, wallet_id)
            .await?
            .ok_or_else(|| {
                EnclaveError::WalletNotFound(format!(
                    "Wallet {} not found in database",
                    wallet_id
                ))
            })?;

        tracing::debug!(
            "Found encrypted seed for wallet {}, decrypting with KMS",
            wallet_id
        );

        // Decrypt seed using KMS
        let kms_data = crate::crypto::kms::EncryptedSeedData {
            encrypted_seed: seed_record.encrypted_seed,
            kms_key_id: seed_record.kms_key_id,
            encryption_context: seed_record.encryption_context,
        };

        let decrypted_seed = self.kms_service.decrypt_seed(&kms_data).await?;

        // Create seed manager from decrypted seed
        let seed_manager = SeedManager::from_seed_bytes(&*decrypted_seed)?;

        // Verify wallet ID matches
        if seed_manager.wallet_id() != wallet_id {
            return Err(EnclaveError::Crypto(format!(
                "Wallet ID mismatch: expected {}, got {}",
                wallet_id,
                seed_manager.wallet_id()
            )));
        }

        tracing::info!("Seed decrypted successfully for wallet {}", wallet_id);

        // Create user session
        let session = UserSession::new(seed_manager, self.pool.clone(), self.default_unit.clone())
            .await?;

        tracing::info!("Wallet {} loaded from database", wallet_id);

        Ok(session)
    }

    /// Execute wallet operation with session-based JWT authentication
    pub async fn execute_operation(
        &self,
        wallet_id: WalletId,
        session_id_hex: &str,
        encrypted_jwt_base64: &str,
        encrypted_request_base64: &str,
    ) -> Result<String> {
        // Step 1: Parse session ID
        let session_id_bytes = hex::decode(session_id_hex)
            .map_err(|e| EnclaveError::Auth(format!("Invalid session ID hex: {}", e)))?;

        if session_id_bytes.len() != 32 {
            return Err(EnclaveError::Auth(format!(
                "Invalid session ID length: expected 32, got {}",
                session_id_bytes.len()
            )));
        }

        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&session_id_bytes);

        // Step 2: Decrypt JWT using session key
        let jwt_str = self
            .session_key_manager
            .decrypt_string_with_session(&session_id, encrypted_jwt_base64)
            .await?;

        // Step 3: Validate JWT with JWKS
        let claims = self.jwt_validator.validate(&jwt_str).await?;

        // Step 4: Decrypt operation request (protobuf bytes)
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        let encrypted_bytes = BASE64
            .decode(encrypted_request_base64)
            .map_err(|e| EnclaveError::Crypto(format!("Base64 decode failed: {}", e)))?;

        let decrypted_bytes = self
            .session_key_manager
            .decrypt_with_session(&session_id, &encrypted_bytes)
            .await?;

        // Deserialize protobuf message
        let payload = proto::WalletOperationPayload::decode(&decrypted_bytes[..])
            .map_err(|e| EnclaveError::InvalidRequest(format!("Protobuf decode failed: {}", e)))?;

        // Convert protobuf to internal WalletOperation enum
        let operation = Self::protobuf_to_wallet_operation(payload)?;

        tracing::debug!("Executing operation: {:?} for wallet: {}", operation, wallet_id);

        // Step 5: Get or load wallet session
        let mut sessions = self.sessions.write().await;

        // Check if wallet is already loaded in memory
        if !sessions.contains_key(&wallet_id) {
            tracing::info!("Wallet {} not in memory, attempting to load from database", wallet_id);

            // Try to load from database
            match self.load_wallet_from_database(wallet_id).await {
                Ok(session) => {
                    sessions.insert(wallet_id, session);
                    tracing::info!("Wallet {} auto-loaded from database", wallet_id);
                }
                Err(e) => {
                    tracing::warn!("Failed to auto-load wallet {}: {}", wallet_id, e);
                    return Err(EnclaveError::WalletNotFound(format!(
                        "Wallet {} not found in memory or database",
                        wallet_id
                    )));
                }
            }
        }

        let session = sessions
            .get_mut(&wallet_id)
            .ok_or_else(|| EnclaveError::WalletNotFound(wallet_id.to_string()))?;

        // Step 6: Verify user owns this wallet
        let db = EncryptedPostgresDatabase::new(
            self.pool.clone(),
            wallet_id,
            *session.seed_manager.db_encryption_key(),
        );
        self.jwt_validator
            .verify_user_owns_wallet(&claims, &wallet_id, &db)
            .await?;

        // Update activity
        session.update_activity();

        // Step 7: Execute operation
        let result = self
            .execute_wallet_operation(&mut session.wallet, &db, operation)
            .await?;

        // Step 8: Encrypt response with session key
        let encrypted_response = self
            .session_key_manager
            .encrypt_json_with_session(&session_id, &result)
            .await?;

        Ok(encrypted_response)
    }

    /// Execute wallet operation
    async fn execute_wallet_operation(
        &self,
        wallet: &mut MultiMintWallet,
        db: &EncryptedPostgresDatabase,
        operation: WalletOperation,
    ) -> Result<serde_json::Value> {
        use WalletOperation::*;

        match operation {
            GetBalance { mint_url } => {
                let balance = if let Some(url) = mint_url {
                    let mint_url = MintUrl::from_str(&url)
                        .map_err(|e| EnclaveError::InvalidRequest(e.to_string()))?;
                    // Get balance from specific wallet
                    let wallet_opt = wallet.get_wallet(&mint_url).await;
                    wallet_opt
                        .ok_or_else(|| EnclaveError::Wallet("Mint not found".to_string()))?
                        .total_balance().await?
                } else {
                    wallet.total_balance().await?
                };

                Ok(serde_json::json!({ "balance": u64::from(balance) }))
            }

            Send { amount, mint_url } => {
                let mint_url = mint_url
                    .map(|url| MintUrl::from_str(&url))
                    .transpose()
                    .map_err(|e| EnclaveError::InvalidRequest(e.to_string()))?
                    .ok_or_else(|| EnclaveError::InvalidRequest("mint_url required for send".to_string()))?;

                let amount = Amount::from(amount);
                let opts = MultiMintSendOptions::default();
                let prepared = wallet.prepare_send(mint_url, amount, opts).await?;
                let token = prepared.confirm(None).await?;

                Ok(serde_json::json!({ "token": token }))
            }

            Receive { token } => {
                let opts = MultiMintReceiveOptions::default();
                let amount = wallet.receive(&token, opts).await?;
                Ok(serde_json::json!({ "received": u64::from(amount) }))
            }

            MintQuote { amount, mint_url } => {
                let mint_url = MintUrl::from_str(&mint_url)
                    .map_err(|e| EnclaveError::InvalidRequest(e.to_string()))?;
                let amount = Amount::from(amount);

                let quote = wallet.mint_quote(&mint_url, amount, None).await?;

                Ok(serde_json::json!({
                    "quote_id": quote.id,
                    "request": quote.request,
                    "expiry": quote.expiry
                }))
            }

            Mint { quote_id: _ } => {
                // Need to find which mint this quote belongs to
                // For now, return error - in real impl, track quote->mint mapping
                return Err(EnclaveError::Wallet(
                    "Mint operation requires mint_url tracking - not yet implemented".to_string()
                ));
            }

            MeltQuote { bolt11, mint_url } => {
                let mint_url = MintUrl::from_str(&mint_url)
                    .map_err(|e| EnclaveError::InvalidRequest(e.to_string()))?;

                let quote = wallet.melt_quote(&mint_url, bolt11, None).await?;

                Ok(serde_json::json!({
                    "quote_id": quote.id,
                    "amount": u64::from(quote.amount),
                    "fee_reserve": u64::from(quote.fee_reserve),
                    "state": format!("{:?}", quote.state),
                    "expiry": quote.expiry
                }))
            }

            Melt { quote_id, mint_url } => {
                let mint_url = MintUrl::from_str(&mint_url)
                    .map_err(|e| EnclaveError::InvalidRequest(e.to_string()))?;

                let melted = wallet.melt_with_mint(&mint_url, &quote_id).await?;

                Ok(serde_json::json!({
                    "state": format!("{:?}", melted.state),
                    "preimage": melted.preimage,
                    "amount": u64::from(melted.amount),
                    "fee_paid": u64::from(melted.fee_paid)
                }))
            }

            AddMint { mint_url } => {
                let mint_url = MintUrl::from_str(&mint_url)
                    .map_err(|e| EnclaveError::InvalidRequest(e.to_string()))?;

                wallet.add_mint(mint_url, None).await?;

                Ok(serde_json::json!({ "success": true }))
            }

            ListMints => {
                let wallets = wallet.get_wallets().await;
                let mint_urls: Vec<String> = wallets.iter()
                    .map(|w| w.mint_url.to_string())
                    .collect();

                Ok(serde_json::json!({ "mints": mint_urls }))
            }

            GetTransactions { mint_url: _ } => {
                let transactions = wallet.list_transactions(None).await?;

                Ok(serde_json::json!({ "transactions": transactions }))
            }

            AddUser { user_id } => {
                // Add user to this wallet in the database
                db.link_user_to_wallet(&user_id).await?;

                Ok(serde_json::json!({
                    "success": true,
                    "message": format!("User '{}' added to wallet", user_id)
                }))
            }

            RemoveUser { user_id } => {
                // Remove user from this wallet
                db.unlink_user_from_wallet(&user_id).await?;

                Ok(serde_json::json!({
                    "success": true,
                    "message": format!("User '{}' removed from wallet", user_id)
                }))
            }

            ListUsers => {
                // List all users for this wallet
                let user_ids = db.list_wallet_users().await?;

                Ok(serde_json::json!({
                    "users": user_ids
                }))
            }
        }
    }

    /// Convert protobuf WalletOperationPayload to internal WalletOperation enum
    fn protobuf_to_wallet_operation(payload: proto::WalletOperationPayload) -> Result<WalletOperation> {
        use proto::wallet_operation_payload::Operation;

        let operation = payload.operation
            .ok_or_else(|| EnclaveError::InvalidRequest("Missing operation in payload".to_string()))?;

        match operation {
            Operation::GetBalance(req) => Ok(WalletOperation::GetBalance {
                mint_url: req.mint_url,
            }),
            Operation::Send(req) => Ok(WalletOperation::Send {
                amount: req.amount,
                mint_url: req.mint_url,
            }),
            Operation::Receive(req) => Ok(WalletOperation::Receive {
                token: req.token,
            }),
            Operation::MintQuote(req) => Ok(WalletOperation::MintQuote {
                amount: req.amount,
                mint_url: req.mint_url,
            }),
            Operation::Mint(req) => Ok(WalletOperation::Mint {
                quote_id: req.quote_id,
            }),
            Operation::MeltQuote(req) => Ok(WalletOperation::MeltQuote {
                bolt11: req.bolt11,
                mint_url: req.mint_url,
            }),
            Operation::Melt(req) => Ok(WalletOperation::Melt {
                quote_id: req.quote_id,
                mint_url: req.mint_url,
            }),
            Operation::AddMint(req) => Ok(WalletOperation::AddMint {
                mint_url: req.mint_url,
            }),
            Operation::ListMints(_) => Ok(WalletOperation::ListMints),
            Operation::GetTransactions(req) => Ok(WalletOperation::GetTransactions {
                mint_url: req.mint_url,
            }),
            Operation::AddUser(req) => Ok(WalletOperation::AddUser {
                user_id: req.user_id,
            }),
            Operation::RemoveUser(req) => Ok(WalletOperation::RemoveUser {
                user_id: req.user_id,
            }),
            Operation::ListUsers(_) => Ok(WalletOperation::ListUsers),
        }
    }

    /// Clean up expired sessions (both wallet and session keys)
    pub async fn cleanup_expired_sessions(&self) {
        // Clean up wallet sessions
        {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|wallet_id, session| {
                if session.is_expired() {
                    tracing::info!("Removing expired wallet session for wallet_id: {}", wallet_id);
                    false
                } else {
                    true
                }
            });
        }

        // Clean up session keys
        self.session_key_manager.cleanup_expired_sessions().await;
    }
}
