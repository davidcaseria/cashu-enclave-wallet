use crate::crypto::encryption::{decrypt_json, encrypt_json};
use crate::error::{EnclaveError, Result};
use crate::types::{EncryptedBlob, WalletId};
use async_trait::async_trait;
use cdk::cdk_database::{Error as CdkDbError, WalletDatabase};
use cdk::nuts::{CurrencyUnit, Id, KeySetInfo, Keys, MintInfo, PublicKey, SpendingConditions, State};
use cdk::nuts::nut02::KeySet;
use cdk::types::ProofInfo;
use cdk::wallet::types::{MeltQuote, MintQuote, Transaction, TransactionDirection, TransactionId};
use cdk::mint_url::MintUrl;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Encrypted PostgreSQL database implementation
#[derive(Clone)]
pub struct EncryptedPostgresDatabase {
    pool: PgPool,
    wallet_id: WalletId,
    encryption_key: Arc<Zeroizing<[u8; 32]>>,
}

impl Debug for EncryptedPostgresDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedPostgresDatabase")
            .field("wallet_id", &self.wallet_id)
            .finish()
    }
}

impl EncryptedPostgresDatabase {
    /// Create a new encrypted database instance
    pub fn new(pool: PgPool, wallet_id: WalletId, encryption_key: [u8; 32]) -> Self {
        Self {
            pool,
            wallet_id,
            encryption_key: Arc::new(Zeroizing::new(encryption_key)),
        }
    }

    /// Encrypt data for storage
    fn encrypt<T: Serialize>(&self, data: &T) -> Result<Vec<u8>> {
        let blob = encrypt_json(&self.encryption_key, data)?;
        Ok(blob.to_bytes())
    }

    /// Decrypt data from storage
    fn decrypt<T: for<'de> Deserialize<'de>>(&self, encrypted: &[u8]) -> Result<T> {
        let blob = EncryptedBlob::from_bytes(encrypted)
            .map_err(|e| EnclaveError::Database(e))?;
        decrypt_json(&self.encryption_key, &blob)
    }

    /// Convert error to CdkDbError
    fn to_db_error<E: std::error::Error + Send + Sync + 'static>(e: E) -> CdkDbError {
        CdkDbError::Database(Box::new(e))
    }
}

#[async_trait]
impl WalletDatabase for EncryptedPostgresDatabase {
    type Err = CdkDbError;

    /// Add a new mint
    async fn add_mint(
        &self,
        mint_url: MintUrl,
        mint_info: Option<MintInfo>,
    ) -> std::result::Result<(), Self::Err> {
        let mint_info_encrypted = match mint_info {
            Some(info) => Some(self.encrypt(&info).map_err(Self::to_db_error)?),
            None => None,
        };

        sqlx::query!(
            "INSERT INTO wallets (wallet_id, mint_url, mint_info_encrypted, created_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (wallet_id, mint_url) DO UPDATE
             SET mint_info_encrypted = EXCLUDED.mint_info_encrypted",
            self.wallet_id.as_bytes(),
            mint_url.to_string(),
            mint_info_encrypted
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Remove a mint
    async fn remove_mint(&self, mint_url: MintUrl) -> std::result::Result<(), Self::Err> {
        sqlx::query!(
            "DELETE FROM wallets WHERE wallet_id = $1 AND mint_url = $2",
            self.wallet_id.as_bytes(),
            mint_url.to_string()
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Get mint info
    async fn get_mint(&self, mint_url: MintUrl) -> std::result::Result<Option<MintInfo>, Self::Err> {
        let row = sqlx::query!(
            "SELECT mint_info_encrypted FROM wallets WHERE wallet_id = $1 AND mint_url = $2",
            self.wallet_id.as_bytes(),
            mint_url.to_string()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        match row {
            Some(r) => match &r.mint_info_encrypted {
                Some(encrypted) => {
                    let info = self.decrypt(encrypted)
                        .map_err(Self::to_db_error)?;
                    Ok(Some(info))
                }
                None => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// Get all mints
    async fn get_mints(&self) -> std::result::Result<HashMap<MintUrl, Option<MintInfo>>, Self::Err> {
        let rows = sqlx::query!(
            "SELECT mint_url, mint_info_encrypted FROM wallets WHERE wallet_id = $1",
            self.wallet_id.as_bytes()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        let mut mints = HashMap::new();
        for row in rows {
            let mint_url = MintUrl::from_str(&row.mint_url)
                .map_err(Self::to_db_error)?;

            let mint_info = match &row.mint_info_encrypted {
                Some(encrypted) => Some(
                    self.decrypt(encrypted)
                        .map_err(Self::to_db_error)?,
                ),
                None => None,
            };

            mints.insert(mint_url, mint_info);
        }

        Ok(mints)
    }

    /// Update mint URL
    async fn update_mint_url(
        &self,
        old_mint_url: MintUrl,
        new_mint_url: MintUrl,
    ) -> std::result::Result<(), Self::Err> {
        sqlx::query!(
            "UPDATE wallets SET mint_url = $3 WHERE wallet_id = $1 AND mint_url = $2",
            self.wallet_id.as_bytes(),
            old_mint_url.to_string(),
            new_mint_url.to_string()
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Add mint keysets
    async fn add_mint_keysets(
        &self,
        mint_url: MintUrl,
        keysets: Vec<KeySetInfo>,
    ) -> std::result::Result<(), Self::Err> {
        for keyset in keysets {
            let keyset_encrypted = self.encrypt(&keyset)
                .map_err(Self::to_db_error)?;

            sqlx::query!(
                "INSERT INTO keysets (wallet_id, mint_url, keyset_id, keyset_info_encrypted, created_at)
                 VALUES ($1, $2, $3, $4, NOW())
                 ON CONFLICT (wallet_id, mint_url, keyset_id) DO UPDATE
                 SET keyset_info_encrypted = EXCLUDED.keyset_info_encrypted",
                self.wallet_id.as_bytes(),
                mint_url.to_string(),
                keyset.id.to_bytes(),
                keyset_encrypted
            )
            .execute(&self.pool)
            .await
            .map_err(Self::to_db_error)?;
        }

        Ok(())
    }

    /// Get mint keysets
    async fn get_mint_keysets(
        &self,
        mint_url: MintUrl,
    ) -> std::result::Result<Option<Vec<KeySetInfo>>, Self::Err> {
        let rows = sqlx::query!(
            "SELECT keyset_info_encrypted FROM keysets WHERE wallet_id = $1 AND mint_url = $2",
            self.wallet_id.as_bytes(),
            mint_url.to_string()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        if rows.is_empty() {
            return Ok(None);
        }

        let mut keysets = Vec::new();
        for row in rows {
            let keyset: KeySetInfo = self.decrypt(&row.keyset_info_encrypted)
                .map_err(Self::to_db_error)?;
            keysets.push(keyset);
        }

        Ok(Some(keysets))
    }

    /// Get keyset by ID
    async fn get_keyset_by_id(&self, keyset_id: &Id) -> std::result::Result<Option<KeySetInfo>, Self::Err> {
        let row = sqlx::query!(
            "SELECT keyset_info_encrypted FROM keysets WHERE wallet_id = $1 AND keyset_id = $2",
            self.wallet_id.as_bytes(),
            keyset_id.to_bytes()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        match row {
            Some(r) => {
                let keyset = self.decrypt(&r.keyset_info_encrypted)
                    .map_err(Self::to_db_error)?;
                Ok(Some(keyset))
            }
            None => Ok(None),
        }
    }

    /// Add mint quote
    async fn add_mint_quote(&self, quote: MintQuote) -> std::result::Result<(), Self::Err> {
        let quote_encrypted = self.encrypt(&quote)
            .map_err(Self::to_db_error)?;

        let state = quote.state as i32;

        sqlx::query!(
            "INSERT INTO mint_quotes (wallet_id, quote_id, quote_encrypted, state, created_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT (wallet_id, quote_id) DO UPDATE
             SET quote_encrypted = EXCLUDED.quote_encrypted, state = EXCLUDED.state",
            self.wallet_id.as_bytes(),
            quote.id,
            quote_encrypted,
            state
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Get mint quote
    async fn get_mint_quote(&self, quote_id: &str) -> std::result::Result<Option<MintQuote>, Self::Err> {
        let row = sqlx::query!(
            "SELECT quote_encrypted FROM mint_quotes WHERE wallet_id = $1 AND quote_id = $2",
            self.wallet_id.as_bytes(),
            quote_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        match row {
            Some(r) => {
                let quote = self.decrypt(&r.quote_encrypted)
                    .map_err(Self::to_db_error)?;
                Ok(Some(quote))
            }
            None => Ok(None),
        }
    }

    /// Get all mint quotes
    async fn get_mint_quotes(&self) -> std::result::Result<Vec<MintQuote>, Self::Err> {
        let rows = sqlx::query!(
            "SELECT quote_encrypted FROM mint_quotes WHERE wallet_id = $1",
            self.wallet_id.as_bytes()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        let mut quotes = Vec::new();
        for row in rows {
            let quote = self.decrypt(&row.quote_encrypted)
                .map_err(Self::to_db_error)?;
            quotes.push(quote);
        }

        Ok(quotes)
    }

    /// Remove mint quote
    async fn remove_mint_quote(&self, quote_id: &str) -> std::result::Result<(), Self::Err> {
        sqlx::query!(
            "DELETE FROM mint_quotes WHERE wallet_id = $1 AND quote_id = $2",
            self.wallet_id.as_bytes(),
            quote_id
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Add melt quote
    async fn add_melt_quote(&self, quote: MeltQuote) -> std::result::Result<(), Self::Err> {
        let quote_encrypted = self.encrypt(&quote)
            .map_err(Self::to_db_error)?;

        let state = quote.state as i32;

        sqlx::query!(
            "INSERT INTO melt_quotes (wallet_id, quote_id, quote_encrypted, state, created_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT (wallet_id, quote_id) DO UPDATE
             SET quote_encrypted = EXCLUDED.quote_encrypted, state = EXCLUDED.state",
            self.wallet_id.as_bytes(),
            quote.id,
            quote_encrypted,
            state
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Get melt quote
    async fn get_melt_quote(&self, quote_id: &str) -> std::result::Result<Option<MeltQuote>, Self::Err> {
        let row = sqlx::query!(
            "SELECT quote_encrypted FROM melt_quotes WHERE wallet_id = $1 AND quote_id = $2",
            self.wallet_id.as_bytes(),
            quote_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        match row {
            Some(r) => {
                let quote = self.decrypt(&r.quote_encrypted)
                    .map_err(Self::to_db_error)?;
                Ok(Some(quote))
            }
            None => Ok(None),
        }
    }

    /// Get all melt quotes
    async fn get_melt_quotes(&self) -> std::result::Result<Vec<MeltQuote>, Self::Err> {
        let rows = sqlx::query!(
            "SELECT quote_encrypted FROM melt_quotes WHERE wallet_id = $1",
            self.wallet_id.as_bytes()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        let mut quotes = Vec::new();
        for row in rows {
            let quote = self.decrypt(&row.quote_encrypted)
                .map_err(Self::to_db_error)?;
            quotes.push(quote);
        }

        Ok(quotes)
    }

    /// Remove melt quote
    async fn remove_melt_quote(&self, quote_id: &str) -> std::result::Result<(), Self::Err> {
        sqlx::query!(
            "DELETE FROM melt_quotes WHERE wallet_id = $1 AND quote_id = $2",
            self.wallet_id.as_bytes(),
            quote_id
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Add keys for a keyset
    async fn add_keys(&self, keyset: KeySet) -> std::result::Result<(), Self::Err> {
        let keys_encrypted = self.encrypt(&keyset)
            .map_err(Self::to_db_error)?;

        sqlx::query!(
            "INSERT INTO keys (wallet_id, keyset_id, keys_encrypted, created_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (wallet_id, keyset_id) DO UPDATE
             SET keys_encrypted = EXCLUDED.keys_encrypted",
            self.wallet_id.as_bytes(),
            keyset.id.to_bytes(),
            keys_encrypted
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Get keys for a keyset
    async fn get_keys(&self, id: &Id) -> std::result::Result<Option<Keys>, Self::Err> {
        let row = sqlx::query!(
            "SELECT keys_encrypted FROM keys WHERE wallet_id = $1 AND keyset_id = $2",
            self.wallet_id.as_bytes(),
            id.to_bytes()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        match row {
            Some(r) => {
                let keys = self.decrypt(&r.keys_encrypted)
                    .map_err(Self::to_db_error)?;
                Ok(Some(keys))
            }
            None => Ok(None),
        }
    }

    /// Remove keys for a keyset
    async fn remove_keys(&self, id: &Id) -> std::result::Result<(), Self::Err> {
        sqlx::query!(
            "DELETE FROM keys WHERE wallet_id = $1 AND keyset_id = $2",
            self.wallet_id.as_bytes(),
            id.to_bytes()
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Update proofs (add new, remove spent)
    async fn update_proofs(
        &self,
        added: Vec<ProofInfo>,
        removed_ys: Vec<PublicKey>,
    ) -> std::result::Result<(), Self::Err> {
        // Remove spent proofs
        for y in removed_ys {
            sqlx::query!(
                "DELETE FROM proofs WHERE wallet_id = $1 AND y_hash = $2",
                self.wallet_id.as_bytes(),
                &y.to_bytes()
            )
            .execute(&self.pool)
            .await
            .map_err(Self::to_db_error)?;
        }

        // Add new proofs
        for proof_info in added {
            let proof_encrypted = self.encrypt(&proof_info)
                .map_err(Self::to_db_error)?;

            let state = proof_info.state as i32;
            let unit = proof_info.unit.to_string();

            sqlx::query!(
                "INSERT INTO proofs (wallet_id, y_hash, proof_encrypted, mint_url, state, unit, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, NOW())
                 ON CONFLICT (wallet_id, y_hash) DO UPDATE
                 SET proof_encrypted = EXCLUDED.proof_encrypted,
                     state = EXCLUDED.state",
                self.wallet_id.as_bytes(),
                &proof_info.y.to_bytes(),
                proof_encrypted,
                proof_info.mint_url.to_string(),
                state,
                unit
            )
            .execute(&self.pool)
            .await
            .map_err(Self::to_db_error)?;
        }

        Ok(())
    }

    /// Get proofs with filters
    async fn get_proofs(
        &self,
        mint_url: Option<MintUrl>,
        unit: Option<CurrencyUnit>,
        state: Option<Vec<State>>,
        spending_conditions: Option<Vec<SpendingConditions>>,
    ) -> std::result::Result<Vec<ProofInfo>, Self::Err> {
        // Build query based on filters
        let mut query = String::from("SELECT proof_encrypted FROM proofs WHERE wallet_id = $1");
        let mut param_idx = 2;

        if mint_url.is_some() {
            query.push_str(&format!(" AND mint_url = ${}", param_idx));
            param_idx += 1;
        }

        if unit.is_some() {
            query.push_str(&format!(" AND unit = ${}", param_idx));
            param_idx += 1;
        }

        if state.is_some() {
            query.push_str(&format!(" AND state = ANY(${})", param_idx));
        }

        // Execute query with parameters
        let mut q = sqlx::query_scalar::<_, Vec<u8>>(&query);
        q = q.bind(self.wallet_id.as_bytes());

        if let Some(url) = mint_url {
            q = q.bind(url.to_string());
        }

        if let Some(u) = unit {
            q = q.bind(u.to_string());
        }

        // Convert state to i32 outside if block to extend lifetime
        let state_ints: Option<Vec<i32>> = state.map(|states| states.iter().map(|s| *s as i32).collect());
        if let Some(ref ints) = state_ints {
            q = q.bind(ints);
        }

        let rows = q.fetch_all(&self.pool)
            .await
            .map_err(Self::to_db_error)?;

        let mut proofs = Vec::new();
        for encrypted in rows {
            let proof_info: ProofInfo = self.decrypt(&encrypted)
                .map_err(Self::to_db_error)?;

            // Filter by spending conditions if specified
            if let Some(ref conds) = spending_conditions {
                if let Some(ref proof_cond) = proof_info.spending_condition {
                    if !conds.contains(proof_cond) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            proofs.push(proof_info);
        }

        Ok(proofs)
    }

    /// Get balance
    async fn get_balance(
        &self,
        mint_url: Option<MintUrl>,
        unit: Option<CurrencyUnit>,
        state: Option<Vec<State>>,
    ) -> std::result::Result<u64, Self::Err> {
        // Get proofs matching the filters
        let proofs = self.get_proofs(mint_url, unit, state, None).await?;

        // Sum up the amounts (convert Amount to u64)
        let balance: u64 = proofs.iter().map(|p| u64::from(p.proof.amount)).sum();

        Ok(balance)
    }

    /// Update proof states
    async fn update_proofs_state(
        &self,
        ys: Vec<PublicKey>,
        state: State,
    ) -> std::result::Result<(), Self::Err> {
        let state_int = state as i32;

        for y in ys {
            // Need to re-encrypt with updated state
            // First fetch and decrypt
            let row = sqlx::query!(
                "SELECT proof_encrypted FROM proofs WHERE wallet_id = $1 AND y_hash = $2",
                self.wallet_id.as_bytes(),
                &y.to_bytes()
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(Self::to_db_error)?;

            if let Some(r) = row {
                let mut proof_info: ProofInfo = self.decrypt(&r.proof_encrypted)
                    .map_err(Self::to_db_error)?;

                // Update state
                proof_info.state = state;

                // Re-encrypt
                let proof_encrypted = self.encrypt(&proof_info)
                    .map_err(Self::to_db_error)?;

                // Update in database
                sqlx::query!(
                    "UPDATE proofs SET proof_encrypted = $3, state = $4 WHERE wallet_id = $1 AND y_hash = $2",
                    self.wallet_id.as_bytes(),
                    &y.to_bytes(),
                    proof_encrypted,
                    state_int
                )
                .execute(&self.pool)
                .await
                .map_err(Self::to_db_error)?;
            }
        }

        Ok(())
    }

    /// Increment keyset counter
    async fn increment_keyset_counter(
        &self,
        keyset_id: &Id,
        count: u32,
    ) -> std::result::Result<u32, Self::Err> {
        let result = sqlx::query!(
            "INSERT INTO keyset_counters (wallet_id, keyset_id, counter)
             VALUES ($1, $2, $3)
             ON CONFLICT (wallet_id, keyset_id) DO UPDATE
             SET counter = keyset_counters.counter + $3
             RETURNING counter",
            self.wallet_id.as_bytes(),
            keyset_id.to_bytes(),
            count as i32
        )
        .fetch_one(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(result.counter as u32)
    }

    /// Add transaction
    async fn add_transaction(&self, transaction: Transaction) -> std::result::Result<(), Self::Err> {
        let transaction_encrypted = self.encrypt(&transaction)
            .map_err(Self::to_db_error)?;

        let direction = transaction.direction as i32;
        let tx_id = transaction.id();
        let tx_id_bytes = tx_id.as_bytes();

        sqlx::query!(
            "INSERT INTO transactions (wallet_id, tx_id, transaction_encrypted, mint_url, direction, unit, timestamp, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
             ON CONFLICT (wallet_id, tx_id) DO UPDATE
             SET transaction_encrypted = EXCLUDED.transaction_encrypted",
            self.wallet_id.as_bytes(),
            tx_id_bytes,
            transaction_encrypted,
            transaction.mint_url.to_string(),
            direction,
            transaction.unit.to_string(),
            transaction.timestamp as i64
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }

    /// Get transaction by ID
    async fn get_transaction(
        &self,
        transaction_id: TransactionId,
    ) -> std::result::Result<Option<Transaction>, Self::Err> {
        let row = sqlx::query!(
            "SELECT transaction_encrypted FROM transactions WHERE wallet_id = $1 AND tx_id = $2",
            self.wallet_id.as_bytes(),
            transaction_id.as_bytes()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        match row {
            Some(r) => {
                let tx = self.decrypt(&r.transaction_encrypted)
                    .map_err(Self::to_db_error)?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    /// List transactions with filters
    async fn list_transactions(
        &self,
        mint_url: Option<MintUrl>,
        direction: Option<TransactionDirection>,
        unit: Option<CurrencyUnit>,
    ) -> std::result::Result<Vec<Transaction>, Self::Err> {
        let mut query = String::from("SELECT transaction_encrypted FROM transactions WHERE wallet_id = $1");
        let mut param_idx = 2;

        if mint_url.is_some() {
            query.push_str(&format!(" AND mint_url = ${}", param_idx));
            param_idx += 1;
        }

        if direction.is_some() {
            query.push_str(&format!(" AND direction = ${}", param_idx));
            param_idx += 1;
        }

        if unit.is_some() {
            query.push_str(&format!(" AND unit = ${}", param_idx));
        }

        query.push_str(" ORDER BY timestamp DESC");

        let mut q = sqlx::query_scalar::<_, Vec<u8>>(&query);
        q = q.bind(self.wallet_id.as_bytes());

        if let Some(url) = mint_url {
            q = q.bind(url.to_string());
        }

        if let Some(dir) = direction {
            q = q.bind(dir as i32);
        }

        if let Some(u) = unit {
            q = q.bind(u.to_string());
        }

        let rows = q.fetch_all(&self.pool)
            .await
            .map_err(Self::to_db_error)?;

        let mut transactions = Vec::new();
        for encrypted in rows {
            let tx = self.decrypt(&encrypted)
                .map_err(Self::to_db_error)?;
            transactions.push(tx);
        }

        Ok(transactions)
    }

    /// Remove transaction
    async fn remove_transaction(
        &self,
        transaction_id: TransactionId,
    ) -> std::result::Result<(), Self::Err> {
        sqlx::query!(
            "DELETE FROM transactions WHERE wallet_id = $1 AND tx_id = $2",
            self.wallet_id.as_bytes(),
            transaction_id.as_bytes()
        )
        .execute(&self.pool)
        .await
        .map_err(Self::to_db_error)?;

        Ok(())
    }
}

// Additional methods for user-wallet mapping
impl EncryptedPostgresDatabase {
    /// Link a user to this wallet
    /// Encrypts the user_id with the wallet's encryption key before storing
    pub async fn link_user_to_wallet(&self, user_id: &str) -> Result<()> {
        // Encrypt user_id with wallet encryption key
        let user_id_encrypted = self.encrypt(&user_id)?;

        sqlx::query!(
            "INSERT INTO user_wallets (user_id_encrypted, wallet_id, created_at)
             VALUES ($1, $2, NOW())
             ON CONFLICT (user_id_encrypted, wallet_id) DO NOTHING",
            user_id_encrypted,
            self.wallet_id.as_bytes()
        )
        .execute(&self.pool)
        .await
        .map_err(|e| EnclaveError::Database(format!("Failed to link user to wallet: {}", e)))?;

        Ok(())
    }

    /// Unlink a user from this wallet
    /// Note: Must decrypt all users to find the match since AES-GCM produces different ciphertext each time
    pub async fn unlink_user_from_wallet(&self, user_id: &str) -> Result<()> {
        let rows = sqlx::query!(
            "SELECT user_id_encrypted FROM user_wallets WHERE wallet_id = $1",
            self.wallet_id.as_bytes()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EnclaveError::Database(format!("Failed to fetch wallet users: {}", e)))?;

        // Find and delete the matching user
        for row in rows {
            let decrypted_user_id: String = self.decrypt(&row.user_id_encrypted)?;
            if decrypted_user_id == user_id {
                sqlx::query!(
                    "DELETE FROM user_wallets WHERE user_id_encrypted = $1 AND wallet_id = $2",
                    row.user_id_encrypted,
                    self.wallet_id.as_bytes()
                )
                .execute(&self.pool)
                .await
                .map_err(|e| EnclaveError::Database(format!("Failed to unlink user from wallet: {}", e)))?;
                return Ok(());
            }
        }

        // User not found - not an error, just return Ok
        Ok(())
    }

    /// Verify that a user owns this wallet
    /// Returns true if a user-wallet mapping exists
    /// Note: Must decrypt all users since AES-GCM with random nonces produces different ciphertext each time
    pub async fn verify_user_owns_wallet(&self, user_id: &str) -> Result<bool> {
        let rows = sqlx::query!(
            "SELECT user_id_encrypted FROM user_wallets WHERE wallet_id = $1",
            self.wallet_id.as_bytes()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EnclaveError::Database(format!("Failed to fetch wallet users: {}", e)))?;

        // Decrypt and check each user_id
        for row in rows {
            let decrypted_user_id: String = self.decrypt(&row.user_id_encrypted)?;
            if decrypted_user_id == user_id {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// List all users for this wallet
    /// Returns decrypted user IDs
    pub async fn list_wallet_users(&self) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            "SELECT user_id_encrypted FROM user_wallets WHERE wallet_id = $1",
            self.wallet_id.as_bytes()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EnclaveError::Database(format!("Failed to list wallet users: {}", e)))?;

        let mut user_ids = Vec::new();
        for row in rows {
            // Decrypt each user_id
            let user_id: String = self.decrypt(&row.user_id_encrypted)?;
            user_ids.push(user_id);
        }

        Ok(user_ids)
    }

    // ========================================================================
    // Seeds table operations
    // ========================================================================

    /// Store encrypted seed in database
    /// This allows wallets to be auto-loaded on demand without requiring client-side storage
    pub async fn store_encrypted_seed(
        pool: &PgPool,
        wallet_id: WalletId,
        encrypted_seed: &[u8],
        kms_key_id: Option<&str>,
        encryption_context: Option<&serde_json::Value>,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO seeds (wallet_id, encrypted_seed, kms_key_id, encryption_context, created_at, updated_at)
             VALUES ($1, $2, $3, $4, NOW(), NOW())
             ON CONFLICT (wallet_id) DO UPDATE
             SET encrypted_seed = EXCLUDED.encrypted_seed,
                 kms_key_id = EXCLUDED.kms_key_id,
                 encryption_context = EXCLUDED.encryption_context,
                 updated_at = NOW()",
            wallet_id.as_bytes(),
            encrypted_seed,
            kms_key_id,
            encryption_context
        )
        .execute(pool)
        .await
        .map_err(|e| EnclaveError::Database(format!("Failed to store encrypted seed: {}", e)))?;

        tracing::info!("Encrypted seed stored for wallet_id: {}", wallet_id);
        Ok(())
    }

    /// Get encrypted seed from database
    /// Returns None if wallet seed is not stored
    pub async fn get_encrypted_seed(
        pool: &PgPool,
        wallet_id: WalletId,
    ) -> Result<Option<EncryptedSeedRecord>> {
        let row = sqlx::query!(
            "SELECT encrypted_seed, kms_key_id, encryption_context, created_at, updated_at
             FROM seeds WHERE wallet_id = $1",
            wallet_id.as_bytes()
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| EnclaveError::Database(format!("Failed to fetch encrypted seed: {}", e)))?;

        match row {
            Some(r) => Ok(Some(EncryptedSeedRecord {
                wallet_id,
                encrypted_seed: r.encrypted_seed,
                kms_key_id: r.kms_key_id,
                encryption_context: r.encryption_context,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })),
            None => Ok(None),
        }
    }

    /// Delete encrypted seed from database
    /// This removes the ability to auto-load the wallet, requiring manual seed import
    pub async fn delete_encrypted_seed(pool: &PgPool, wallet_id: WalletId) -> Result<()> {
        sqlx::query!(
            "DELETE FROM seeds WHERE wallet_id = $1",
            wallet_id.as_bytes()
        )
        .execute(pool)
        .await
        .map_err(|e| EnclaveError::Database(format!("Failed to delete encrypted seed: {}", e)))?;

        tracing::info!("Encrypted seed deleted for wallet_id: {}", wallet_id);
        Ok(())
    }

    /// List all wallet IDs that have stored seeds
    pub async fn list_wallets_with_seeds(pool: &PgPool) -> Result<Vec<WalletId>> {
        let rows = sqlx::query!(
            "SELECT wallet_id FROM seeds ORDER BY created_at DESC"
        )
        .fetch_all(pool)
        .await
        .map_err(|e| EnclaveError::Database(format!("Failed to list wallets: {}", e)))?;

        let mut wallet_ids = Vec::new();
        for row in rows {
            if row.wallet_id.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&row.wallet_id);
                wallet_ids.push(WalletId(arr));
            } else {
                tracing::warn!(
                    "Skipping wallet with invalid ID length: expected 16, got {}",
                    row.wallet_id.len()
                );
            }
        }

        Ok(wallet_ids)
    }
}

/// Record from the seeds table
#[derive(Debug, Clone)]
pub struct EncryptedSeedRecord {
    pub wallet_id: WalletId,
    pub encrypted_seed: Vec<u8>,
    pub kms_key_id: Option<String>,
    pub encryption_context: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
