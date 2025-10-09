-- Initial schema for Cashu Enclave Wallet
-- All sensitive data is stored encrypted using wallet-specific keys
-- Uses sequence-based primary keys for proper relational database design
-- Wallet IDs use SHA-128 (16 bytes) for efficient routing

-- Seeds table - stores encrypted wallet seeds for persistence
-- Seeds are encrypted using AWS KMS (production) or dev key (local)
CREATE TABLE IF NOT EXISTS seeds (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16), -- SHA-128 (16 bytes)
    encrypted_seed BYTEA NOT NULL,
    kms_key_id TEXT, -- AWS KMS key ID (production only)
    encryption_context JSONB, -- Additional KMS context for attestation
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_seeds_wallet_id ON seeds(wallet_id);
CREATE INDEX idx_seeds_created_at ON seeds(created_at);

COMMENT ON TABLE seeds IS 'Stores encrypted wallet seeds. Seeds are encrypted with AWS KMS (production) or dev key (local) and can be auto-loaded on demand.';
COMMENT ON COLUMN seeds.wallet_id IS 'SHA-128 hash of seed (first 16 bytes of SHA-256). Used for routing and session management.';
COMMENT ON COLUMN seeds.encrypted_seed IS 'Wallet seed encrypted with KMS or dev key. Can only be decrypted inside the enclave.';
COMMENT ON COLUMN seeds.kms_key_id IS 'AWS KMS key ID used for encryption (production only). NULL in local dev mode.';
COMMENT ON COLUMN seeds.encryption_context IS 'Additional context for KMS operations, includes attestation document hash.';

-- Wallets table - stores mint URLs and encrypted mint info
CREATE TABLE IF NOT EXISTS wallets (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16), -- SHA-128
    mint_url TEXT NOT NULL,
    mint_info_encrypted BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_wallets_wallet_mint ON wallets(wallet_id, mint_url);
CREATE INDEX idx_wallets_wallet_id ON wallets(wallet_id);
CREATE INDEX idx_wallets_mint_url ON wallets(mint_url);

COMMENT ON TABLE wallets IS 'Stores wallet-mint associations. mint_info_encrypted contains sensitive data encrypted with wallet-specific key.';

-- Keysets table - stores encrypted keyset information
CREATE TABLE IF NOT EXISTS keysets (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16),
    mint_url TEXT NOT NULL,
    keyset_id BYTEA NOT NULL,
    keyset_info_encrypted BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_keysets_wallet_mint_keyset ON keysets(wallet_id, mint_url, keyset_id);
CREATE INDEX idx_keysets_wallet_id ON keysets(wallet_id);
CREATE INDEX idx_keysets_mint_url ON keysets(mint_url);

-- Proofs table - stores encrypted proof data with plaintext indexes
CREATE TABLE IF NOT EXISTS proofs (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16),
    y_hash BYTEA NOT NULL,
    proof_encrypted BYTEA NOT NULL,
    mint_url TEXT NOT NULL,
    state INTEGER NOT NULL,
    unit TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_proofs_wallet_y_hash ON proofs(wallet_id, y_hash);
CREATE INDEX idx_proofs_wallet_id ON proofs(wallet_id);
CREATE INDEX idx_proofs_mint_url ON proofs(wallet_id, mint_url);
CREATE INDEX idx_proofs_state ON proofs(wallet_id, state);
CREATE INDEX idx_proofs_unit ON proofs(wallet_id, unit);
CREATE INDEX idx_proofs_y_hash ON proofs(y_hash);

COMMENT ON TABLE proofs IS 'Stores ecash proofs. proof_encrypted contains the full proof encrypted with wallet-specific key. Plaintext fields enable efficient querying without decryption.';

-- Mint quotes table - stores encrypted quote data
CREATE TABLE IF NOT EXISTS mint_quotes (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16),
    quote_id TEXT NOT NULL,
    quote_encrypted BYTEA NOT NULL,
    state INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_mint_quotes_wallet_quote ON mint_quotes(wallet_id, quote_id);
CREATE INDEX idx_mint_quotes_wallet_id ON mint_quotes(wallet_id);
CREATE INDEX idx_mint_quotes_state ON mint_quotes(wallet_id, state);
CREATE INDEX idx_mint_quotes_quote_id ON mint_quotes(quote_id);

COMMENT ON TABLE mint_quotes IS 'Stores mint quotes. quote_encrypted contains sensitive quote data including private keys, encrypted with wallet-specific key.';

-- Melt quotes table - stores encrypted quote data
CREATE TABLE IF NOT EXISTS melt_quotes (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16),
    quote_id TEXT NOT NULL,
    quote_encrypted BYTEA NOT NULL,
    state INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_melt_quotes_wallet_quote ON melt_quotes(wallet_id, quote_id);
CREATE INDEX idx_melt_quotes_wallet_id ON melt_quotes(wallet_id);
CREATE INDEX idx_melt_quotes_state ON melt_quotes(wallet_id, state);
CREATE INDEX idx_melt_quotes_quote_id ON melt_quotes(quote_id);

COMMENT ON TABLE melt_quotes IS 'Stores melt quotes. quote_encrypted contains sensitive quote data, encrypted with wallet-specific key.';

-- Keys table - stores encrypted keyset keys
CREATE TABLE IF NOT EXISTS keys (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16),
    keyset_id BYTEA NOT NULL,
    keys_encrypted BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_keys_wallet_keyset ON keys(wallet_id, keyset_id);
CREATE INDEX idx_keys_wallet_id ON keys(wallet_id);
CREATE INDEX idx_keys_keyset_id ON keys(keyset_id);

-- Transactions table - stores encrypted transaction data with plaintext indexes
CREATE TABLE IF NOT EXISTS transactions (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16),
    tx_id BYTEA NOT NULL,
    transaction_encrypted BYTEA NOT NULL,
    mint_url TEXT NOT NULL,
    direction INTEGER NOT NULL,
    unit TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_transactions_wallet_tx ON transactions(wallet_id, tx_id);
CREATE INDEX idx_transactions_wallet_id ON transactions(wallet_id);
CREATE INDEX idx_transactions_mint_url ON transactions(wallet_id, mint_url);
CREATE INDEX idx_transactions_direction ON transactions(wallet_id, direction);
CREATE INDEX idx_transactions_timestamp ON transactions(wallet_id, timestamp DESC);
CREATE INDEX idx_transactions_tx_id ON transactions(tx_id);

COMMENT ON TABLE transactions IS 'Stores transaction history. transaction_encrypted contains full transaction data encrypted with wallet-specific key.';

-- Keyset counters table - for deterministic secret generation
CREATE TABLE IF NOT EXISTS keyset_counters (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16),
    keyset_id BYTEA NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_keyset_counters_wallet_keyset ON keyset_counters(wallet_id, keyset_id);
CREATE INDEX idx_keyset_counters_wallet_id ON keyset_counters(wallet_id);

-- User-Wallet Mapping Table
-- Maps user IDs to wallet IDs with encrypted user ID storage
-- This prevents tampering with user-wallet relationships outside the enclave
CREATE TABLE IF NOT EXISTS user_wallets (
    id BIGSERIAL PRIMARY KEY,
    -- Encrypted user ID
    -- Encrypted with wallet-specific key to prevent tampering
    user_id_encrypted BYTEA NOT NULL,
    -- Wallet ID (plaintext for indexing and efficient lookups)
    wallet_id BYTEA NOT NULL CHECK (length(wallet_id) = 16),
    -- Creation timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_user_wallets_user_wallet ON user_wallets(user_id_encrypted, wallet_id);
CREATE INDEX idx_user_wallets_user_id ON user_wallets(user_id_encrypted);
CREATE INDEX idx_user_wallets_wallet_id ON user_wallets(wallet_id);

COMMENT ON TABLE user_wallets IS 'Maps user IDs to wallet IDs. user_id_encrypted is encrypted with wallet encryption key to prevent tampering outside the enclave.';
COMMENT ON COLUMN user_wallets.user_id_encrypted IS 'User ID encrypted with wallet encryption key. Only the enclave can decrypt and verify user identity.';
COMMENT ON COLUMN user_wallets.wallet_id IS 'Wallet ID in plaintext for efficient indexing. SHA-128 hash derived from seed, not sensitive.';
