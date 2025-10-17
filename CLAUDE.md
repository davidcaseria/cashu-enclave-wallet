# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

**IMPORTANT: Always use Docker for building and running the application.**

### Docker Compose (Recommended for Local Development)
```bash
# Start all services (postgres, wallet, proxy)
docker compose up --build

# Stop services
docker compose down

# View logs
docker logs cashu-enclave-wallet-wallet-1
docker logs cashu-enclave-wallet-proxy-1
```

### Manual Docker Build
```bash
# Build wallet enclave image
docker build -t cashu-wallet -f wallet/Dockerfile .

# Build proxy image
docker build -t cashu-proxy -f proxy/Dockerfile .

# Run wallet (local mode)
docker run -e DATABASE_URL="postgresql://cashu:cashu@postgres:5432/cashu_enclave" \
  -e SOCKET_PATH=/tmp/enclave.sock \
  cashu-wallet

# Run proxy (local mode)
docker run -p 50051:50051 \
  -e LISTEN_ADDR=0.0.0.0:50051 \
  -e MODE=local \
  -e SOCKET_PATH=/tmp/enclave.sock \
  cashu-proxy
```

### Local Development (Cargo)
```bash
# Build all workspace members
cargo build

# Build wallet with local-dev features
cargo build --package wallet --features local-dev --no-default-features

# Run wallet (local mode)
MODE=local DATABASE_URL="postgresql://cashu:cashu@localhost:5432/cashu_enclave" \
  cargo run --bin wallet

# Run proxy (local mode)
MODE=local cargo run --bin proxy

# Run tests
cargo test --workspace

# Lint
cargo clippy --all-targets --all-features
```

### CLI Testing (Validation)

**Use the CLI for all validation testing.**

```bash
# Build and install CLI
cargo install --path cli

# Get attestation
cashu-enclave-wallet attestation

# Initialize wallet
cashu-enclave-wallet init

# Get balance (auto-detects wallet from session)
cashu-enclave-wallet balance

# Send tokens
cashu-enclave-wallet send <AMOUNT> --mint-url https://testnut.cashu.space

# Receive tokens
cashu-enclave-wallet receive <CASHU_TOKEN>

# Melt (pay Lightning invoice)
cashu-enclave-wallet melt-quote <BOLT11> --mint-url https://testnut.cashu.space
cashu-enclave-wallet melt <QUOTE_ID> --mint-url https://testnut.cashu.space

# Override wallet-id if needed
cashu-enclave-wallet --wallet-id <WALLET_ID> balance
```

### Database Setup
```bash
# Run migrations (auto-applied via docker-compose volumes)
psql $DATABASE_URL < migrations/001_initial_schema.sql

# For SQLx offline compilation (run AFTER any schema changes)
# This generates cached query metadata in .sqlx/ directory
# Required for Docker builds without database connectivity
DATABASE_URL="postgres:///cashu_enclave" cargo sqlx prepare --workspace

# The .sqlx/ directory is committed to git and used during Docker builds
# with SQLX_OFFLINE=true environment variable
```

## Architecture Overview

This is a **zero-knowledge Cashu wallet** running in AWS Nitro Enclaves. The parent EC2 instance acts as an **untrusted proxy** and never sees plaintext seeds, JWTs, or proof secrets.

### Key Components (Workspace Structure)

**1. `wallet/` - Enclave Application**
- Runs inside AWS Nitro Enclave (or Unix socket in local mode)
- Contains all sensitive cryptographic operations
- **Never exports** wallet seeds, private keys, or JWT secrets
- Implements `WalletManager` for session management
- Uses `EncryptedPostgresDatabase` for field-level encryption
- Feature flags: `nsm` (Nitro) or `local-dev` (Unix socket)

**2. `proxy/` - Parent Application**
- gRPC server on parent EC2 instance
- **Cannot decrypt** any wallet data
- Forwards encrypted payloads via vsock (Nitro) or Unix socket (local)
- Implements `EnclaveClient` trait with `VsockClient` or `UnixClient`
- HTTP CONNECT proxy for HTTPS requests (mints, JWKS, KMS)
- TCP proxy for PostgreSQL database connections (required in Nitro Enclaves)
- Mode controlled by `MODE` env var: `nitro` or `local`

**3. `proto/` - Protocol Buffers**
- Shared gRPC service definitions
- Generated code for client/server communication
- Service: `enclave.EnclaveService`

**4. `cli/` - Command-Line Interface**
- User-facing tool for wallet operations
- Handles RSA encryption client-side
- Generates and manages JWT tokens
- See `cli/src/commands/` for operation implementations

### Communication Flow

```
User/CLI
  ↓ [1. Get attestation with enclave public key]
Proxy (gRPC)
  ↓ [2. Forward via vsock/Unix socket]
Wallet (Enclave)
  ↓ [3. Return RSA public key + NSM attestation]
User/CLI
  ↓ [4. Encrypt seed/JWT with public key]
  ↓ [5. Send encrypted request]
Proxy (gRPC)
  ↓ [6. Forward encrypted blob - cannot decrypt]
Wallet (Enclave)
  ↓ [7. Decrypt, validate JWT, execute operation]
  ↓ [8. Return encrypted response]
```

### Network Proxy Architecture

**AWS Nitro Enclaves have NO direct network access.** All network traffic must be routed through the parent EC2 instance. To preserve end-to-end encryption and zero-knowledge properties, the proxy implements different strategies for different types of network calls:

#### 1. HTTPS Requests to Mints (HTTP CONNECT Proxy)

**Security Requirement:** Proxy MUST NOT see request/response content, only destination hostname.

**Implementation:**
- Proxy runs HTTP CONNECT proxy on port 8888 (`proxy/src/http_proxy/`)
- Enclave configures `HTTP_PROXY` environment variable to `http://proxy:8888`
- TLS handshake happens **inside the enclave**, not in proxy
- Proxy sees only: `CONNECT testnut.cashu.space:443`
- Proxy forwards raw TCP bytes without decryption
- Request path, body, and response remain encrypted end-to-end

**Network Flow:**
```
Wallet (Enclave)
  ↓ [CONNECT mint.example.com:443]
Proxy (HTTP CONNECT on port 8888)
  ↓ [Establish TCP connection]
Mint Server
  ↓ [Proxy tunnels encrypted TLS bytes]
Wallet (Enclave)
```

**Code Locations:**
- Proxy implementation: `proxy/src/http_proxy/server.rs`
- Enclave HTTP client config: `wallet/src/crypto/jwks.rs:56-63`
- CDK automatically uses `HTTP_PROXY` environment variable

#### 2. PostgreSQL Database Connections (TCP Proxy)

**Security:** Field-level encryption protects sensitive data even as it passes through proxy.

**Implementation:**
- Proxy runs TCP proxy on port 5432 (`proxy/src/tcp_proxy/`)
- Enclave connects to `proxy:5432` instead of direct PostgreSQL connection
- Proxy forwards raw TCP bytes to backend PostgreSQL (`wallet-postgres:5432`)
- **AWS Nitro Enclaves cannot access VPC resources directly** - ALL traffic must go through parent
- Database sees only encrypted blobs for sensitive fields
- Plaintext fields are only for indexing (wallet_id, mint_url, state)

**Network Flow:**
```
Wallet (Enclave)
  ↓ [Connect to proxy:5432]
Proxy (TCP Proxy on port 5432)
  ↓ [Forward TCP stream to PostgreSQL]
PostgreSQL Database (VPC Resource)
  ↓ [Receives encrypted data from enclave]
Wallet (Enclave)
```

**Code Locations:**
- Proxy implementation: `proxy/src/tcp_proxy/server.rs`
- Database connection: `wallet/src/main.rs:57-61` (uses `DATABASE_URL` env var)
- Field-level encryption: `wallet/src/database/encrypted_db.rs`

#### 3. JWKS Fetching (HTTP CONNECT Proxy)

**Security:** Use same HTTP CONNECT proxy to prevent tampering.

**Implementation:**
- Same as mint requests
- JWKS URL typically points to Keycloak or other OIDC provider
- Proxy cannot modify public keys (protected by TLS)
- Configured via `HTTP_PROXY` environment variable

#### 4. AWS KMS Requests (HTTP CONNECT Proxy)

**Security:** Attestation document must come from enclave, not proxy.

**Implementation:**
- Same HTTP CONNECT proxy mechanism
- KMS requests contain Nitro attestation document
- KMS verifies enclave identity via attestation
- Proxy cannot see or modify attestation document (TLS encrypted)

**Note:** AWS KMS integration not yet implemented (see `wallet/src/crypto/kms.rs:241-309`)

#### Security Properties Preserved

✅ **Zero-Knowledge:** Proxy never sees plaintext seeds, JWTs, or proofs
✅ **End-to-End TLS:** All HTTPS connections established inside enclave
✅ **Mint Privacy:** Proxy only sees destination hostname, not URL paths or request bodies
✅ **Tampering Protection:** TLS prevents proxy from modifying JWKS or KMS responses
✅ **Database Security:** Field-level encryption protects sensitive data even as it transits through TCP proxy
✅ **PostgreSQL Privacy:** Proxy forwards encrypted blobs without decryption capability

#### Environment Variables

**Wallet (Enclave):**
- `DATABASE_URL` - PostgreSQL connection string pointing to proxy (e.g., `postgresql://cashu:cashu@proxy:5432/wallet_db`)
  - Enclave connects to proxy instead of direct PostgreSQL connection
  - Required for all database operations
- `HTTP_PROXY` - HTTP CONNECT proxy URL (e.g., `http://proxy:8888`)
  - Used by reqwest for all HTTPS requests (JWKS, Mints, KMS)
  - If not set, enclave attempts direct connections (will fail in Nitro)

**Proxy:**
- `HTTP_PROXY_ADDR` - HTTP CONNECT proxy listen address (default: `0.0.0.0:8888`)
  - Runs alongside gRPC server on port 50051
  - Implements RFC 2817 HTTP CONNECT method
- `POSTGRES_PROXY_ADDR` - PostgreSQL TCP proxy listen address (default: `0.0.0.0:5432`)
  - Forwards raw TCP traffic to backend PostgreSQL
  - Runs concurrently with gRPC and HTTP proxy servers
- `POSTGRES_BACKEND_ADDR` - Backend PostgreSQL address (default: `wallet-postgres:5432`)
  - Target PostgreSQL server for TCP proxy forwarding

### Critical Security Invariants

**NEVER violate these rules when modifying code:**

1. **Wallet seeds MUST only be decrypted in `wallet/`** - Never in `proxy/` or anywhere outside the enclave
2. **Seeds are encrypted with KMS before database storage** - Uses AWS KMS (production) or local dev key
3. **Wallets can auto-load from encrypted seeds** - Seeds stored in `seeds` table, decrypted on-demand
4. **JWT secrets are derived from wallet seed** - Uses HKDF in `wallet/src/crypto/seed.rs`
5. **All DB sensitive fields MUST be encrypted** - Via `EncryptedPostgresDatabase` in `wallet/src/database/encrypted_db.rs`
6. **User IDs in database are encrypted** - Prevents tampering by parent/DBA (see `user_wallets` table)
7. **Proxy only handles opaque encrypted blobs** - No plaintext access to seeds, JWTs, or proofs
8. **RSA encryption happens client-side** - Enclave public key from attestation
9. **Wallet IDs use SHA-128** - First 16 bytes of SHA-256 for efficient routing with 128-bit security

### Key Code Locations

**Wallet (Enclave)**
- Session management: `wallet/src/wallet_manager.rs` - `WalletManager` handles user sessions with 1hr timeout, auto-loads from DB
- Seed derivation: `wallet/src/crypto/seed.rs` - Derives `wallet_id` (SHA-128), DB key, JWT secret via HKDF
- KMS integration: `wallet/src/crypto/kms.rs` - Encrypts/decrypts seeds with AWS KMS or local dev key
- JWT validation: `wallet/src/crypto/jwt.rs` - Validates HS256 tokens with wallet-derived secret
- Field encryption: `wallet/src/crypto/encryption.rs` - AES-256-GCM for database fields
- Database: `wallet/src/database/encrypted_db.rs` - Implements CDK `WalletDatabase` trait + seeds table
- Server: `wallet/src/network/` - `VsockServer` (Nitro) or `UnixServer` (local)
- Attestation: `wallet/src/attestation.rs` - RSA keypair + NSM attestation

**Proxy**
- gRPC service: `proxy/src/grpc/service.rs` - Implements `EnclaveService` RPCs
- Enclave clients: `proxy/src/vsock/client.rs` and `proxy/src/unix/client.rs`
- HTTP CONNECT proxy: `proxy/src/http_proxy/server.rs` - HTTPS tunneling for mints/JWKS/KMS
- TCP proxy: `proxy/src/tcp_proxy/server.rs` - PostgreSQL database forwarding
- Main entry: `proxy/src/main.rs` - Mode selection and server startup

**CLI**
- Commands: `cli/src/commands/` - Wallet and user management operations
- Crypto: `cli/src/crypto.rs` - Client-side RSA encryption
- Client: `cli/src/client.rs` - gRPC client wrapper

### Database Schema Notes

All tables use `wallet_id` (16 bytes, SHA-128) for multi-wallet isolation. Key tables:
- `seeds` - **Encrypted seeds** stored with KMS for wallet auto-loading
- `wallets` - Mint URLs (plaintext) and encrypted `MintInfo`
- `proofs` - Encrypted secrets with plaintext indexes (state, mint_url, keyset_id)
- `user_wallets` - **Encrypted** user IDs for multi-user access control
- `mint_quotes`, `melt_quotes` - Encrypted quote data
- `transactions` - Encrypted transaction history

All tables now have sequence-based primary keys (BIGSERIAL) for proper foreign key relationships.
Plaintext fields are only for indexing (wallet_id, mint_url, state, timestamps).

### Multi-User Access Control

The system supports multiple users sharing one wallet:
- **Wallet ID**: `SHA-128(seed)` - First 16 bytes of SHA-256, used as routing identifier
- **User ID**: From JWT `sub` claim - encrypted in `user_wallets` table
- **JWT Secret**: Same for all users of a wallet, derived from seed via HKDF
- User-wallet mappings verified via `JwtValidator::verify_user_owns_wallet()`

### Seed Storage and Auto-Loading

Wallets can be persisted and auto-loaded:
- **Seed Encryption**: Seeds encrypted with AWS KMS (production) or local dev key before storage
- **Storage**: Encrypted seeds stored in `seeds` table with `wallet_id` as key
- **Auto-Loading**: When a wallet operation is requested, WalletManager checks memory first, then loads from database
- **Local Dev Key**: Stored in `~/.cashu-enclave-wallet/dev-master-key` or `DEV_SEED_MASTER_KEY` env var
- **Production KMS**: Uses AWS KMS with Nitro Enclave attestation document for cryptographic verification

### Build Modes

**local-dev mode** (Unix socket):
- No NSM attestation (uses dummy RSA keypair)
- Unix socket at `/tmp/enclave.sock` (or `$SOCKET_PATH`)
- Seeds encrypted with local AES-256-GCM key
- Dev key stored in `~/.cashu-enclave-wallet/dev-master-key` or `DEV_SEED_MASTER_KEY`
- **WARNING**: Local dev key is NOT secure for production use
- For development/testing without AWS Nitro

**nsm mode** (Nitro Enclave):
- Real NSM attestation with signed PCRs
- Vsock communication (CID 16 by default)
- Seeds encrypted with AWS KMS using attestation document
- KMS verifies enclave identity before decrypting
- Production deployment on AWS EC2 Nitro

Modes controlled by Cargo features in `wallet/Cargo.toml`:
- `--features local-dev --no-default-features` for local
- Default features include `nsm` for production

### Common Development Tasks

**Adding a new wallet operation:**
1. Add enum variant to `WalletOperation` in `wallet/src/types.rs`
2. Implement handler in `WalletManager::execute_wallet_operation()` in `wallet/src/wallet_manager.rs`
3. Add gRPC message types to `proto/proto/enclave.proto`
4. Update `EnclaveServiceImpl` in `proxy/src/grpc/service.rs`
5. Add CLI command in `cli/src/commands/`

**Adding encrypted database fields:**
1. Update schema in `migrations/001_initial_schema.sql`
2. Update `EncryptedPostgresDatabase` methods in `wallet/src/database/encrypted_db.rs`
3. Use `self.encrypt()` / `self.decrypt()` for sensitive fields
4. Keep indexing fields (wallet_id, mint_url, etc.) plaintext

**Testing encryption end-to-end:**
1. Use `docker compose up` to start all services
2. Use CLI to initialize wallet: `cashu-enclave-wallet init`
3. Verify wallet seed never appears in proxy logs or database plaintext
4. Check database: `SELECT * FROM proofs` shows encrypted blobs

### Environment Variables Reference

**Wallet (Enclave):**
- `DATABASE_URL` - PostgreSQL connection string
- `JWKS_URL` - JWKS endpoint URL for JWT validation (required)
- `HTTP_PROXY` - HTTP CONNECT proxy URL for HTTPS requests (e.g., `http://proxy:8888`)
- `SOCKET_PATH` - Unix socket path (local mode only)
- `RUST_LOG` - Logging level (default: info)

**Proxy:**
- `LISTEN_ADDR` - gRPC listen address (default: 0.0.0.0:50051)
- `HTTP_PROXY_ADDR` - HTTP CONNECT proxy listen address (default: 0.0.0.0:8888)
- `POSTGRES_PROXY_ADDR` - PostgreSQL TCP proxy listen address (default: 0.0.0.0:5432)
- `POSTGRES_BACKEND_ADDR` - Backend PostgreSQL address (default: wallet-postgres:5432)
- `MODE` - `local` or `nitro` (default: nitro)
- `ENCLAVE_CID` - Vsock CID for Nitro mode (default: 16)
- `SOCKET_PATH` - Unix socket path for local mode
- `RUST_LOG` - Logging level

**CLI:**
- `CASHU_GRPC_ADDR` - gRPC server address (default: http://localhost:50051)
- `CASHU_JWT` - JWT token (alternative to --jwt flag)
