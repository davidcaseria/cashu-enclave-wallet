# Cashu Enclave Wallet

A secure Cashu wallet implementation running in AWS Nitro Enclaves with end-to-end encryption, ensuring that wallet seeds and proofs are never exposed outside the enclave.

## Architecture Overview

This project implements a **zero-knowledge architecture** where the parent EC2 instance acts as an untrusted intermediary, forwarding encrypted data between users and the enclave. All sensitive cryptographic operations occur exclusively within the isolated Nitro Enclave environment.

### Components

1. **`wallet`** - Rust application running inside AWS Nitro Enclave
   - CDK MultiMintWallet for multi-mint Cashu operations
   - Field-level encrypted PostgreSQL database
   - Attestation service with RSA key pair generation
   - Multi-user wallet management with BIP39/BIP32 derivation
   - JWT-based authentication
   - Vsock server for parent communication

2. **`proxy`** - Rust application running on parent EC2 instance
   - gRPC server (forwards encrypted payloads only)
   - Vsock client for enclave communication
   - PostgreSQL connection management
   - gRPC reflection and health checking
   - **NO access to plaintext seeds, JWTs, or proofs**

3. **`proto`** - Shared protocol buffer definitions
   - gRPC service definitions
   - Type-safe API contracts
   - Client/server code generation

4. **`cli`** - Command-line interface tool
   - User-friendly wallet operations
   - Client-side RSA encryption
   - JWT generation and management
   - Mnemonic generation and handling

### Security Model

#### Zero-Knowledge Design

The parent instance **never sees**:
- User wallet seeds (12-word mnemonics)
- JWT authentication tokens
- Cashu proof secrets or private keys
- Database encryption keys
- Any decrypted wallet data

#### Encryption Flow

```
User (Client-Side)
  ↓ [1. Request attestation]
Parent Proxy
  ↓ [2. Forward request via vsock]
Enclave
  ↓ [3. Generate RSA keypair + NSM attestation]
  ↓ [4. Return attestation document with public key]
Parent Proxy
  ↓ [5. Forward attestation to user]
User
  ↓ [6. Encrypt seed with enclave public key]
  ↓ [7. Send encrypted seed to parent]
Parent Proxy
  ↓ [8. Forward encrypted blob via vsock]
Enclave
  ↓ [9. Decrypt seed with private key]
  ↓ [10. Derive wallet_id, encryption keys]
  ↓ [11. Never expose seed again]
```

## Key Features

### 1. Attestation-Based Encryption

- Enclave generates ephemeral RSA keypair on boot
- NSM (Nitro Security Module) signs attestation document containing public key
- Users verify attestation and encrypt sensitive data client-side
- Only the enclave's private key (never leaves enclave) can decrypt

### 2. Multi-User Access Control

Multiple users can securely share access to a single wallet:

- **Wallet ID**: `SHA256(seed)` - one-way hash for routing
- **DB Encryption Key**: `HKDF-SHA256(seed, "db-encryption-v1")`
- **Master Key**: BIP32 extended private key from seed
- **User Authentication**: JWT tokens with `sub` (user ID) claim
- **User-Wallet Mapping**: Encrypted user IDs stored in database, preventing tampering outside enclave

**Security Features:**
- User IDs encrypted with wallet-specific key before storage
- Parent proxy cannot read or modify user-wallet relationships
- Each operation requires valid JWT with user ID and database verification
- Users can be added/removed from wallets programmatically

### 3. Field-Level Database Encryption

All sensitive fields encrypted with AES-256-GCM:
- Proofs (amount, secret, C, witness, DLEQ)
- Private keys from mint/melt quotes
- Transaction metadata
- Mint information

Plaintext indexing fields for efficient queries:
- `wallet_id`, `mint_url`, `keyset_id`
- `state`, `unit`, `timestamp`

### 4. JWT Authentication with User Claims

- JWT tokens use standard `sub` (subject) claim for user ID
- Tokens encrypted with enclave public key in transit
- Validated inside enclave using wallet-derived HMAC secret
- User ownership verified against encrypted database mapping
- Parent proxy cannot read, forge, or tamper with tokens

## Getting Started

### Quick Start with Docker Compose

```bash
# Start all services
docker compose up --build

# In another terminal, use the CLI
cargo run --package cli -- attestation
cargo run --package cli -- wallet init --generate
```

### CLI Usage

```bash
# Get attestation
cargo run --package cli -- attestation

# Initialize wallet (generates mnemonic)
cargo run --package cli -- wallet init --generate

# Get balance
cargo run --package cli -- wallet balance --wallet-id <ID> --jwt <TOKEN>

# Send tokens
cargo run --package cli -- wallet send --wallet-id <ID> --jwt <TOKEN> --mint-url <URL> <AMOUNT>

# Receive tokens
cargo run --package cli -- wallet receive --wallet-id <ID> --jwt <TOKEN> <CASHU_TOKEN>
```

See [GRPC_MIGRATION.md](./GRPC_MIGRATION.md) for complete CLI documentation.

## API

The proxy exposes a **gRPC API** on port 50051. See [proto/proto/enclave.proto](./proto/proto/enclave.proto) for protocol definitions.

**Main Operations:**
- `GetAttestation()` - Get enclave public key + attestation
- `InitWallet(encrypted_seed)` - Initialize new wallet
- `WalletOperation(...)` - Execute wallet operations (balance, send, receive, mint, melt, etc.)
- Multi-user: `AddUser()`, `RemoveUser()`, `ListUsers()`

For complete API documentation, see [GRPC_MIGRATION.md](./GRPC_MIGRATION.md).

## Database Schema

PostgreSQL with field-level encryption. All tables use `wallet_id` for multi-wallet isolation.

**Key tables:**
- `proofs` - Encrypted proof secrets with plaintext indexes (state, mint_url, keyset_id)
- `wallets` - Mint URLs (plaintext) + encrypted mint info
- `user_wallets` - Encrypted user IDs for multi-user access control
- `mint_quotes`, `melt_quotes` - Encrypted quote data
- `transactions` - Encrypted transaction history

Migrations in `migrations/001_initial_schema.sql` auto-apply via Docker Compose.

## Production Deployment (AWS Nitro)

### Prerequisites

- AWS EC2 instance with Nitro Enclave support
- PostgreSQL database
- Docker and `nitro-cli`

### Build & Deploy

```bash
# 1. Build enclave Docker image
docker build -t cashu-wallet -f wallet/Dockerfile .

# 2. Convert to Nitro Enclave Image Format (EIF)
nitro-cli build-enclave \
  --docker-uri cashu-wallet:latest \
  --output-file wallet.eif

# 3. Start enclave
nitro-cli run-enclave \
  --eif-path wallet.eif \
  --cpu-count 2 \
  --memory 2048 \
  --enclave-cid 16

# 4. Run proxy on parent instance
export MODE=nitro
export ENCLAVE_CID=16
export DATABASE_URL="postgresql://user:pass@localhost:5432/cashu_enclave"
cargo run --release --package proxy
```

### Environment Variables

- **Wallet**: `DATABASE_URL`, `RUST_LOG`
- **Proxy**: `MODE` (nitro/local), `ENCLAVE_CID`, `LISTEN_ADDR`, `SOCKET_PATH` (local mode)
- **CLI**: `CASHU_GRPC_ADDR`, `CASHU_JWT`

## Using gRPC Directly

For programmatic access from other languages, use the gRPC API:

```rust
use proto::enclave_service_client::EnclaveServiceClient;

let mut client = EnclaveServiceClient::connect("http://localhost:50051").await?;
let response = client.get_attestation(AttestationRequest {}).await?;

// See cli/src/crypto.rs for client-side RSA encryption implementation
```

Generate clients from `proto/proto/enclave.proto` in any language (Python, Go, JavaScript, etc.).

## Security Guarantees

### What is Protected

✅ **Wallet seeds** - Never leave enclave in plaintext
✅ **Proof secrets** - Encrypted at rest, decrypted only in enclave
✅ **Private keys** - Generated and stored only in enclave
✅ **JWT tokens** - Encrypted before transmission, validated in enclave
✅ **Database encryption keys** - Derived from seed, never exported
✅ **User IDs** - Encrypted with wallet key before database storage
✅ **User-wallet relationships** - Cannot be tampered with outside enclave

### What is Visible to Parent

❌ Wallet IDs (SHA256 hashes of seeds)
❌ Encrypted blobs (ciphertext only)
❌ Mint URLs (public information)
❌ Transaction counts and timestamps
❌ Proof states (spent/unspent)

### Threat Model

**Protected Against:**
- Compromised parent instance (cannot access seeds/proofs/user mappings)
- Database compromise (all sensitive data encrypted including user IDs)
- Network eavesdropping (end-to-end encryption)
- Malicious parent operator (cannot forge JWTs, decrypt data, or modify user-wallet relationships)
- Unauthorized wallet access (JWT validation + database user verification)

**Not Protected Against:**
- Compromised enclave image (verify attestation PCRs)
- Side-channel attacks on enclave (AWS Nitro hardware protection)
- User's client-side compromise (secure your private keys)

## Development

### Quick Start (Docker Compose)

```bash
# Start all services (postgres, wallet, proxy)
docker compose up --build

# Stop services
docker compose down
```

### Local Development

```bash
# Build workspace
cargo build

# Run tests
cargo test

# Run clippy
cargo clippy --all-targets --all-features

# Run wallet (local mode with Unix socket)
MODE=local DATABASE_URL="postgresql://cashu:cashu@localhost:5432/cashu_enclave" \
  cargo run --bin wallet

# Run proxy (local mode)
MODE=local cargo run --bin proxy
```

### Database Setup

```bash
# Migrations auto-apply via docker-compose
# Or manually:
psql $DATABASE_URL < migrations/001_initial_schema.sql
```

## Contributing

Contributions are welcome! Please ensure:
- All sensitive operations remain in enclave
- No plaintext secrets in parent code
- Database fields encrypted where appropriate
- Tests for cryptographic operations

## License

MIT License - see LICENSE file

## Acknowledgments

- [Cashu Development Kit (CDK)](https://github.com/cashubtc/cdk) - Cashu protocol implementation
- [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) - Trusted execution environment
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic code for generating deterministic keys
