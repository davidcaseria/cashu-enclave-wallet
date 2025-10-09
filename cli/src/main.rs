mod client;
mod commands;
mod credentials;
mod crypto;
mod session;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use client::CashuClient;
use credentials::Credentials;

#[derive(Parser)]
#[command(name = "cashu-enclave-wallet")]
#[command(about = "CLI for Cashu Enclave Wallet", long_about = None)]
#[command(version)]
struct Cli {
    /// gRPC server address
    #[arg(long, env = "CASHU_GRPC_ADDR", default_value = "http://localhost:50051")]
    grpc_addr: String,

    /// JWT token (optional, will use credentials file if not provided)
    #[arg(long, env = "CASHU_JWT", global = true)]
    jwt: Option<String>,

    /// Wallet ID (optional, will auto-detect from most recent session if not provided)
    #[arg(long, global = true)]
    wallet_id: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get attestation document from the enclave
    Attestation {
        /// Optional nonce (hex-encoded)
        #[arg(long)]
        nonce: Option<String>,
    },

    /// Initialize a new wallet with a seed
    Init {
        /// BIP39 mnemonic phrase (12 or 24 words)
        #[arg(long)]
        mnemonic: Option<String>,

        /// Generate a new random mnemonic
        #[arg(long)]
        generate: bool,
    },

    /// Get wallet balance
    Balance {
        /// Mint URL (optional, for specific mint)
        #[arg(long)]
        mint_url: Option<String>,
    },

    /// Send tokens
    Send {
        /// Amount to send
        amount: u64,

        /// Mint URL
        #[arg(long)]
        mint_url: String,
    },

    /// Receive tokens
    Receive {
        /// Cashu token string
        token: String,
    },

    /// Create mint quote
    MintQuote {
        /// Amount
        amount: u64,

        /// Mint URL
        #[arg(long)]
        mint_url: String,
    },

    /// Create melt quote (for paying Lightning invoice)
    MeltQuote {
        /// Lightning invoice (bolt11)
        bolt11: String,

        /// Mint URL
        #[arg(long)]
        mint_url: String,
    },

    /// Melt tokens (pay Lightning invoice)
    Melt {
        /// Quote ID from melt-quote
        quote_id: String,

        /// Mint URL
        #[arg(long)]
        mint_url: String,
    },

    /// Add a new mint to the wallet
    AddMint {
        /// Mint URL to add
        mint_url: String,
    },

    /// List all mints in the wallet
    ListMints,

    /// Get transaction history
    Transactions {
        /// Mint URL (optional, for specific mint)
        #[arg(long)]
        mint_url: Option<String>,
    },
}

// TODO: Uncomment when user management is implemented via WalletOperation
// #[derive(Subcommand)]
// enum UserCommands {
//     /// Add a user to a wallet
//     AddUser {
//         /// Wallet ID (hex)
//         #[arg(long)]
//         wallet_id: String,
//
//         /// User ID
//         #[arg(long)]
//         user_id: String,
//
//         /// JWT secret (for signing JWT)
//         #[arg(long, env = "CASHU_JWT_SECRET")]
//         jwt_secret: String,
//     },
//
//     /// Remove a user from a wallet
//     RemoveUser {
//         /// Wallet ID (hex)
//         #[arg(long)]
//         wallet_id: String,
//
//         /// User ID
//         #[arg(long)]
//         user_id: String,
//
//         /// JWT secret (for signing JWT)
//         #[arg(long, env = "CASHU_JWT_SECRET")]
//         jwt_secret: String,
//     },
//
//     /// List all users for a wallet
//     ListUsers {
//         /// Wallet ID (hex)
//         #[arg(long)]
//         wallet_id: String,
//
//         /// User ID (for authentication)
//         #[arg(long)]
//         user_id: String,
//
//         /// JWT secret (for signing JWT)
//         #[arg(long, env = "CASHU_JWT_SECRET")]
//         jwt_secret: String,
//     },
// }

/// Get JWT token from CLI args or credentials file
fn get_jwt(cli_jwt: Option<String>) -> Result<String> {
    if let Some(jwt) = cli_jwt {
        return Ok(jwt);
    }

    // Try to load from credentials file
    let credentials = Credentials::load()
        .context("No JWT provided and failed to load credentials file. Either:\n  1. Pass --jwt flag\n  2. Set CASHU_JWT environment variable\n  3. Run ./scripts/keycloak-auth.sh to authenticate")?;

    credentials.get_valid_access_token()
}

/// Get wallet ID from CLI args or auto-detect from session
fn get_wallet_id(cli_wallet_id: Option<String>) -> Result<String> {
    if let Some(wallet_id) = cli_wallet_id {
        return Ok(wallet_id);
    }

    // Auto-detect from most recent session
    session::WalletSession::find_active_wallet()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut client = CashuClient::connect(&cli.grpc_addr).await?;

    match cli.command {
        Commands::Attestation { nonce } => {
            commands::attestation::run(&mut client, nonce).await?;
        }
        Commands::Init { mnemonic, generate } => {
            commands::wallet::init(&mut client, mnemonic, generate).await?;
        }
        Commands::Balance { mint_url } => {
            let wallet_id = get_wallet_id(cli.wallet_id)?;
            let jwt = get_jwt(cli.jwt)?;
            commands::wallet::balance(&mut client, &wallet_id, &jwt, mint_url.as_deref()).await?;
        }
        Commands::Send { amount, mint_url } => {
            let wallet_id = get_wallet_id(cli.wallet_id)?;
            let jwt = get_jwt(cli.jwt)?;
            commands::wallet::send(&mut client, &wallet_id, &jwt, amount, &mint_url).await?;
        }
        Commands::Receive { token } => {
            let wallet_id = get_wallet_id(cli.wallet_id)?;
            let jwt = get_jwt(cli.jwt)?;
            commands::wallet::receive(&mut client, &wallet_id, &jwt, &token).await?;
        }
        Commands::MintQuote { amount, mint_url } => {
            let wallet_id = get_wallet_id(cli.wallet_id)?;
            let jwt = get_jwt(cli.jwt)?;
            commands::wallet::mint_quote(&mut client, &wallet_id, &jwt, amount, &mint_url).await?;
        }
        Commands::MeltQuote { bolt11, mint_url } => {
            let wallet_id = get_wallet_id(cli.wallet_id)?;
            let jwt = get_jwt(cli.jwt)?;
            commands::wallet::melt_quote(&mut client, &wallet_id, &jwt, &bolt11, &mint_url).await?;
        }
        Commands::Melt { quote_id, mint_url } => {
            let wallet_id = get_wallet_id(cli.wallet_id)?;
            let jwt = get_jwt(cli.jwt)?;
            commands::wallet::melt(&mut client, &wallet_id, &jwt, &quote_id, &mint_url).await?;
        }
        Commands::AddMint { mint_url } => {
            let wallet_id = get_wallet_id(cli.wallet_id)?;
            let jwt = get_jwt(cli.jwt)?;
            commands::wallet::add_mint(&mut client, &wallet_id, &jwt, &mint_url).await?;
        }
        Commands::ListMints => {
            let wallet_id = get_wallet_id(cli.wallet_id)?;
            let jwt = get_jwt(cli.jwt)?;
            commands::wallet::list_mints(&mut client, &wallet_id, &jwt).await?;
        }
        Commands::Transactions { mint_url } => {
            let wallet_id = get_wallet_id(cli.wallet_id)?;
            let jwt = get_jwt(cli.jwt)?;
            commands::wallet::transactions(&mut client, &wallet_id, &jwt, mint_url.as_deref())
                .await?;
        }
    }

    Ok(())
}
