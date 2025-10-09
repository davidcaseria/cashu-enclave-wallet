use crate::client::CashuClient;
use crate::credentials::Credentials;
use crate::crypto;
use crate::session::WalletSession;
use anyhow::{Context, Result};
use base64::Engine;
use colored::Colorize;

/// Initialize a new wallet with session-based encryption
/// The enclave generates the seed internally for security
pub async fn init(
    client: &mut CashuClient,
    _mnemonic: Option<String>,  // Deprecated: enclave generates seed
    _generate: bool,              // Deprecated: always generates
) -> Result<()> {
    println!("{}", "Initializing new wallet...".cyan());
    println!("{}", "Note: The seed will be generated securely inside the enclave".cyan());

    // Step 1: Get attestation and extract RSA public key
    println!("\n{}", "Fetching attestation...".cyan());
    let attestation = client.get_attestation_simple().await?;

    println!("{}", "Extracting public key...".cyan());
    let public_key = crypto::extract_public_key_from_attestation(&attestation.attestation_document)
        .context("Failed to extract public key from attestation")?;

    // Step 2: Generate AES-256 session key (client-side)
    println!("{}", "Generating session key...".cyan());
    let session_key = crypto::generate_session_key();

    // Step 3: Encrypt session key with RSA public key
    println!("{}", "Encrypting session key...".cyan());
    let encrypted_session_key = crypto::encrypt_with_public_key(&session_key, &public_key)?;

    // Step 4: Load JWT from credentials file
    println!("{}", "Loading authentication credentials...".cyan());
    let credentials = Credentials::load().context(
        "Failed to load credentials. Please authenticate first:\n  ./scripts/keycloak-auth.sh"
    )?;
    let jwt = credentials.get_valid_access_token()?;

    // Step 5: Encrypt JWT with session key
    println!("{}", "Encrypting authentication token...".cyan());
    let encrypted_jwt = crypto::encrypt_string_with_session_key(&session_key, &jwt)?;

    // Step 6: Call InitWallet - enclave generates seed internally
    println!("{}", "Initializing wallet in enclave...".cyan());
    let response = client.init_wallet(encrypted_session_key, encrypted_jwt).await?;

    // Step 7: Decrypt the seed returned by the enclave
    println!("{}", "Decrypting wallet seed...".cyan());
    let encrypted_seed_bytes = base64::engine::general_purpose::STANDARD
        .decode(&response.encrypted_seed)
        .context("Failed to decode encrypted seed")?;
    let seed = crypto::decrypt_with_session_key(&session_key, &encrypted_seed_bytes)?;

    // Step 8: Generate mnemonic from seed for user backup
    let mnemonic = crypto::seed_to_mnemonic(&seed)?;

    // Step 9: Save session to disk
    println!("{}", "Saving session...".cyan());
    let session = WalletSession::new(
        response.wallet_id.clone(),
        response.session_id,
        session_key,
        seed,
    );
    session.save()?;

    // Step 10: Display results
    println!("\n{}", "✓ Wallet initialized successfully!".green().bold());
    println!("{}", format!("Wallet ID: {}", response.wallet_id).green());
    println!("\n{}", "Your recovery phrase (BIP39 mnemonic):".yellow().bold());
    println!("{}", mnemonic.cyan());
    println!(
        "{}",
        "\n⚠️  IMPORTANT: Write down this mnemonic and store it securely!".red().bold()
    );
    println!(
        "{}",
        "This is the ONLY way to recover your wallet if the session expires."
            .red()
            .bold()
    );

    println!("\n{}", "Session Information:".green().bold());
    println!("  Session expires in: {} minutes", session.time_remaining() / 60);
    println!(
        "  Session file: ~/.cashu-enclave-wallet/sessions/{}.json",
        response.wallet_id
    );

    Ok(())
}

/// Helper function to execute a wallet operation with session-based encryption
async fn execute_wallet_operation<T: serde::de::DeserializeOwned>(
    client: &mut CashuClient,
    wallet_id: &str,
    jwt: &str,
    operation: proto::WalletOperationPayload,
) -> Result<T> {
    // Load session from disk
    let session = WalletSession::load(wallet_id)
        .context("Failed to load wallet session. Did you run 'wallet init'?")?;

    // Encrypt JWT with session key
    let encrypted_jwt = crypto::encrypt_string_with_session_key(&session.session_key, jwt)?;

    // Encrypt operation request with session key (protobuf serialization)
    let encrypted_request =
        crypto::encrypt_protobuf_with_session_key(&session.session_key, &operation)?;

    // Call wallet operation
    let response = client
        .wallet_operation(
            wallet_id.to_string(),
            session.session_id.clone(),
            encrypted_jwt,
            encrypted_request,
        )
        .await?;

    // Handle response
    match response.result {
        Some(proto::wallet_operation_response::Result::Success(success)) => {
            // Decrypt response with session key
            let data: T =
                crypto::decrypt_json_with_session_key(&session.session_key, &success.data)?;
            Ok(data)
        }
        Some(proto::wallet_operation_response::Result::Error(error)) => {
            anyhow::bail!("Enclave error: {}", error.message)
        }
        None => {
            anyhow::bail!("No response from enclave")
        }
    }
}

/// Get wallet balance
pub async fn balance(
    client: &mut CashuClient,
    wallet_id: &str,
    jwt: &str,
    mint_url: Option<&str>,
) -> Result<()> {
    println!("{}", "Fetching balance...".cyan());

    let operation = proto::WalletOperationPayload {
        operation: Some(proto::wallet_operation_payload::Operation::GetBalance(
            proto::GetBalanceRequest {
                mint_url: mint_url.map(String::from),
            },
        )),
    };

    let data: serde_json::Value =
        execute_wallet_operation(client, wallet_id, jwt, operation).await?;

    println!("\n{}", "Balance:".green().bold());
    println!("{}", serde_json::to_string_pretty(&data)?);

    Ok(())
}

/// Send tokens
pub async fn send(
    client: &mut CashuClient,
    wallet_id: &str,
    jwt: &str,
    amount: u64,
    mint_url: &str,
) -> Result<()> {
    println!("{}", format!("Sending {} sats...", amount).cyan());

    let operation = proto::WalletOperationPayload {
        operation: Some(proto::wallet_operation_payload::Operation::Send(
            proto::SendRequest {
                amount,
                mint_url: Some(mint_url.to_string()),
            },
        )),
    };

    let data: serde_json::Value =
        execute_wallet_operation(client, wallet_id, jwt, operation).await?;

    println!("\n{}", "✓ Token created successfully!".green().bold());
    println!("{}", serde_json::to_string_pretty(&data)?);

    Ok(())
}

/// Receive tokens
pub async fn receive(
    client: &mut CashuClient,
    wallet_id: &str,
    jwt: &str,
    token: &str,
) -> Result<()> {
    println!("{}", "Receiving token...".cyan());

    let operation = proto::WalletOperationPayload {
        operation: Some(proto::wallet_operation_payload::Operation::Receive(
            proto::ReceiveRequest {
                token: token.to_string(),
            },
        )),
    };

    let data: serde_json::Value =
        execute_wallet_operation(client, wallet_id, jwt, operation).await?;

    println!("\n{}", "✓ Token received successfully!".green().bold());
    println!("{}", serde_json::to_string_pretty(&data)?);

    Ok(())
}

/// Create mint quote
pub async fn mint_quote(
    client: &mut CashuClient,
    wallet_id: &str,
    jwt: &str,
    amount: u64,
    mint_url: &str,
) -> Result<()> {
    println!("{}", "Creating mint quote...".cyan());

    let operation = proto::WalletOperationPayload {
        operation: Some(proto::wallet_operation_payload::Operation::MintQuote(
            proto::MintQuoteRequest {
                amount,
                mint_url: mint_url.to_string(),
            },
        )),
    };

    let data: serde_json::Value =
        execute_wallet_operation(client, wallet_id, jwt, operation).await?;

    println!("\n{}", "✓ Mint quote created!".green().bold());
    println!("{}", serde_json::to_string_pretty(&data)?);

    Ok(())
}

/// Add mint to wallet
pub async fn add_mint(
    client: &mut CashuClient,
    wallet_id: &str,
    jwt: &str,
    mint_url: &str,
) -> Result<()> {
    println!("{}", format!("Adding mint {}...", mint_url).cyan());

    let operation = proto::WalletOperationPayload {
        operation: Some(proto::wallet_operation_payload::Operation::AddMint(
            proto::AddMintRequest {
                mint_url: mint_url.to_string(),
            },
        )),
    };

    let data: serde_json::Value =
        execute_wallet_operation(client, wallet_id, jwt, operation).await?;

    println!("\n{}", "✓ Mint added successfully!".green().bold());
    println!("{}", serde_json::to_string_pretty(&data)?);

    Ok(())
}

/// List mints in wallet
pub async fn list_mints(client: &mut CashuClient, wallet_id: &str, jwt: &str) -> Result<()> {
    println!("{}", "Fetching mints...".cyan());

    let operation = proto::WalletOperationPayload {
        operation: Some(proto::wallet_operation_payload::Operation::ListMints(
            proto::ListMintsRequest {},
        )),
    };

    let data: serde_json::Value =
        execute_wallet_operation(client, wallet_id, jwt, operation).await?;

    println!("\n{}", "Mints:".green().bold());
    println!("{}", serde_json::to_string_pretty(&data)?);

    Ok(())
}

/// Get transaction history
pub async fn transactions(
    client: &mut CashuClient,
    wallet_id: &str,
    jwt: &str,
    mint_url: Option<&str>,
) -> Result<()> {
    println!("{}", "Fetching transactions...".cyan());

    let operation = proto::WalletOperationPayload {
        operation: Some(proto::wallet_operation_payload::Operation::GetTransactions(
            proto::GetTransactionsRequest {
                mint_url: mint_url.map(String::from),
            },
        )),
    };

    let data: serde_json::Value =
        execute_wallet_operation(client, wallet_id, jwt, operation).await?;

    println!("\n{}", "Transactions:".green().bold());
    println!("{}", serde_json::to_string_pretty(&data)?);

    Ok(())
}

/// Create melt quote (for paying Lightning invoice)
pub async fn melt_quote(
    client: &mut CashuClient,
    wallet_id: &str,
    jwt: &str,
    bolt11: &str,
    mint_url: &str,
) -> Result<()> {
    println!("{}", "Creating melt quote...".cyan());

    let operation = proto::WalletOperationPayload {
        operation: Some(proto::wallet_operation_payload::Operation::MeltQuote(
            proto::MeltQuoteRequest {
                bolt11: bolt11.to_string(),
                mint_url: mint_url.to_string(),
            },
        )),
    };

    let data: serde_json::Value =
        execute_wallet_operation(client, wallet_id, jwt, operation).await?;

    println!("\n{}", "✓ Melt quote created!".green().bold());
    println!("{}", serde_json::to_string_pretty(&data)?);

    Ok(())
}

/// Melt tokens (pay Lightning invoice)
pub async fn melt(
    client: &mut CashuClient,
    wallet_id: &str,
    jwt: &str,
    quote_id: &str,
    mint_url: &str,
) -> Result<()> {
    println!("{}", "Melting tokens (paying invoice)...".cyan());

    let operation = proto::WalletOperationPayload {
        operation: Some(proto::wallet_operation_payload::Operation::Melt(
            proto::MeltRequest {
                quote_id: quote_id.to_string(),
                mint_url: mint_url.to_string(),
            },
        )),
    };

    let data: serde_json::Value =
        execute_wallet_operation(client, wallet_id, jwt, operation).await?;

    println!("\n{}", "✓ Invoice paid successfully!".green().bold());
    println!("{}", serde_json::to_string_pretty(&data)?);

    Ok(())
}
