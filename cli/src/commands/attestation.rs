use crate::client::CashuClient;
use anyhow::Result;
use colored::Colorize;

pub async fn run(client: &mut CashuClient, nonce_hex: Option<String>) -> Result<()> {
    println!("{}", "Fetching attestation document...".cyan());

    // Parse nonce if provided
    let nonce = if let Some(hex) = nonce_hex {
        let bytes = hex::decode(&hex)?;
        println!("Using nonce: {}", hex);
        Some(bytes)
    } else {
        None
    };

    let response = client.get_attestation(nonce).await?;

    println!("\n{}", "Attestation Document:".green().bold());
    println!("{}", response.attestation_document);

    if !response.user_data.is_empty() {
        println!("\n{}", "User Data:".green().bold());
        println!("{}", response.user_data);
    }

    println!(
        "\n{}",
        "✓ Attestation document retrieved successfully".green()
    );
    println!(
        "{}",
        "Use this to encrypt your seed before sending to the enclave".yellow()
    );

    Ok(())
}
