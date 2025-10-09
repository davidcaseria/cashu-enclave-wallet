use anyhow::Result;
use proto::enclave_service_client::EnclaveServiceClient;
use proto::*;
use tonic::transport::Channel;

/// Wrapper around the gRPC client
pub struct CashuClient {
    client: EnclaveServiceClient<Channel>,
}

impl CashuClient {
    /// Connect to the gRPC server
    pub async fn connect(addr: &str) -> Result<Self> {
        let client = EnclaveServiceClient::connect(addr.to_string()).await?;
        Ok(Self { client })
    }

    /// Get attestation document
    pub async fn get_attestation(&mut self, nonce: Option<Vec<u8>>) -> Result<AttestationResponse> {
        let request = tonic::Request::new(AttestationRequest {
            nonce,
        });
        let response = self.client.get_attestation(request).await?;
        Ok(response.into_inner())
    }

    /// Get attestation document without nonce (convenience method)
    pub async fn get_attestation_simple(&mut self) -> Result<AttestationResponse> {
        self.get_attestation(None).await
    }

    /// Initialize wallet
    /// encrypted_session_key: Base64-encoded session key encrypted with RSA public key
    /// encrypted_jwt: Base64-encoded JWT encrypted with session key (passed in metadata)
    pub async fn init_wallet(
        &mut self,
        encrypted_session_key: String,
        encrypted_jwt: String,
    ) -> Result<InitWalletResponse> {
        let mut request = tonic::Request::new(InitWalletRequest {
            encrypted_session_key,
        });

        // Add encrypted JWT to metadata
        request.metadata_mut().insert(
            "x-encrypted-jwt",
            encrypted_jwt.parse().map_err(|_| anyhow::anyhow!("Invalid metadata value"))?,
        );

        let response = self.client.init_wallet(request).await?;
        Ok(response.into_inner())
    }

    /// Execute wallet operation
    /// session_id: Hex-encoded session ID from InitWallet response
    /// encrypted_jwt: Base64-encoded JWT encrypted with session key (passed in metadata)
    /// encrypted_request: Base64-encoded operation request encrypted with session key
    pub async fn wallet_operation(
        &mut self,
        wallet_id: String,
        session_id: String,
        encrypted_jwt: String,
        encrypted_request: String,
    ) -> Result<WalletOperationResponse> {
        let mut request = tonic::Request::new(WalletOperationRequest {
            wallet_id,
            encrypted_request,
        });

        // Add session ID and encrypted JWT to metadata
        request.metadata_mut().insert(
            "x-session-id",
            session_id.parse().map_err(|_| anyhow::anyhow!("Invalid session ID"))?,
        );
        request.metadata_mut().insert(
            "x-encrypted-jwt",
            encrypted_jwt.parse().map_err(|_| anyhow::anyhow!("Invalid JWT metadata"))?,
        );

        let response = self.client.wallet_operation(request).await?;
        Ok(response.into_inner())
    }
}
