/// Generated gRPC code from protobuf definitions
pub mod enclave {
    tonic::include_proto!("enclave");
}

// Re-export for convenience
pub use enclave::*;

/// File descriptor set for gRPC reflection
pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("enclave_descriptor");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proto_types_exist() {
        // Ensure proto types are generated and available
        let _req = AttestationRequest {};
        let _resp = AttestationResponse {
            attestation_document: String::new(),
        };
    }
}
