//! HTTPS-over-vsock transport for CDK MintConnector
//!
//! This module provides a custom HTTP transport that works in AWS Nitro Enclaves
//! where no TCP/IP stack is available. All network communication must go through
//! vsock to the parent EC2 instance.
//!
//! ## Architecture
//!
//! ```text
//! Enclave (no TCP/IP):
//!   ┌──────────────────────────────────────┐
//!   │ HTTP Client (CDK)                    │
//!   │   ↓                                  │
//!   │ TLS Layer (rustls) - ENCRYPTS HERE   │
//!   │   ↓                                  │
//!   │ Vsock Connection                     │
//!   └──────────────────────────────────────┘
//!             ↓ [encrypted TLS bytes]
//!   ═══════════════════════════════════════
//!             ↓ vsock tunnel
//!   ═══════════════════════════════════════
//! Parent EC2:
//!   ┌──────────────────────────────────────┐
//!   │ Network Proxy Server                 │
//!   │   - Receives vsock connection        │
//!   │   - Reads destination header         │
//!   │   - Forwards encrypted bytes to mint │
//!   │   - CANNOT decrypt (TLS in enclave)  │
//!   └──────────────────────────────────────┘
//! ```
//!
//! ## Security Properties
//!
//! - TLS handshake happens **inside the enclave**
//! - Parent proxy only sees encrypted bytes
//! - End-to-end encryption preserved (enclave ↔ mint)
//! - Parent cannot read request/response content
//! - Parent only knows destination hostname

mod transport;

pub use transport::VsockTransport;
