# Dockerfile for Enclave Wallet using cargo-chef for optimized builds

# Build argument for features (default: production build without local-dev)
ARG BUILD_FEATURES=""

FROM lukemathwalker/cargo-chef:0.1.72-rust-1.90.0-slim-bookworm AS chef
WORKDIR /app

FROM chef AS planner
# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY wallet ./wallet
COPY proxy ./proxy
COPY proto ./proto
COPY cli ./cli
# Generate recipe
RUN cargo chef prepare --recipe-path recipe.json --bin wallet

FROM chef AS builder
# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy recipe and build dependencies (feature flags affect dependency resolution)
ARG BUILD_FEATURES
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json ${BUILD_FEATURES}

# Copy source and build application with feature flags
COPY Cargo.toml Cargo.lock ./
COPY wallet ./wallet
COPY proto ./proto
COPY .sqlx ./.sqlx
RUN cargo build --release --bin wallet ${BUILD_FEATURES}

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /app/target/release/wallet /usr/local/bin/wallet

# Set environment
ENV RUST_LOG=info
ENV DATABASE_URL=postgresql://cashu:cashu@postgres:5432/cashu_enclave

# Expose vsock port (note: not a TCP port, just for documentation)
EXPOSE 5000

# Run the enclave wallet
CMD ["/usr/local/bin/wallet"]
