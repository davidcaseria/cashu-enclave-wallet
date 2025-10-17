# Dockerfile for Proxy using cargo-chef for optimized builds

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
RUN cargo chef prepare --recipe-path recipe.json --bin proxy

FROM chef AS builder
# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy recipe and build dependencies
COPY --from=planner /app/recipe.json recipe.json

# Accept build arguments for feature flags
ARG BUILD_FEATURES=""
RUN cargo chef cook --release --recipe-path recipe.json ${BUILD_FEATURES}

# Copy source and build application
COPY Cargo.toml Cargo.lock ./
COPY proxy ./proxy
COPY proto ./proto
RUN cargo build --release --bin proxy ${BUILD_FEATURES}

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /app/target/release/proxy /usr/local/bin/proxy

# Set environment
ENV RUST_LOG=info
ENV LISTEN_ADDR=0.0.0.0:50051
ENV MODE=nitro
ENV ENCLAVE_CID=16

# Expose gRPC port
EXPOSE 50051

# Run the proxy
CMD ["/usr/local/bin/proxy"]
