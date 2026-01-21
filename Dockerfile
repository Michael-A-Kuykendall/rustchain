# Multi-stage build for optimal Docker image size
FROM rust:1.70-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy dependency files first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release --bin rustchain && rm -rf src

# Copy actual source code
COPY src ./src
COPY examples ./examples
COPY docs ./docs

# Build the actual application
RUN cargo build --release --bin rustchain

# Runtime stage with minimal image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -r -s /bin/false rustchain

# Copy binary from builder stage
COPY --from=builder /app/target/release/rustchain /usr/local/bin/rustchain

# Copy example configurations
COPY --from=builder /app/examples /opt/rustchain/examples

# Set ownership and permissions
RUN chown root:root /usr/local/bin/rustchain && \
    chmod 755 /usr/local/bin/rustchain

# Create working directory for user
WORKDIR /workspace
RUN chown rustchain:rustchain /workspace

# Switch to non-root user
USER rustchain

# Set environment variables
ENV RUST_LOG=info
ENV RUSTCHAIN_CONFIG_PATH=/workspace/rustchain.toml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD rustchain --version || exit 1

# Default command
CMD ["rustchain", "--help"]

# Labels for metadata
LABEL org.opencontainers.image.title="Rustchain Community Edition" \
      org.opencontainers.image.description="Production-ready AI agent framework built in Rust" \
      org.opencontainers.image.vendor="Rustchain Community" \
      org.opencontainers.image.url="https://rustchain.dev" \
      org.opencontainers.image.documentation="https://docs.rs/rustchain-community" \
      org.opencontainers.image.source="https://github.com/Michael-A-Kuykendall/rustchain-community" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"