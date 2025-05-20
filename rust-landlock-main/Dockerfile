# Stage 1: Build the Rust binary
FROM rust:1.76 AS builder
WORKDIR /app

# First, copy just the Cargo.toml and Cargo.lock (if it exists)
# This allows better use of Docker's layer caching
COPY Cargo.toml ./
# Copy Cargo.lock if it exists
COPY Cargo.lock* ./

# Create dummy source file to build dependencies
RUN mkdir -p src && \
    echo "fn main() {println!(\"dummy\")}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Now copy the actual source code
COPY src/ ./src/
COPY build.rs* ./

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev

# Debug: List contents to verify files are where we expect
RUN ls -la && ls -la src/

# Build the application
RUN cargo build --release --verbose

# Stage 2: Minimal runtime image
FROM debian:bullseye-slim

# Install SSL certificates and any runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates libssl1.1 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/supernanny_sandboxer /usr/local/bin/supernanny_sandboxer
WORKDIR /usr/local/bin

ENTRYPOINT ["./supernanny_sandboxer"]
