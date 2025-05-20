# Stage 1: Build the Rust binary
FROM rust:1.76 AS builder
WORKDIR /app

# Install build dependencies first
RUN apt-get update && apt-get install -y pkg-config libssl-dev

# Copy the entire project
COPY . .

# Debug: List contents to verify files are where we expect
RUN ls -la && \
    if [ -d "src" ]; then ls -la src/; fi && \
    if [ -f "Cargo.toml" ]; then cat Cargo.toml; fi

# Build the application
RUN cargo build --release --verbose

# Stage 2: Minimal runtime image
FROM debian:bullseye-slim

# Install SSL certificates and any runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates libssl1.1 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/supernanny_sandboxer /usr/local/bin/supernanny_sandboxer
WORKDIR /usr/local/bin

ENTRYPOINT ["./supernanny_sandboxer"]
