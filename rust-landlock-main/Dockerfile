# Stage 1: Build the Rust binary
FROM rust:1.76 AS builder
WORKDIR /app

# Install build dependencies first
RUN apt-get update && apt-get install -y pkg-config libssl-dev

# Copy the entire project
COPY . .

# Debug: List directory contents and show Cargo.toml
RUN echo "=== LISTING DIRECTORY CONTENTS ===" && \
    ls -la && \
    echo "=== CHECKING FOR SRC DIRECTORY ===" && \
    if [ -d "src" ]; then ls -la src/; else echo "src directory NOT FOUND"; fi && \
    echo "=== CHECKING CARGO.TOML ===" && \
    if [ -f "Cargo.toml" ]; then cat Cargo.toml; else echo "Cargo.toml NOT FOUND"; fi

# Try to build with additional debug output
RUN RUST_BACKTRACE=1 cargo build --release --verbose || \
    (echo "=== BUILD FAILED, CHECKING PROJECT STRUCTURE ===" && \
     find . -type f -name "*.rs" | sort && \
     echo "=== CHECKING CARGO VERSION ===" && \
     cargo --version && \
     echo "=== TRYING ALTERNATIVE BUILD APPROACH ===" && \
     # Try alternative build if regular build fails
     if [ -f "Cargo.toml" ]; then \
       echo "Trying cargo build with minimal features" && \
       cargo build --release --no-default-features || \
       (echo "Build still failed. Exiting with error code."; exit 1); \
     else \
       echo "No Cargo.toml found. Cannot build."; \
       exit 1; \
     fi)

# Stage 2: Minimal runtime image
FROM debian:bullseye-slim

# Install SSL certificates and any runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates libssl1.1 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/supernanny_sandboxer /usr/local/bin/supernanny_sandboxer
WORKDIR /usr/local/bin

ENTRYPOINT ["./supernanny_sandboxer"]
