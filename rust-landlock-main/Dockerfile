# Stage 1: Build the binary
FROM rust:latest AS builder

WORKDIR /app
COPY . .

# Install common dependencies for building crates like openssl, ring, etc.
RUN apt-get update && apt-get install -y pkg-config libssl-dev clang build-essential strace

# Build the release binary with logs
RUN cargo build --release --verbose

# Stage 2: Create minimal runtime image
FROM debian:bullseye-slim

COPY --from=builder /app/target/release/supernanny_sandboxer /usr/local/bin/supernanny_sandboxer

WORKDIR /usr/local/bin

ENTRYPOINT ["./supernanny_sandboxer"]
