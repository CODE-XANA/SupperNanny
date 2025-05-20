# Stage 1: Build the binary
FROM rust:1.76 as builder

WORKDIR /app
COPY . .

# Build the Rust binary in release mode
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bullseye-slim

# Copy compiled binary into minimal runtime container
COPY --from=builder /app/target/release/supernanny_sandboxer /usr/local/bin/supernanny_sandboxer

# Working directory is where the binary will run from
WORKDIR /usr/local/bin

# Run the binary by default
ENTRYPOINT ["./supernanny_sandboxer"]
