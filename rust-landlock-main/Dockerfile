# Stage 1: Build the Rust binary
FROM rust:1.76 AS builder

WORKDIR /app
COPY . .

# Optional: install build dependencies (if needed)
RUN apt-get update && apt-get install -y pkg-config libssl-dev

RUN cargo build --release

# Stage 2: Minimal runtime image
FROM debian:bullseye-slim

COPY --from=builder /app/target/release/supernanny_sandboxer /usr/local/bin/supernanny_sandboxer

WORKDIR /usr/local/bin

ENTRYPOINT ["./supernanny_sandboxer"]
