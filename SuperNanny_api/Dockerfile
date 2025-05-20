# Stage 1: Build the binary
FROM rust:latest AS builder

WORKDIR /app
COPY . .

# Install common native build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev clang build-essential

RUN cargo build --release --bin SuperNanny_api --verbose

# Stage 2: Runtime image
FROM debian:bullseye-slim

COPY --from=builder /app/target/release/SuperNanny_api /usr/local/bin/supernanny_admin_api

WORKDIR /usr/local/bin

# Optionally copy .env if it will be static (not mounted)
# COPY .env /usr/local/bin/.env

ENTRYPOINT ["./supernanny_admin_api"]
