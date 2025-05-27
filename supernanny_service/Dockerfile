# Stage 1: Build the binary
FROM rust:latest AS builder

WORKDIR /app
COPY . .

# Install common native build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev clang build-essential

RUN cargo build --release --verbose

# Stage 2: Minimal runtime image
FROM debian:testing-slim

COPY --from=builder /app/target/release/supernanny_service /usr/local/bin/supernanny_axiom

WORKDIR /usr/local/bin

# Optional: copy .env here if static
# COPY .env /usr/local/bin/.env

ENTRYPOINT ["/bin/bash"]
#ENTRYPOINT ["./supernanny_axiom"]
