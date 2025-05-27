# Stage 1: Build the static binary with musl
FROM rust:latest AS builder

WORKDIR /app
COPY . .

RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools

RUN cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Minimal runtime image with musl static binary
FROM alpine:latest

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/supernanny_service /usr/local/bin/supernanny_axiom

WORKDIR /usr/local/bin

ENTRYPOINT ["/usr/local/bin/supernanny_axiom"]
