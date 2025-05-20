# Stage 1: Build Yew frontend with Trunk
FROM rust:latest AS yew_builder

WORKDIR /frontend
COPY ../frontend .

# Install trunk and wasm target
RUN cargo install --locked trunk && \
    rustup target add wasm32-unknown-unknown && \
    trunk build --release

# Stage 2: Build static_server binary
FROM rust:latest AS server_builder

WORKDIR /static_server
COPY . .

# Install dependencies required for building
RUN apt-get update && apt-get install -y pkg-config libssl-dev clang build-essential

RUN cargo build --release --verbose

# Stage 3: Final runtime image
FROM debian:bullseye-slim

# Copy the compiled static files
COPY --from=yew_builder /frontend/dist /var/www

# Copy the static_server binary
COPY --from=server_builder /static_server/target/release/static_server /usr/local/bin/static_server

WORKDIR /usr/local/bin

ENV STATIC_DIR=/var/www

ENTRYPOINT ["./static_server"]
