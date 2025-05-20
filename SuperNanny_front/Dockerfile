# ──────────────────────────────────────────────────────────────
# Stage 1: Build Yew frontend with Trunk
# ──────────────────────────────────────────────────────────────
FROM rust:latest AS yew_builder

WORKDIR /app

# Copy only the frontend directory
COPY ./frontend ./frontend

# Install Trunk and WebAssembly target
RUN cargo install --locked trunk \
 && rustup target add wasm32-unknown-unknown \
 && cd frontend \
 && trunk build --release

# ──────────────────────────────────────────────────────────────
# Stage 2: Build the static_server Rust backend
# ──────────────────────────────────────────────────────────────
FROM rust:latest AS server_builder

WORKDIR /app

# Copy only the static_server crate
COPY ./static_server ./static_server

# Install system dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev clang build-essential

# Build the static_server binary
RUN cd static_server && cargo build --release --verbose

# ──────────────────────────────────────────────────────────────
# Stage 3: Runtime image
# ──────────────────────────────────────────────────────────────
FROM debian:bullseye-slim

# Copy compiled frontend files
COPY --from=yew_builder /app/frontend/dist /var/www

# Copy compiled Rust binary
COPY --from=server_builder /app/static_server/target/release/static_server /usr/local/bin/static_server

WORKDIR /usr/local/bin

# Tell the server where to find static files
ENV STATIC_DIR=/var/www

ENTRYPOINT ["./static_server"]
