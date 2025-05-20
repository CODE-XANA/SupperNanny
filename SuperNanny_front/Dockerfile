# ──────────────────────────────────────────────────────────────
# Stage 1: Build Yew frontend with Trunk
# ──────────────────────────────────────────────────────────────
FROM rust:latest AS yew_builder

WORKDIR /app

# Correct path to frontend
COPY ./SuperNanny_front/frontend ./frontend

RUN cargo install --locked trunk \
 && rustup target add wasm32-unknown-unknown \
 && cd frontend \
 && trunk build --release

# ──────────────────────────────────────────────────────────────
# Stage 2: Build the static_server Rust backend
# ──────────────────────────────────────────────────────────────
FROM rust:latest AS server_builder

WORKDIR /app

# Correct path to static_server
COPY ./SuperNanny_front/static_server ./static_server

RUN apt-get update && apt-get install -y pkg-config libssl-dev clang build-essential

RUN cd static_server && cargo build --release --verbose

# ──────────────────────────────────────────────────────────────
# Stage 3: Runtime image
# ──────────────────────────────────────────────────────────────
FROM debian:bullseye-slim

COPY --from=yew_builder /app/frontend/dist /var/www
COPY --from=server_builder /app/static_server/target/release/static_server /usr/local/bin/static_server

WORKDIR /usr/local/bin
ENV STATIC_DIR=/var/www

ENTRYPOINT ["./static_server"]
