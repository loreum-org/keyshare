# keyshare-mcp image for Railway (Phase 0, testnet).
# Rust 1.90 matches rust-version in the workspace Cargo.toml.
# A Dockerfile at the repo root is what Railway builds. It does not use Nixpacks.

FROM rust:1.90.0-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked --bin keyshare-mcp

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 keyshare \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin keyshare \
    && mkdir -p /data /etc/keyshare \
    && chown keyshare:keyshare /data

COPY --from=build /src/target/release/keyshare-mcp /usr/local/bin/keyshare-mcp
COPY keyshare.railway.example.toml /etc/keyshare/keyshare.toml

USER keyshare

EXPOSE 8080

CMD ["keyshare-mcp", "serve", "/etc/keyshare/keyshare.toml"]
