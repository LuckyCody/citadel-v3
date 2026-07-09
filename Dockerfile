# =============================================================================
# Citadel API Server - Docker Image
#
# Produces a Redis-capable production image (--features redis-backend).
#
# Build:  docker build -t citadel:v3 .
# Run (production single-node):
#   docker run -p 8443:8443 \
#     -e CITADEL_MASTER_KEY=$(openssl rand -hex 32) \
#     -e CITADEL_ENV=production \
#     -e CITADEL_REPLAY_STORE=file \
#     -v citadel_data:/data \
#     citadel:v3
#
# For Redis multi-node replay, set CITADEL_REPLAY_STORE=redis and CITADEL_REDIS_URL.
# See DEPLOYMENT.md for full production setup.
# =============================================================================

# Stage 1: Build
FROM rust:1.81-bookworm AS builder

WORKDIR /build

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY citadel-envelope/Cargo.toml citadel-envelope/Cargo.toml
COPY citadel-keystore/Cargo.toml citadel-keystore/Cargo.toml
COPY citadel-api/Cargo.toml citadel-api/Cargo.toml
COPY citadel-cli/Cargo.toml citadel-cli/Cargo.toml

# Create stub files so cargo can resolve the workspace
RUN mkdir -p citadel-envelope/src && echo "" > citadel-envelope/src/lib.rs && \
    mkdir -p citadel-keystore/src && echo "" > citadel-keystore/src/lib.rs && \
    mkdir -p citadel-api/src && echo "fn main() {}" > citadel-api/src/main.rs && \
    mkdir -p citadel-cli/src && echo "fn main() {}" > citadel-cli/src/main.rs

# Cache dependency build (with redis-backend for Redis replay support — P110)
# P132: --bins builds all binaries in the specified packages
# (citadel-api + hash-apikey from citadel-api pkg; citadel from citadel-cli pkg)
RUN cargo build --release -p citadel-api -p citadel-cli --bins --features redis-backend 2>/dev/null || true

# Copy actual source
COPY citadel-envelope/ citadel-envelope/
COPY citadel-keystore/ citadel-keystore/
COPY citadel-api/ citadel-api/
COPY citadel-cli/ citadel-cli/

# Touch sources to invalidate the stub cache
RUN touch citadel-envelope/src/lib.rs citadel-keystore/src/lib.rs \
          citadel-api/src/main.rs citadel-cli/src/main.rs

# Build release binaries with Redis replay support (P110, P115)
# P132: --bins is required; hash-apikey is a bin target in citadel-api, not a package
RUN cargo build --release -p citadel-api -p citadel-cli --bins --features redis-backend

# Stage 2: Runtime (minimal image)
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r citadel && useradd -r -g citadel -m citadel

# Copy binary
# Copy binaries (P115 — include CLI so `citadel doctor` works in container)
COPY --from=builder /build/target/release/citadel-api /usr/local/bin/citadel-api
COPY --from=builder /build/target/release/citadel    /usr/local/bin/citadel
COPY --from=builder /build/target/release/hash-apikey /usr/local/bin/hash-apikey

# Data directory (mount a volume here for persistence)
RUN mkdir -p /data && chown citadel:citadel /data
VOLUME /data

USER citadel

# P109 — Production-safe defaults.
# CITADEL_SEED_DEMO defaults false — demo seeding must be explicitly enabled.
# CITADEL_PORT matches the production compose (8443).
# CITADEL_MASTER_KEY and CITADEL_REPLAY_STORE are NOT set here — operators
# must inject them at runtime via environment or secrets manager.
ENV CITADEL_PORT=8443
ENV CITADEL_DATA_DIR=/data
ENV CITADEL_SEED_DEMO=false

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:8443/health || exit 1

ENTRYPOINT ["citadel-api"]
