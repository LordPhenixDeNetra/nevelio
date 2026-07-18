# ─── Stage 1 : builder ────────────────────────────────────────────────────────
# Cargo 1.88+ is required by locked dependencies such as instability 0.3.12
# and time 0.3.47 / time-core 0.1.8 / time-macros 0.2.27.
FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first for dependency-layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# payloads/ must be present at compile time (embedded via include_str!())
COPY payloads/ payloads/

RUN cargo build --release -p nevelio

# ─── Stage 2 : runtime minimal ────────────────────────────────────────────────
FROM debian:bookworm-slim

# ca-certificates required by reqwest/rustls for TLS peer verification
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/nevelio /usr/local/bin/nevelio

# Non-root user for runtime security
RUN useradd -m -u 1000 nevelio
USER nevelio

WORKDIR /reports

ENTRYPOINT ["nevelio"]
CMD ["--help"]
