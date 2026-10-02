# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Hanagram-web contributors

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder

WORKDIR /app

COPY Cargo.toml ./
COPY Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY vendor ./vendor

# One binary serves both roles: `/app/reset_admin` is a symlink that runs the admin reset.
RUN cargo build --release --locked --bin hanagram-web \
    && mkdir -p /out \
    && cp target/x86_64-unknown-linux-musl/release/hanagram-web /out/hanagram-web \
    && ln -s hanagram-web /out/reset_admin

FROM scratch

WORKDIR /app

# TLS uses the root certificates compiled into the binary (webpki-roots), so no CA bundle is needed.
COPY --from=builder /out/ /app/

ENV BIND_ADDR=0.0.0.0:8080
ENV SESSIONS_DIR=./sessions
ENV RUST_LOG=info

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/hanagram-web", "healthcheck", "http://127.0.0.1:8080/health"]

CMD ["/app/hanagram-web"]
