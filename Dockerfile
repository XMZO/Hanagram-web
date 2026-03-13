# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Hanagram-web contributors

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder

WORKDIR /app

COPY Cargo.toml ./
COPY Cargo.lock ./
COPY src ./src
COPY templates ./templates

RUN cargo build --release --locked --bin hanagram-web --bin reset_admin

FROM scratch

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/hanagram-web ./hanagram-web
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/reset_admin ./reset_admin

ENV BIND_ADDR=0.0.0.0:8080
ENV SESSIONS_DIR=./sessions
ENV RUST_LOG=info

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/hanagram-web", "healthcheck", "http://127.0.0.1:8080/health"]

CMD ["/app/hanagram-web"]
