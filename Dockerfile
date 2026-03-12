# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Hanagram-web contributors

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder

WORKDIR /app

COPY Cargo.toml ./
COPY src ./src
COPY templates ./templates

RUN cargo build --release

FROM alpine:3.21

WORKDIR /app

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/hanagram-web /usr/local/bin/hanagram-web
COPY templates ./templates

RUN mkdir -p /app/sessions

ENV BIND_ADDR=0.0.0.0:8080
ENV SESSIONS_DIR=./sessions
ENV RUST_LOG=info

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["hanagram-web"]
