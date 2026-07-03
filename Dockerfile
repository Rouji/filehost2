FROM --platform=$BUILDPLATFORM rust:latest AS builder

ARG TARGETARCH

# cargo-zigbuild cross-links against musl for any target from this one
# (amd64) builder, so the arm64 leg needs no QEMU emulation.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends python3-pip \
    && pip3 install --break-system-packages ziglang \
    && cargo install cargo-zigbuild

RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl > /rust_target ;; \
      arm64) echo aarch64-unknown-linux-musl > /rust_target ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac
RUN rustup target add "$(cat /rust_target)"

WORKDIR /app

COPY . .

ENV SQLX_OFFLINE=true

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo zigbuild --release --target "$(cat /rust_target)" && \
    cp "target/$(cat /rust_target)/release/filehost2" /filehost2

FROM scratch

COPY --from=builder /filehost2 /filehost2

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/filehost2"]
