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

RUN mkdir /empty_dir

WORKDIR /app

ENV SQLX_OFFLINE=true

# pre build and cache (in an image layer) dependencies only
COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-$TARGETARCH \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git-$TARGETARCH \
    mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo zigbuild --release --target "$(cat /rust_target)" \
    && rm -rf src

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-$TARGETARCH \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git-$TARGETARCH \
    cargo zigbuild --release --target "$(cat /rust_target)" && \
    cp "target/$(cat /rust_target)/release/filehost2" /filehost2

FROM scratch

ENV STORE_PATH=/data

COPY --from=builder /filehost2 /filehost2

# from scratch image can't `chown` on its own
COPY --from=builder --chown=65532:65532 /empty_dir /data
COPY --from=builder --chown=65532:65532 /empty_dir /tmp

VOLUME ["/data"]
VOLUME ["/tmp"]
EXPOSE 8080

USER 65532:65532

ENTRYPOINT ["/filehost2"]
