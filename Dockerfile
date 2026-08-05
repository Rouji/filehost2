FROM --platform=$BUILDPLATFORM docker.io/tonistiigi/xx AS xx

FROM --platform=$BUILDPLATFORM docker.io/library/rust:alpine AS builder
COPY --from=xx / /

RUN apk add --no-cache clang lld musl-dev

ARG TARGETPLATFORM
RUN xx-apk add --no-cache musl-dev gcc

RUN mkdir /empty_dir

WORKDIR /app

ENV SQLX_OFFLINE=true

# pre build and cache (in an image layer) dependencies only
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && xx-cargo build --release --target-dir ./build \
    && rm -rf src

COPY . .

# make sure mtime is newer than the stub main.rs
RUN find . -path ./build -prune -o -type f -exec touch {} +

RUN xx-cargo build --release --target-dir ./build \
    && xx-verify "./build/$(xx-cargo --print-target-triple)/release/filehost2" \
    && cp "./build/$(xx-cargo --print-target-triple)/release/filehost2" /filehost2

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
