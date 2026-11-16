FROM alpine:3 AS dirs
RUN mkdir /empty_dir

FROM scratch
ARG TARGETARCH

# upload-artifact v4 does not preserve file permissions
COPY --chmod=0755 filehost2-linux-${TARGETARCH} /filehost2

# from scratch image can't `chown` on its own
COPY --from=dirs --chown=65532:65532 /empty_dir /data
COPY --from=dirs --chown=65532:65532 /empty_dir /tmp

ENV STORE_PATH=/data

VOLUME ["/data"]
VOLUME ["/tmp"]
EXPOSE 8080

USER 65532:65532

ENTRYPOINT ["/filehost2"]
