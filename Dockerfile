# syntax=docker/dockerfile:1

FROM rust:1.96.1-alpine3.22 AS builder

RUN apk add --no-cache build-base libpcap-dev

WORKDIR /usr/src/pingly

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --locked --release --no-default-features --features server,mimalloc

FROM alpine:3.22 AS runtime

LABEL org.opencontainers.image.source="https://github.com/0x676e67/pingly" \
      org.opencontainers.image.description="TLS and HTTP/1/2 fingerprint analysis server" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache ca-certificates libpcap \
    && addgroup -S -g 10001 pingly \
    && adduser -S -D -H -u 10001 -G pingly \
        -h /var/lib/pingly -s /sbin/nologin pingly \
    && mkdir -p /var/lib/pingly \
    && chown pingly:pingly /var/lib/pingly \
    && chmod 0700 /var/lib/pingly

COPY --from=builder /usr/src/pingly/target/release/pingly /usr/local/bin/pingly
COPY LICENSE /usr/share/licenses/pingly/LICENSE

ENV HOME=/var/lib/pingly \
    STATE_DIRECTORY=/var/lib/pingly

WORKDIR /var/lib/pingly
USER 10001:10001

VOLUME ["/var/lib/pingly"]
EXPOSE 8181 8080
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/pingly"]
CMD ["run"]
