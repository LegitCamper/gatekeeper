FROM rust:1.98-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
RUN cargo build --release --locked
RUN mkdir -m 700 /gatekeeper-data

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /app/target/release/gatekeeper /usr/local/bin/gatekeeper
COPY --from=builder --chown=65532:65532 /gatekeeper-data /var/lib/gatekeeper
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gatekeeper"]
