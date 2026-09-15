FROM rust:1.98-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /app/target/release/gatekeeper /usr/local/bin/gatekeeper
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gatekeeper"]
