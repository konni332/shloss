# -- Stage 1: Builder --
FROM rust:1.95-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Tell SQLx to look at the local JSON files instead of trying to hit a network database
ENV SQLX_OFFLINE=true

# Build the release binary
RUN cargo build --release --bin shloss

# -- Stage 2: Runtime --
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 shloss && \
    useradd -u 10001 -g shloss -s /bin/false -m shloss

WORKDIR /app
COPY --from=builder /app/target/release/shloss /app/shloss
RUN chown shloss:shloss /app/shloss

USER shloss
EXPOSE 3000

CMD ["./shloss"]
