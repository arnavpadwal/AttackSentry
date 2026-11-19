# AttackSentry sensor (headless capture agent)
FROM rust:1.83-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/release/sentry_sensor /usr/local/bin/sentry_sensor

ENV SENTRY_HEADLESS=1
ENTRYPOINT ["/usr/local/bin/sentry_sensor"]
