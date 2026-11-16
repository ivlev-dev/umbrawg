FROM rust:1.85-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --workspace

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/umbrawg /usr/bin/umbrawg
ENTRYPOINT ["umbrawg"]
