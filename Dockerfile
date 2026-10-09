# syntax=docker/dockerfile:1

FROM rust:1.97.1-bookworm AS build

WORKDIR /build

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src

RUN cargo build --release --locked --bin archive

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="Archive Ledger" \
      org.opencontainers.image.description="Local-first preservation inventory and disaster-risk ledger" \
      org.opencontainers.image.source="https://github.com/buildmesh/archive-ledger" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        git \
        openssh-client \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /home/archive-ledger --uid 10001 --user-group archive-ledger \
    && install --directory --owner=archive-ledger --group=archive-ledger /state

COPY --from=build /build/target/release/archive /usr/local/bin/archive
COPY LICENSE /usr/share/licenses/archive-ledger/LICENSE

ENV HOME=/state \
    XDG_CONFIG_HOME=/state/config \
    XDG_DATA_HOME=/state/data

USER archive-ledger
WORKDIR /locations

ENTRYPOINT ["archive"]
CMD ["--help"]
