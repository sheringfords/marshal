# Build
FROM rust:1.88-bookworm AS build
WORKDIR /src

# Cache dependencies separately from source. The dummy lib.rs is enough to
# resolve and build the dependency graph; `touch` forces a real rebuild once
# the sources land, since cargo trusts mtimes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/lib.rs \
    && cargo build --release --bin marshalld 2>/dev/null || true
COPY src ./src
RUN touch src/lib.rs && cargo build --release --bin marshalld

# Runtime
FROM debian:bookworm-slim

# ca-certificates is required: HttpTool speaks HTTPS to allowlisted hosts and
# rustls has no certificates of its own.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged. The tools enforce policy in-process rather than through kernel
# isolation, so a bug past the policy has whatever rights this user has — which
# should be as close to none as the workload allows.
RUN useradd --system --uid 10001 --home-dir /var/lib/marshalld --create-home marshalld

COPY --from=build /src/target/release/marshalld /usr/local/bin/marshalld
COPY marshall.yaml /etc/marshalld/marshall.yaml

USER marshalld
WORKDIR /var/lib/marshalld
EXPOSE 3000

# The daemon binds loopback by default and refuses a non-loopback bind without
# a token, which is exactly wrong for a container that has to be reachable —
# so the image sets the bind explicitly, and MARSHALLD_API_TOKEN must be
# supplied at run time or startup fails. That failure is the point: it is the
# difference between a deliberate deployment and an open executor.
ENV MARSHALLD_BIND=0.0.0.0
ENV MARSHALLD_PORT=3000

# Probes the running service, not just the binary. `--healthcheck` reads the
# same MARSHALLD_PORT the server binds.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/marshalld", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/marshalld"]
CMD ["--config", "/etc/marshalld/marshall.yaml"]
