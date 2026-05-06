# syntax=docker/dockerfile:1.7
###############################################################################
# Build stage — Elixir + Erlang toolchain + native compilers for EKV / SQLite.
###############################################################################
ARG ELIXIR_VERSION=1.17.3
ARG OTP_VERSION=27.1
ARG DEBIAN_VERSION=bookworm-20240926-slim

ARG BUILDER_IMAGE="hexpm/elixir:${ELIXIR_VERSION}-erlang-${OTP_VERSION}-debian-${DEBIAN_VERSION}"
ARG RUNNER_IMAGE="debian:${DEBIAN_VERSION}"

FROM ${BUILDER_IMAGE} AS builder

# Native deps for EKV (vendored SQLite NIF) and exqlite. Pin to
# what the deps' precompile artefacts target to avoid a surprise
# source build at deploy time.
RUN apt-get update -y \
 && apt-get install -y --no-install-recommends build-essential git ca-certificates \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ENV MIX_ENV=prod \
    LANG=C.UTF-8

WORKDIR /build

# Cache deps independently of source.
COPY mix.exs mix.lock ./
COPY config config

RUN mix local.hex --force \
 && mix local.rebar --force \
 && mix deps.get --only prod \
 && mix deps.compile

# Now bring in the source.
COPY lib lib
COPY priv priv
COPY src src

# Compile + assemble the release tarball.
RUN mix compile \
 && mix release ex_dns --overwrite

###############################################################################
# Runtime stage — minimal Debian + the release tree, nothing else.
###############################################################################
FROM ${RUNNER_IMAGE}

# OpenSSL for the BEAM's :crypto, libstdc++ for SQLite NIF,
# tini as PID 1 for clean signal forwarding, dnsutils for
# debugging from inside the container.
RUN apt-get update -y \
 && apt-get install -y --no-install-recommends \
        libssl3 libstdc++6 libncurses6 locales tini ca-certificates \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
 && locale-gen

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8

# Non-root runtime user.
RUN groupadd --system --gid 1000 exdns \
 && useradd --system --uid 1000 --gid exdns --home /var/lib/exdns --shell /usr/sbin/nologin exdns \
 && install -d -o exdns -g exdns -m 0750 /var/lib/exdns \
 && install -d -o root -g exdns -m 0750 /etc/exdns \
 && install -d -o root -g exdns -m 0750 /etc/exdns/zones.d

WORKDIR /opt/exdns

COPY --from=builder --chown=root:root /build/_build/prod/rel/ex_dns ./

# Bind low ports (53, 853, 443) without root.
RUN setcap 'cap_net_bind_service=+ep' /opt/exdns/erts-*/bin/beam.smp || true

USER exdns:exdns

# Operator drops their config + zones at these paths via volume mount.
VOLUME ["/etc/exdns", "/var/lib/exdns"]

# DNS (UDP+TCP), DoT, DoH, admin API, health, metrics.
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 9571/tcp 9572/tcp 9573/tcp

ENV EXDNS_RUNTIME_CONFIG=/etc/exdns/runtime.exs

# Health check — tied to the readiness probe ExDns exports.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -T 2 -O /dev/null http://127.0.0.1:9572/readyz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/exdns/bin/ex_dns"]
CMD ["start"]
