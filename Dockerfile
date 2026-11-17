# syntax=docker/dockerfile:1
#
# Local all-in-one image: builds the AI sidecar, the dashboard and the Rust daemon,
# then serves the embedded dashboard from a small Debian runtime.
#
#   docker compose build            # dashboard from the local web/src/components/arc-pro (git-ignored)
#   ARC_PRO_TOKEN=... docker compose build   # fetch the licensed Arc Pro components instead
#
# The dashboard build needs web/src/components/arc-pro/ (licensed, never committed) or the
# ARC_PRO_TOKEN build arg; see web/README.md and web/arc-pro.json.

# ---------------------------------------------------------------- AI sidecar
FROM node:22-bookworm-slim AS sidecar
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH
RUN corepack enable
WORKDIR /src/agent-sidecar
COPY agent-sidecar/package.json agent-sidecar/pnpm-lock.yaml agent-sidecar/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY agent-sidecar/ ./
RUN pnpm build

# ---------------------------------------------------------------- dashboard
FROM node:22-bookworm AS web
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH
RUN corepack enable
ARG ARC_PRO_TOKEN=
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
# The Pro components are git-ignored. Use the copy in the build context, or fetch them when a token is given.
RUN if [ -n "$ARC_PRO_TOKEN" ] && [ ! -d src/components/arc-pro ]; then ARC_PRO_TOKEN="$ARC_PRO_TOKEN" pnpm arc:pro; fi
RUN pnpm build

# ---------------------------------------------------------------- daemon
FROM rust:1-bookworm AS backend
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY backend ./backend
COPY --from=sidecar /src/agent-sidecar/dist ./agent-sidecar/dist
COPY --from=web /src/web/dist ./web/dist
# rust-embed bakes the dashboard and the sidecar into the binary.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/tsmonitor /usr/local/bin/tsmonitor

# ---------------------------------------------------------------- runtime
FROM node:22-bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=backend /usr/local/bin/tsmonitor /usr/local/bin/tsmonitor

RUN useradd --system --create-home --home-dir /var/lib/tsmonitor --shell /usr/sbin/nologin tsm \
 && mkdir -p /var/lib/tsmonitor /etc/tsmonitor \
 && chown -R tsm:tsm /var/lib/tsmonitor

USER tsm
WORKDIR /var/lib/tsmonitor
EXPOSE 8787

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/tsmonitor"]
CMD ["--config", "/etc/tsmonitor/config.toml"]
