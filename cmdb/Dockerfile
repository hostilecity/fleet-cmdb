# syntax=docker/dockerfile:1
# check=error=true

# This Dockerfile is designed for production, not development. .github/workflows/cd.yml builds and runs it on the
# server (docs/operations/install-server.md). Build it from cmdb/ with the agent API schemas from docs/api and the
# agent's compiled-in certificate authorities from agent/trust and its release public keys from agent/release-keys passed
# in as named build contexts (read at runtime; P1-API-AUTH, ADR 0024, #181):
# docker build --build-context api=../docs/api --build-context trust=../agent/trust --build-context release-keys=../agent/release-keys -t cmdb .

# For a containerized dev environment, see Dev Containers: https://guides.rubyonrails.org/getting_started_with_devcontainer.html

# Make sure RUBY_VERSION matches the Ruby version in .ruby-version
ARG RUBY_VERSION=3.4.13
FROM docker.io/library/ruby:$RUBY_VERSION-slim AS base

# Rails app lives here
WORKDIR /rails

# Install base packages
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y curl libjemalloc2 postgresql-client && \
    ln -s /usr/lib/$(uname -m)-linux-gnu/libjemalloc.so.2 /usr/local/lib/libjemalloc.so && \
    rm -rf /var/lib/apt/lists /var/cache/apt/archives

# Set production environment variables and enable jemalloc for reduced memory usage and latency.
ENV RAILS_ENV="production" \
    BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development:test" \
    LD_PRELOAD="/usr/local/lib/libjemalloc.so" \
    FLEET_API_SCHEMAS_DIR="/rails/api-schemas" \
    FLEET_RULES_SCHEMA_DIR="/rails/api-rules" \
    FLEET_TASK_CATALOG_DIR="/rails/api-tasks" \
    FLEET_AGENT_TRUST_DIR="/rails/agent-trust" \
    FLEET_AGENT_RELEASE_KEYS_DIR="/rails/agent-release-keys"

# Throw-away build stage to reduce size of final image
FROM base AS build

# Install packages needed to build gems
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y build-essential git libpq-dev libyaml-dev pkg-config && \
    rm -rf /var/lib/apt/lists /var/cache/apt/archives

# Install application gems
COPY vendor/* ./vendor/
COPY Gemfile Gemfile.lock ./

# -j 1 disables parallel compilation to avoid a QEMU bug: https://github.com/rails/bootsnap/issues/495
RUN bundle install && \
    rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache "${BUNDLE_PATH}"/ruby/*/bundler/gems/*/.git && \
    bundle exec bootsnap precompile -j 1 --gemfile

# Copy application code
COPY . .
# Persistent data (release files, the backup status file) lives under storage/, a volume in the deployment. Created
# here so a new volume starts owned by the app user.
RUN mkdir -p storage/releases storage/backup

# Agent API JSON Schemas, the single source of truth in docs/api (named build context "api").
COPY --from=api schemas ./api-schemas
# The CIS-aligned rule file schema (P2-S04), from the same build context.
COPY --from=api rules ./api-rules
# The task catalog (P3-S01), the same file the agent compiles in; loaded and linted at boot.
COPY --from=api tasks/task-catalog.json tasks/task-catalog.schema.json ./api-tasks/
# The certificate authorities compiled into the agent (ADR 0024), the same files: the install page gives curl the one
# that signed the server's certificate (named build context "trust").
COPY --from=trust *.pem ./agent-trust/
# The release public keys compiled into the agent (agent/release-keys, named build context "release-keys"): the install
# page warns when the configured FLEET_RELEASE_KEY_* differ from them, since the install check uses these (#181).
COPY --from=release-keys *.pub ./agent-release-keys/

# Precompile bootsnap code for faster boot times.
# -j 1 disable parallel compilation to avoid a QEMU bug: https://github.com/rails/bootsnap/issues/495
RUN bundle exec bootsnap precompile -j 1 app/ lib/

# Precompiling assets for production without requiring secret RAILS_MASTER_KEY
RUN SECRET_KEY_BASE_DUMMY=1 ./bin/rails assets:precompile




# Final stage for app image
FROM base

# Run as a non-root user that owns only what it writes at runtime (NFR-1): storage/ (the volume), tmp/ (bootsnap's and
# Puma's files), and log/. The code and the gems belong to root, so a compromised app process cannot change what it
# runs, and a change cannot outlive the container's restart (`--restart unless-stopped` keeps the same container).
RUN groupadd --system --gid 1000 rails && \
    useradd rails --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin

# Copy built artifacts: gems, application
COPY --from=build "${BUNDLE_PATH}" "${BUNDLE_PATH}"
COPY --from=build /rails /rails
# The Ruby image leaves GEM_HOME world-writable (1777); nothing writes there at runtime.
RUN chown -R rails:rails /rails/storage /rails/tmp /rails/log && chmod 755 "${BUNDLE_PATH}"
USER 1000:1000

# Entrypoint prepares the database.
ENTRYPOINT ["/rails/bin/docker-entrypoint"]

# Puma directly, not through Thruster (P1-O03): HostSeparation trusts X-Forwarded-* headers only from the proxy
# that connected, and behind Thruster every request would come from loopback, which is always trusted. Puma also
# serves HTTPS on 3443 with the server's Cloudflare Origin CA certificate when it is configured (ADR 0024,
# config/puma.rb); 3000 is plain HTTP for the container's own health checks.
ENV PORT="3000"
EXPOSE 3000 3443
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
