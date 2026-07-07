FROM ubuntu:22.04 AS base

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    ca-certificates \
    postgresql-14 \
    postgresql-contrib \
    redis-server \
    supervisor \
    openssl \
    rpm \
    cpio \
    unzip \
    locales \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Set Locale and Timezone
RUN locale-gen ko_KR.UTF-8
ENV LANG=ko_KR.UTF-8
ENV LC_ALL=ko_KR.UTF-8
ENV TZ=Asia/Seoul
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Install Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g pnpm@11.7.0

# Setup directories
WORKDIR /app

# PROD DEPS STAGE
FROM base AS prod-deps
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile
# Generate prisma client (requires dev deps)
RUN pnpm --filter @jasca/api prisma:generate
# Prune to production deps only (removes prisma CLI but keeps generated client)
RUN pnpm prune --prod

# BUILDER STAGE
FROM base AS builder
WORKDIR /app
COPY . .
# Standard install for build
RUN pnpm install --frozen-lockfile
# Generate prisma
RUN pnpm --filter @jasca/api prisma:generate
# Build API
RUN pnpm --filter @jasca/api build
# Build Web
RUN pnpm --filter @jasca/web build
# Compile seed.ts to JavaScript for offline execution (using project tsconfig)
RUN cd apps/api && npx tsc prisma/seed.ts --outDir prisma --skipLibCheck

# RUNNER STAGE
FROM base AS runner
WORKDIR /app

# Install Trivy (Offline capability preparation)
RUN apt-get update && apt-get install -y wget lsb-release \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# Install Checkov for offline IaC misconfiguration scans.
RUN apt-get update && apt-get install -y python3-pip \
    && pip3 install --no-cache-dir checkov \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep for offline source-code SAST scans, and snapshot the
# community rules at build time so the closed network never needs the
# semgrep registry (SEMGREP_RULES_PATH points here).
RUN pip3 install --no-cache-dir semgrep \
    && mkdir -p /app/semgrep-rules \
    && curl -fsSL https://github.com/semgrep/semgrep-rules/tarball/HEAD | tar -xz -C /app/semgrep-rules --strip-components=1 \
    && rm -rf /app/semgrep-rules/.github \
    && find /app/semgrep-rules -name "*.test.yaml" -delete
ENV SEMGREP_RULES_PATH=/app/semgrep-rules

# Checkov's helm and kustomize frameworks require their CLIs at runtime.
# They are bundled into the offline image during build, not downloaded in the closed network.
ARG HELM_VERSION=v3.15.4
ARG KUSTOMIZE_VERSION=v5.4.2
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) tool_arch="amd64" ;; \
      arm64) tool_arch="arm64" ;; \
      *) echo "Unsupported architecture for helm/kustomize: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${tool_arch}.tar.gz" -o /tmp/helm.tar.gz; \
    tar -xzf /tmp/helm.tar.gz -C /tmp; \
    mv "/tmp/linux-${tool_arch}/helm" /usr/local/bin/helm; \
    chmod +x /usr/local/bin/helm; \
    rm -rf /tmp/helm.tar.gz "/tmp/linux-${tool_arch}"; \
    curl -fsSL "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F${KUSTOMIZE_VERSION}/kustomize_${KUSTOMIZE_VERSION}_linux_${tool_arch}.tar.gz" -o /tmp/kustomize.tar.gz; \
    tar -xzf /tmp/kustomize.tar.gz -C /usr/local/bin kustomize; \
    chmod +x /usr/local/bin/kustomize; \
    rm -f /tmp/kustomize.tar.gz

# Install Syft at image build time so closed-network runtime scans can generate
# SBOMs locally without reaching out to cloud services.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Prepare Trivy DB mount point for offline usage.
# Recommended: mount the target server's Trivy cache at runtime:
#   -v /path/to/trivy-cache:/app/trivy-db:ro
RUN mkdir -p /app/trivy-db
RUN mkdir -p /app/trivy-db/db /app/trivy-db/java-db && \
    if [ -f /app/trivy-db/trivy.db ] && [ ! -f /app/trivy-db/db/trivy.db ]; then cp /app/trivy-db/trivy.db /app/trivy-db/db/trivy.db; fi && \
    if [ -f /app/trivy-db/metadata.json ] && [ ! -f /app/trivy-db/db/metadata.json ]; then cp /app/trivy-db/metadata.json /app/trivy-db/db/metadata.json; fi && \
    if [ -f /app/trivy-db/trivy-java.db ] && [ ! -f /app/trivy-db/java-db/trivy-java.db ]; then cp /app/trivy-db/trivy-java.db /app/trivy-db/java-db/trivy-java.db; fi && \
    if [ -f /app/trivy-db/java-metadata.json ] && [ ! -f /app/trivy-db/java-db/metadata.json ]; then cp /app/trivy-db/java-metadata.json /app/trivy-db/java-db/metadata.json; fi
ENV TRIVY_CACHE_DIR=/app/trivy-db

# Copy Web artifacts (Standalone) FIRST to avoid node_modules conflicts
# Next.js standalone build output: server.js is at the root of the standalone folder
COPY --from=builder /app/apps/web/.next/standalone ./
COPY --from=builder /app/apps/web/.next/static ./.next/static

# Preserve standalone's node_modules (contains 'next' and required deps)
RUN mv node_modules node_modules_web

# Copy production node_modules from prod-deps (for API)
COPY --from=prod-deps /app/node_modules ./node_modules

# Merge web's node_modules into main node_modules (copy missing modules)
RUN cp -rn node_modules_web/* node_modules/ 2>/dev/null || true && \
    rm -rf node_modules_web && \
    echo "=== Verifying next module ===" && \
    ls -la node_modules/next && \
    echo "next module found"

# Ensure server.js is accessible and create fallback symlink for compatibility
RUN echo "=== Verifying server.js location ===" && \
    ls -la server.js && \
    echo "server.js found at /app/server.js" && \
    mkdir -p apps/web && \
    ln -sf /app/server.js /app/apps/web/server.js && \
    echo "Created symlink: /app/apps/web/server.js -> /app/server.js"

# Copy API artifacts
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/apps/api/package.json ./apps/api/
COPY --from=builder /app/apps/api/prisma ./apps/api/prisma
# Copy compiled seed.js
COPY --from=builder /app/apps/api/prisma/seed.js ./apps/api/prisma/seed.js

# Keep Node's normal module resolution working for Prisma seed/runtime code.
RUN mkdir -p /app/node_modules/@prisma /app/node_modules/.bin && \
    if [ -d /app/node_modules/.pnpm/@prisma+client@5.22.0_prisma@5.22.0/node_modules/@prisma/client ]; then \
      ln -sfn /app/node_modules/.pnpm/@prisma+client@5.22.0_prisma@5.22.0/node_modules/@prisma/client /app/node_modules/@prisma/client; \
    fi && \
    if [ -d /app/node_modules/.pnpm/prisma@5.22.0/node_modules/prisma ]; then \
      ln -sfn /app/node_modules/.pnpm/prisma@5.22.0/node_modules/prisma /app/node_modules/prisma; \
      ln -sfn ../prisma/build/index.js /app/node_modules/.bin/prisma; \
    fi && \
    if [ -d /app/node_modules/.pnpm/bcryptjs@2.4.3/node_modules/bcryptjs ]; then \
      ln -sfn /app/node_modules/.pnpm/bcryptjs@2.4.3/node_modules/bcryptjs /app/node_modules/bcryptjs; \
    fi

# Copy Configs
COPY docker/monolith/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/monolith/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Configure Redis to bind to all interfaces
RUN sed -i "s/bind 127.0.0.1 -/bind 0.0.0.0/" /etc/redis/redis.conf || true
RUN sed -i "s/bind 127.0.0.1 ::1/bind 0.0.0.0/" /etc/redis/redis.conf || true

# Volumes for persistence
VOLUME ["/var/lib/postgresql/data", "/var/lib/redis"]

# Ports
EXPOSE 3000 3001

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
