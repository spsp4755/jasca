FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build \
    && mkdir -p /lic \
    && npm ls --omit=dev --all --parseable | tail -n +2 | while read -r d; do \
       n=$(echo "${d#/src/web/node_modules/}" | tr / _); \
       for f in "$d"/LICENSE* "$d"/license* "$d"/NOTICE*; do [ -f "$f" ] && cp "$f" "/lic/$n-$(basename "$f")"; done; \
       true; \
    done

# Trivy is built from its release tag instead of copied from the official image: the official 0.76.2 binary still carries
# golang.org/x/crypto v0.58.0 (GO-2026-5932) and an older Go standard library. Same build flags as upstream's goreleaser.yml.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS trivy
ARG TRIVY_VERSION=0.76.2
ARG TRIVY_COMMIT=3f6334d223b52188324af3b9923b4249cd206652
WORKDIR /src
RUN apk add --no-cache git \
    && git clone -q --depth 1 --branch "v${TRIVY_VERSION}" https://github.com/aquasecurity/trivy . \
    && [ "$(git rev-parse HEAD)" = "$TRIVY_COMMIT" ] \
    && go get golang.org/x/crypto@v0.59.0 \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -extldflags '-static' -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}" -o /trivy ./cmd/trivy \
    && /trivy --version

FROM golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=1.3.0
# DB-backed tests need JASCA_TEST_DATABASE_URL and are skipped here; they run against PostgreSQL before release.
RUN go vet ./... && go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/jasca . \
    && mkdir -p /out/tmp /out/licenses && chmod 1777 /out/tmp && cp /usr/local/go/LICENSE /out/licenses/Go-LICENSE \
    && go list -m -f '{{.Path}}|{{.Dir}}' all | while IFS='|' read -r name dir; do \
       [ -n "$dir" ] || continue; \
       find "$dir" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'NOTICE*' \) | while read -r f; do cp "$f" "/out/licenses/$(echo "$name" | tr / _)-$(basename "$f")"; done; \
    done
# Apache-2.0 asks for the license text and a note of what was changed.
COPY --from=trivy /src/LICENSE /out/licenses/Trivy-LICENSE
RUN printf 'Trivy 0.76.2 (c) Aqua Security Software Ltd., licensed under the Apache License 2.0 (Trivy-LICENSE).\nBuilt from the source of that release (https://github.com/aquasecurity/trivy) with one change: golang.org/x/crypto raised to v0.59.0.\n' > /out/licenses/Trivy-NOTICE.txt
# npm packages shipped in the bundle
COPY --from=web /lic/ /out/licenses/
COPY --from=web /src/web/node_modules/pretendard/dist/LICENSE.txt /out/licenses/Pretendard-OFL.txt
COPY --from=trivy /trivy /out/usr/local/bin/trivy

FROM scratch
ARG VERSION=1.3.0
LABEL org.opencontainers.image.title="jasca" org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/spsp4755/jasca"
COPY --from=build /out/ /
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV JASCA_ADDR=0.0.0.0:8080 TMPDIR=/tmp
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/jasca", "--healthcheck"]
ENTRYPOINT ["/jasca"]
