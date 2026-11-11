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

FROM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=1.1.0
# DB-backed tests need JASCA_TEST_DATABASE_URL and are skipped here; they run against PostgreSQL before release.
RUN go vet ./... && go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/jasca . \
    && mkdir -p /out/tmp /out/licenses && chmod 1777 /out/tmp && cp /usr/local/go/LICENSE /out/licenses/Go-LICENSE \
    && go list -m -f '{{.Path}}|{{.Dir}}' all | while IFS='|' read -r name dir; do \
       [ -n "$dir" ] || continue; \
       find "$dir" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'NOTICE*' \) | while read -r f; do cp "$f" "/out/licenses/$(echo "$name" | tr / _)-$(basename "$f")"; done; \
    done
# The Trivy image ships no LICENSE file, so record the notice here (Apache-2.0, https://github.com/aquasecurity/trivy).
RUN printf 'Trivy 0.76.1 (c) Aqua Security Software Ltd., licensed under the Apache License 2.0.\nhttps://github.com/aquasecurity/trivy/blob/main/LICENSE\n' > /out/licenses/Trivy-NOTICE.txt
# npm packages shipped in the bundle
COPY --from=web /lic/ /out/licenses/
COPY --from=web /src/web/node_modules/pretendard/dist/LICENSE.txt /out/licenses/Pretendard-OFL.txt
COPY --from=aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c /usr/local/bin/trivy /out/usr/local/bin/trivy

FROM scratch
ARG VERSION=1.1.0
LABEL org.opencontainers.image.title="jasca" org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/spsp4755/jasca"
COPY --from=build /out/ /
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV JASCA_ADDR=0.0.0.0:8080 TMPDIR=/tmp
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/jasca", "--healthcheck"]
ENTRYPOINT ["/jasca"]
