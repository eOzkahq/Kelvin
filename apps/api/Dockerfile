# Multi-stage hardened production Dockerfile for KELVIN Control Plane API
# Target architecture: linux/arm64 & linux/amd64

# Stage 1: Build binary
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /src

# Ensure reproducible build using local container toolchain without auto-downloading
ENV GOTOOLCHAIN=local

# Install CA certificates and build tools
RUN apk add --no-cache ca-certificates git

# Cache dependency layer
COPY go.work go.work.sum* ./
COPY apps/api/go.mod apps/api/go.sum* ./apps/api/
COPY apps/worker/go.mod apps/worker/go.sum* ./apps/worker/
COPY packages/common/go.mod packages/common/go.sum* ./packages/common/
COPY packages/schemas/go.mod packages/schemas/go.sum* ./packages/schemas/
COPY tests/integration/go.mod tests/integration/go.sum* ./tests/integration/

WORKDIR /src/apps/api
RUN go mod download

# Copy source code
WORKDIR /src
COPY apps/api ./apps/api
COPY packages ./packages

# Compile static binary
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src/apps/api
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-arm64} \
    go build -trimpath -ldflags="-s -w -X main.version=1.0.0-prod" -o /bin/api ./cmd/api && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-arm64} \
    go build -trimpath -ldflags="-s -w" -o /bin/migrate ./cmd/migrate

# Stage 2: Minimal hardened runtime
FROM alpine:3.21

# Install CA certificates, tini for signal forwarding, curl for health probes
RUN apk add --no-cache ca-certificates tini curl tzdata && \
    addgroup -g 10001 -S kelvin && \
    adduser -u 10001 -S kelvin -G kelvin -h /app -s /sbin/nologin && \
    mkdir -p /app /app/db/migrations /tmp && \
    chown -R 10001:10001 /app /tmp

WORKDIR /app

# Copy binaries and migration assets from builder
COPY --from=builder /bin/api /app/kelvin-api
COPY --from=builder /bin/migrate /app/kelvin-migrate
COPY apps/api/db/migrations /app/db/migrations

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/app/kelvin-api"]
