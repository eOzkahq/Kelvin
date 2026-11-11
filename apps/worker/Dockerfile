# Multi-stage hardened production Dockerfile for KELVIN Worker Runner
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

WORKDIR /src/apps/worker
RUN go mod download

# Copy source code and scanner pinned locks
WORKDIR /src
COPY apps/worker ./apps/worker
COPY packages ./packages
COPY deploy/scanner-image-lock.yaml /src/deploy/scanner-image-lock.yaml

# Compile static binary
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src/apps/worker
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-arm64} \
    go build -trimpath -ldflags="-s -w -X main.version=1.0.0-prod" -o /bin/worker ./cmd/runner

# Stage 2: Minimal hardened runtime
FROM alpine:3.21

# Install CA certificates and tini for signal forwarding
RUN apk add --no-cache ca-certificates tini tzdata && \
    addgroup -g 10001 -S kelvin && \
    adduser -u 10001 -S kelvin -G kelvin -h /app -s /sbin/nologin && \
    mkdir -p /app /app/deploy /tmp && \
    chown -R 10001:10001 /app /tmp

WORKDIR /app

# Copy binary and image lock from builder
COPY --from=builder /bin/worker /app/kelvin-worker
COPY --from=builder /src/deploy/scanner-image-lock.yaml /app/deploy/scanner-image-lock.yaml

USER 10001:10001

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/app/kelvin-worker"]
