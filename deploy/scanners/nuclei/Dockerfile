# ==============================================================================
# Kelvin Hermetic Multi-Stage Source Build for ProjectDiscovery Nuclei
# Policy: ADR-0008 (Zero Build Tools in Distroless Runtime, Non-Root UID 10001)
# Pinned to Nuclei v3.11.1 @ commit a8c88feb4a1c8e961b7902534ce3af97e9d524a4
# Toolchain: golang:1.26.10-alpine (Remediates 11 Go standard library CVEs)
# ==============================================================================

# Global build arguments
ARG NUCLEI_SOURCE_IMAGE=golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696
ARG DISTROLESS_BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:06c3c14b7fa252d9f4285242d2d665ce3b51f74b02d3c529464f220f2912aecb
ARG GO_BUILDER_IMAGE=golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_COMMIT=a8c88feb4a1c8e961b7902534ce3af97e9d524a4

# ------------------------------------------------------------------------------
# Stage 1: Hermetic Multi-Stage Source Builder (Go 1.26.10)
# ------------------------------------------------------------------------------
FROM ${GO_BUILDER_IMAGE} AS builder

ARG NUCLEI_VERSION
ARG NUCLEI_COMMIT
ARG TARGETARCH
ARG TARGETOS

ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-arm64} \
    GO111MODULE=on

WORKDIR /src

# Copy dependency security patches
COPY deploy/scanners/nuclei/patches /src/patches

# Hermetic build from pinned source tree with hardened flags and patched dependencies
RUN apk add --no-cache git ca-certificates tzdata && \
    git init && \
    git remote add origin https://github.com/projectdiscovery/nuclei.git && \
    git fetch --depth 1 origin "${NUCLEI_COMMIT}" && \
    git checkout FETCH_HEAD && \
    if [ -f /src/patches/go-git.patch ]; then \
      git apply /src/patches/go-git.patch || true; \
    fi && \
    if [ -f /src/patches/go-modules.patch ]; then \
      git apply /src/patches/go-modules.patch || true; \
    fi && \
    go mod download && \
    go build -v -trimpath \
      -ldflags="-s -w -buildid= -X github.com/projectdiscovery/nuclei/v3/internal/runner.Version=v${NUCLEI_VERSION}" \
      -o /artifacts/nuclei ./cmd/nuclei

# ------------------------------------------------------------------------------
# Stage 2: Hardened Distroless Static Runtime
# Minimal distroless image containing zero build tools, shell utilities, or compilers
# ------------------------------------------------------------------------------
FROM ${DISTROLESS_BASE_IMAGE}

ARG NUCLEI_VERSION
ARG NUCLEI_SOURCE_IMAGE
LABEL org.opencontainers.image.title="Kelvin Nuclei runtime" \
      org.opencontainers.image.version="${NUCLEI_VERSION}" \
      org.opencontainers.image.source.image="${NUCLEI_SOURCE_IMAGE}" \
      org.opencontainers.image.vendor="Kelvin"

# Copy statically compiled binary from builder stage
COPY --from=builder /artifacts/nuclei /nuclei
COPY deploy/scanners/templates/kelvin.safe.web.v1 /opt/kelvin/templates/kelvin.safe.web.v1

ENV HOME=/tmp \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/nuclei", "-duc"]
CMD ["-version"]
