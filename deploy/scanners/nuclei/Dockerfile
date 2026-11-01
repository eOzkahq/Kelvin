# The upstream image is used only as a source for the statically linked Nuclei
# binary. The final runtime contains no shell, package manager, or compiler.
ARG NUCLEI_SOURCE_IMAGE
FROM ${NUCLEI_SOURCE_IMAGE} AS upstream

ARG DISTROLESS_BASE_IMAGE
FROM ${DISTROLESS_BASE_IMAGE}

ARG NUCLEI_VERSION
ARG NUCLEI_SOURCE_IMAGE
LABEL org.opencontainers.image.title="Kelvin Nuclei runtime" \
      org.opencontainers.image.version="${NUCLEI_VERSION}" \
      org.opencontainers.image.source.image="${NUCLEI_SOURCE_IMAGE}" \
      org.opencontainers.image.vendor="Kelvin"

COPY --from=upstream /usr/local/bin/nuclei /nuclei
COPY deploy/scanners/templates/kelvin.safe.web.v1 /opt/kelvin/templates/kelvin.safe.web.v1
ENV HOME=/tmp \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/nuclei", "-duc"]
CMD ["-version"]
