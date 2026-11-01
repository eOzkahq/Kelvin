# Build with ZAP_BASE_IMAGE set to the official ZAP stable image by immutable
# digest. Never pass a mutable tag here.
ARG ZAP_BASE_IMAGE
FROM ${ZAP_BASE_IMAGE}

ARG ZAP_VERSION
ARG ZAP_BASE_IMAGE
LABEL org.opencontainers.image.title="Kelvin OWASP ZAP Baseline runtime" \
      org.opencontainers.image.version="${ZAP_VERSION}" \
      org.opencontainers.image.source.image="${ZAP_BASE_IMAGE}" \
      org.opencontainers.image.vendor="Kelvin"

# The upstream image is read-only at runtime. ZAP writes transient state only
# under the worker-provided /tmp tmpfs. Preserve its official scan scripts and
# installation while enforcing the worker UID.
ENV HOME=/tmp \
    ZAP_HOME=/tmp/.ZAP \
    JAVA_TOOL_OPTIONS="-Duser.home=/tmp"
WORKDIR /tmp
USER 10001:10001

# The official ZAP stable image provides zap-baseline.py; the adapter supplies
# the bounded baseline arguments. Do not expose the ZAP API port.
CMD ["zap-baseline.py", "-h"]
