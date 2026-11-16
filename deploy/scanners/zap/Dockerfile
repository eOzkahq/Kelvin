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

USER root

# Upgrade apt, libapt-pkg, and firefox-esr to remediate reported Debian CVEs
# Hard fail-closed: unpinned fallbacks are strictly prohibited to prevent silent CVE drift
COPY deploy/scanners/zap/packages.list /etc/apt/preferences.d/kelvin-pinned-packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apt=2.6.2* \
        libapt-pkg6.0=2.6.2* \
        firefox-esr=153.7.0esr-1~deb12u1* && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Upgrade Python setuptools to remediate CVE-2025-47273
COPY deploy/scanners/zap/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm -f /tmp/requirements.txt

# Minimize runtime footprint: purge compilers, -dev headers, and static packages
COPY deploy/scanners/zap/slim-packages.list /tmp/slim-packages.list
RUN apt-get purge -y --auto-remove \
      linux-libc-dev \
      libexpat1-dev \
      libpython3.11-dev \
      zlib1g-dev \
      gcc \
      build-essential \
      g++ \
      make \
      dpkg-dev \
      git-man && \
    rm -rf /usr/share/man/* /usr/share/doc/* /var/cache/apt/* /var/lib/apt/lists/* /tmp/slim-packages.list

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
