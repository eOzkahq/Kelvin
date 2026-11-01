#!/usr/bin/env bash
set -euo pipefail

require_digest_ref() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "$name must be an immutable image reference ending in @sha256:<64 lowercase hex>" >&2
    exit 2
  fi
}

require_official_ref() {
  local name="$1" value="$2" prefix="$3"
  if [[ "$value" != "$prefix"@sha256:* ]]; then
    echo "$name must use the approved upstream repository $prefix pinned by digest" >&2
    exit 2
  fi
}

require_version() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
    echo "$name must be an exact semantic version" >&2
    exit 2
  fi
}

: "${ZAP_BASE_IMAGE:?set ZAP_BASE_IMAGE to the official ZAP stable image pinned by digest}"
: "${ZAP_VERSION:?set ZAP_VERSION to the version verified from the selected image}"
: "${NUCLEI_SOURCE_IMAGE:?set NUCLEI_SOURCE_IMAGE to the official Nuclei image pinned by digest}"
: "${NUCLEI_VERSION:?set NUCLEI_VERSION to the version verified from the selected image}"
: "${DISTROLESS_BASE_IMAGE:?set DISTROLESS_BASE_IMAGE to a pinned distroless/static image}"
OUT_DIR="${OUT_DIR:-artifacts/scanner-images}"

require_digest_ref ZAP_BASE_IMAGE "$ZAP_BASE_IMAGE"
require_digest_ref NUCLEI_SOURCE_IMAGE "$NUCLEI_SOURCE_IMAGE"
require_digest_ref DISTROLESS_BASE_IMAGE "$DISTROLESS_BASE_IMAGE"
require_official_ref ZAP_BASE_IMAGE "$ZAP_BASE_IMAGE" "ghcr.io/zaproxy/zaproxy:stable"
require_official_ref NUCLEI_SOURCE_IMAGE "$NUCLEI_SOURCE_IMAGE" "projectdiscovery/nuclei"
require_official_ref DISTROLESS_BASE_IMAGE "$DISTROLESS_BASE_IMAGE" "gcr.io/distroless/static-debian12:nonroot"
require_version ZAP_VERSION "$ZAP_VERSION"
require_version NUCLEI_VERSION "$NUCLEI_VERSION"
mkdir -p "$OUT_DIR"

docker buildx build --platform linux/amd64 --load \
  --metadata-file "$OUT_DIR/zap-build-metadata.json" \
  --build-arg "ZAP_BASE_IMAGE=$ZAP_BASE_IMAGE" \
  --build-arg "ZAP_VERSION=$ZAP_VERSION" \
  --tag "kelvin/scanner-zap:$ZAP_VERSION" \
  --file deploy/scanners/zap/Dockerfile .

docker buildx build --platform linux/amd64 --load \
  --metadata-file "$OUT_DIR/nuclei-build-metadata.json" \
  --build-arg "NUCLEI_SOURCE_IMAGE=$NUCLEI_SOURCE_IMAGE" \
  --build-arg "NUCLEI_VERSION=$NUCLEI_VERSION" \
  --build-arg "DISTROLESS_BASE_IMAGE=$DISTROLESS_BASE_IMAGE" \
  --tag "kelvin/scanner-nuclei:$NUCLEI_VERSION" \
  --file deploy/scanners/nuclei/Dockerfile .

zap_digest="$(jq -er '.["containerimage.digest"] | select(test("^sha256:[0-9a-f]{64}$"))' "$OUT_DIR/zap-build-metadata.json")"
nuclei_digest="$(jq -er '.["containerimage.digest"] | select(test("^sha256:[0-9a-f]{64}$"))' "$OUT_DIR/nuclei-build-metadata.json")"
jq -n \
  --arg zap_base_image "$ZAP_BASE_IMAGE" --arg zap_version "$ZAP_VERSION" --arg zap_digest "$zap_digest" \
  --arg nuclei_source_image "$NUCLEI_SOURCE_IMAGE" --arg nuclei_version "$NUCLEI_VERSION" --arg nuclei_digest "$nuclei_digest" \
  --arg distroless_base_image "$DISTROLESS_BASE_IMAGE" \
  '{schema_version:"1", platform:"linux/amd64", images:{zap:{base_image:$zap_base_image,version:$zap_version,digest:$zap_digest},nuclei:{source_image:$nuclei_source_image,version:$nuclei_version,distroless_base_image:$distroless_base_image,digest:$nuclei_digest}}}' \
  > "$OUT_DIR/build-record.json"

for image in "kelvin/scanner-zap:$ZAP_VERSION" "kelvin/scanner-nuclei:$NUCLEI_VERSION"; do
  uid="$(docker image inspect "$image" --format '{{.Config.User}}')"
  if [[ "$uid" != "10001:10001" ]]; then
    echo "$image has unexpected runtime user: $uid" >&2
    exit 1
  fi
done

docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "kelvin/scanner-zap:$ZAP_VERSION" zap-baseline.py -h
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "kelvin/scanner-nuclei:$NUCLEI_VERSION" -version
zap_version_output="$(docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "kelvin/scanner-zap:$ZAP_VERSION" zap.sh -version 2>&1)"
if ! grep -Fq "$ZAP_VERSION" <<<"$zap_version_output"; then
  echo "ZAP runtime version does not match ZAP_VERSION=$ZAP_VERSION" >&2
  exit 1
fi
nuclei_version_output="$(docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  "kelvin/scanner-nuclei:$NUCLEI_VERSION" -version 2>&1)"
if ! grep -Fq "$NUCLEI_VERSION" <<<"$nuclei_version_output"; then
  echo "Nuclei runtime version does not match NUCLEI_VERSION=$NUCLEI_VERSION" >&2
  exit 1
fi

printf 'Built images and metadata: %s\n' "$OUT_DIR"
