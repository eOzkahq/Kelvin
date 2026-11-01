#!/usr/bin/env bash
set -euo pipefail

: "${KELVIN_LOGICAL_BACKUP_KEY:?Set a unique secret key through a secret manager}"
out=${1:-"backups/kelvin-$(date -u +%Y%m%dT%H%M%SZ).dump.enc"}
mkdir -p "$(dirname "$out")"
tmp="$out.tmp"
trap 'rm -f "$tmp"' EXIT INT TERM

# GPG's AES-256 symmetric format includes integrity protection; OpenSSL enc's
# CBC mode does not authenticate ciphertext. Keep the passphrase off argv.
docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-kelvin}" -d "${POSTGRES_DB:-kelvin_dev}" -Fc \
  | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 \
      --symmetric --cipher-algo AES256 --output "$tmp" 3<<<"$KELVIN_LOGICAL_BACKUP_KEY"
mv "$tmp" "$out"
echo "Encrypted logical backup created: $out"
