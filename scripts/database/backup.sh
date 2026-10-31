#!/usr/bin/env sh
set -eu

compose='docker compose -f docker-compose.yml -f docker-compose.backup.yml'
if [ "${1:-}" = "--init" ]; then
  # Stanza creation is a one-time operation after PostgreSQL is healthy.
  $compose exec -T postgres pgbackrest --stanza=kelvin stanza-create
  $compose exec -T postgres pgbackrest --stanza=kelvin check
  exit 0
fi

# Run from the repository root. Schedule this daily (and run --init once).
$compose exec -T postgres pgbackrest --stanza=kelvin --type=full backup
