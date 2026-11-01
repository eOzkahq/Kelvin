#!/usr/bin/env sh
set -eu

compose='docker compose -f docker-compose.yml -f docker-compose.backup.yml'
image=$($compose images -q postgres)
[ -n "$image" ] || { echo 'Build/start the backup-enabled Compose stack first.' >&2; exit 1; }
suffix=$$
container="kelvin-restore-drill-$suffix"
port=${KELVIN_DRILL_PORT:-55439}
repo=kelvin_pgbackrest_repo
network=kelvin-local-network
pass=${PGBACKREST_REPO1_CIPHER_PASS:?Set the backup encryption passphrase}

cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

# Restore into an ephemeral container with an empty PGDATA, then verify it as PostgreSQL.
docker run -d --name "$container" --network "$network" -p "127.0.0.1:$port:5432" \
  --entrypoint sh \
  -e PGBACKREST_REPO1_CIPHER_PASS="$pass" -e POSTGRES_USER="${POSTGRES_USER:-kelvin}" \
  -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-kelvin_secret_dev_pass}" -e POSTGRES_DB="${POSTGRES_DB:-kelvin_dev}" \
  -v "$repo:/var/lib/pgbackrest" \
  -v "$(pwd)/deploy/postgres/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
  "$image" -ec 'mkdir -p /drill-data; chown postgres:postgres /drill-data; su-exec postgres pgbackrest --stanza=kelvin --pg1-path=/drill-data restore; chown -R postgres:postgres /drill-data; exec su-exec postgres postgres -D /drill-data -c archive_mode=off -c port=5432' >/dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "$container" pg_isready -U "${POSTGRES_USER:-kelvin}" -d "${POSTGRES_DB:-kelvin_dev}" >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[ "$ready" -eq 1 ] || { echo 'Restored PostgreSQL did not become ready within 120 seconds.' >&2; docker logs "$container"; exit 1; }

docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-kelvin}" -d "${POSTGRES_DB:-kelvin_dev}" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 3 AND dirty = false) THEN
    RAISE EXCEPTION 'migration version 3 is missing or dirty';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname='tenants' AND relrowsecurity AND relforcerowsecurity) THEN
    RAISE EXCEPTION 'tenant RLS/FORCE RLS missing';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='tenant_isolation_tenants') THEN
    RAISE EXCEPTION 'tenant RLS policy missing';
  END IF;
END
$$;
SQL
echo "Restore drill passed. Restored instance was reachable on 127.0.0.1:$port and schema/RLS checks succeeded."
