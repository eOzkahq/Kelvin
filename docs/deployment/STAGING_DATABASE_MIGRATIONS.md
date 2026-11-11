# KELVIN Staging Database Migrations Guide (PRE-09)

## 1. Overview

Database schema migrations in KELVIN are strictly managed via `golang-migrate` versioned SQL files located in `apps/api/db/migrations/`. In staging and production environments, migrations must satisfy rigorous security standards:
- **Mandatory TLS**: Explicit `sslmode=verify-full`.
- **Root CA Trust**: Supabase Root CA verification (`sslrootcert`).
- **No Credential Leakage**: Connection URLs are redacted in all logs and CLI output.
- **Dirty State Prevention**: Fail-fast guardrails prevent applying migrations onto a dirty schema state.

---

## 2. Supabase Connection & Pooler Considerations

> [!IMPORTANT]
> **Direct vs. Pooled Connections for Migrations:**
> Supabase provides two connection endpoints:
> 1. **Direct Connection (Port 5432)**: Connects directly to the PostgreSQL instance. **Always use Port 5432 for running migrations.** DDL commands (such as creating tables, indexes, constraints, and advisory locks) require direct session capabilities and advisory lock support.
> 2. **Transaction Pooler (Port 6543 / Supavisor / PgBouncer)**: Transaction-mode poolers multiplex client connections and do **not** support session-level advisory locks or prepared statements. Do **not** use the transaction pooler for executing schema migrations.

### Connection URL Format
```text
postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres?sslmode=verify-full&sslrootcert=/etc/ssl/certs/supabase-ca.crt
```

---

## 3. One-Shot Migration CLI (`apps/api/cmd/migrate`)

KELVIN includes a purpose-built Go migration CLI tool in `apps/api/cmd/migrate`.

### Commands
- `up`: Applies all unapplied schema migrations to the latest version.
- `down [N]`: Rolls back the last N migrations (default 1).
- `version`: Reports the current applied schema version and dirty flag.
- `force <version>`: Resets dirty migration status and forces schema version (disaster recovery).

### Operational Workflow Diagram

```mermaid
flowchart TD
    Start["Run 'migrate.sh up'"] --> ReadEnv["Load KELVIN_DATABASE_URL & Environment"]
    ReadEnv --> CheckTLS{"sslmode=verify-full & CA cert valid?"}
    CheckTLS -- No --> FailClosed["Abort: Insecure TLS or Missing CA"]
    CheckTLS -- Yes --> CheckVersion["Query schema_migrations Table"]
    CheckVersion --> Dirty{"Schema dirty == true?"}
    Dirty -- Yes --> FailDirty["Abort: Dirty Schema Detected<br/>Manual intervention & 'force' required"]
    Dirty -- No --> Apply["Apply Migrations Up"]
    Apply --> VerifyVersion["Verify Final Version & Log Output"]
    VerifyVersion --> Success["Exit 0"]
```

---

## 4. Execution Procedures

### Applying Migrations on Oracle Linux ARM64
On Oracle Linux 9, user `opc` typically executes container commands via `sudo`. The migration runner automatically supports this via `DOCKER_CMD`:

```bash
# 1. Source staging environment variables (chmod 0600)
set -a
source /etc/kelvin/staging.env
set +a

# 2. Check current schema version using sudo Docker Compose
./deploy/staging/migrate.sh version
# Or explicitly specifying sudo docker:
DOCKER_CMD="sudo docker" ./deploy/staging/migrate.sh version
# Or directly via sudo docker compose:
sudo docker compose -f deploy/staging/docker-compose.yml run --rm \
  -v "${SUPABASE_CA_CERT_PATH}:${SUPABASE_CA_CERT_PATH}:ro" \
  migrate version

# 3. Execute one-shot schema migration up
./deploy/staging/migrate.sh up
```

### PostgreSQL TLS & CA Certificate Mounting
- **Verified TLS**: The connection URL must strictly contain `sslmode=verify-full`.
- **System & Custom Root CAs**: On Oracle Linux hosts, the system CA bundle resides at `/etc/pki/tls/certs/ca-bundle.crt`.
- **Container Path Alignment**: `migrate.sh` validates that `SUPABASE_CA_CERT_PATH` exists on the host and mounts it read-only at the identical container path (`-v "${SUPABASE_CA_CERT_PATH}:${SUPABASE_CA_CERT_PATH}:ro"`), ensuring that any `sslrootcert` URL query parameter or `KELVIN_DATABASE_SSL_ROOT_CERT` environment variable resolves correctly within the container.

### Rollback Expectations & Procedure
If an issue arises after applying a migration, rollback should be executed step-by-step:
```bash
# Roll back the single most recent migration (e.g. 1 step)
./deploy/staging/migrate.sh down 1

# Verify new schema version
./deploy/staging/migrate.sh version
```

### Handling Dirty State Recovery
If a migration fails mid-flight (e.g., due to syntax error or timeout), `schema_migrations` marks `dirty = true`. In this state, any further `up` attempts will fail-fast to prevent database corruption.

To recover:
1. Review PostgreSQL logs to identify which SQL statement failed.
2. Connect directly via `psql` and resolve the schema state manually (e.g. drop partially created table or index).
3. Force the migration version back to the last known good version:
   ```bash
   ./deploy/staging/migrate.sh force 60
   ```
4. Verify the dirty flag is cleared:
   ```bash
   ./deploy/staging/migrate.sh version
   ```
5. Fix the migration script and re-run `./deploy/staging/migrate.sh up`.
