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

---

## 5. Pre-Staging Migration Chain Audit & Repair

Prior to the initial application of migrations onto the staging Supabase PostgreSQL database (initial version `nil`), an exhaustive audit and execution pass was performed across all 61 migration pairs against a clean PostgreSQL 16 database.

### Audited Defect Register & Resolution

1. **Migration 000060 (`000060_performance_indexing_and_capacity`)**:
   - *Findings Multi-Tenant Triage Index*: Repaired column reference from `organization_id` to canonical `tenant_id` (`findings (tenant_id, severity, status, created_at DESC)`).
   - *Assessment-to-Finding Composite Index*: Replaced non-existent `assessment_findings` table with direct assessment join index on `findings (tenant_id, assessment_id)`.
   - *Evidence Lookup Index*: Added leading `tenant_id` column to index (`evidence (tenant_id, finding_id, created_at DESC)`) preserving strict tenant isolation boundaries.
   - *Audit Timeline Index*: Replaced non-existent `audit_events (organization_id, timestamp)` with valid schema reference `audit_log (tenant_id, created_at DESC)`.
   - *Assessment Queue Scheduling Index*: Corrected lowercase partial index predicate `('queued', 'scheduled')` to the canonical uppercase assessment enum status `WHERE status = 'QUEUED'`.
   - *Down Migration Symmetry*: Ensured `000060.down.sql` cleanly and idempotently drops all 5 repaired indexes.

2. **Migration 000061 (`000061_standardize_tenant_rls_and_job_store`)**:
   - *Table Name Correction*: Corrected non-existent table reference `remediation_notes` to `remediation_updates`.
   - *RLS Policy Normalization*: Replaced non-permissive `AS RESTRICTIVE` policies on Phase 3 tenant tables (`remediation_tasks`, `remediation_updates`, `finding_risk_history`, `finding_evidence_links`, `report_snapshots`, `report_artifacts`, `evidence`) with standard permissive policies bound to `current_tenant_id()`. This resolved an issue where non-superuser application roles (`kelvin_app`) were rejected by PostgreSQL due to lack of permissive policies.
   - *True Rollback Implementation*: Updated `000061.down.sql` to explicitly revert `FORCE ROW LEVEL SECURITY` to `NO FORCE` on the 6 newly forced tables, while preserving `FORCE` on tables that had it in earlier migrations (`000001`, `000003`, `000005`).

3. **Pre-requisite Upstream Schema Alignment (Migrations 000010, 000017, 000036)**:
   - *Migration 000010*: Renamed unique constraint `uq_correlation_groups_id_tenant` to `uq_finding_correlation_groups_id_tenant` on `finding_correlation_groups` to resolve naming collision with `correlation_groups`.
   - *Migration 000017 & 000036*: Added safe column additions (`ADD COLUMN IF NOT EXISTS`) and aligned down migrations to support running the full chain on fresh databases where `evidence` and `scan_profiles` were originally scaffolded in migration 000001.

### Verified Invariants

- **Execution Tested**: The full migration chain from version 000001 to 000061 applies cleanly from scratch without errors.
- **Rollback Tested**: Step-wise rollbacks (`Steps(-1)`) cleanly revert 000061 to 000060 and 000060 to 000059, and reapply cleanly back to 000061.
- **Tenant Isolation Tested**: Cross-tenant data reads, mutations, and deletions across two isolated tenants under role `kelvin_app` are strictly denied by PostgreSQL RLS. Missing tenant context fails closed (0 rows).

