# Kelvin Security Platform — Database Migrations & Schema Management

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Active — Engineering Specification |
| **Milestone** | Phase 1 — Foundation & Core Architecture (`P1-20`) |
| **Related Docs** | `docs/architecture/decisions/ADR-0002.md`, `docs/architecture/DATA_MODEL.md`, `docs/development/LOCAL_SETUP.md` |
| **Owner** | Platform Engineering / Data Engineering |

---

## 1. Executive Summary & Principles

The Kelvin Security Platform enforces transactional, version-controlled database schema migrations. Ad-hoc DDL queries or ORM auto-synchronization (`synchronize: true`) are strictly prohibited across all environments.

Key architectural guarantees:
1. **Immutable & Reversible:** Every migration consists of an `.up.sql` file applying schema changes and a corresponding `.down.sql` file providing a clean, deterministic rollback.
2. **Schema Drift Detection:** `golang-migrate` tracks applied versions and dirty state in the `schema_migrations` table. If a dirty state or unexpected checksum drift occurs, application startup halts immediately.
3. **Mandatory Row-Level Security (RLS):** All tenant-owned tables must enable and force Row-Level Security (`ALTER TABLE ... FORCE ROW LEVEL SECURITY`) with policies enforcing `tenant_id = current_tenant_id()`.
4. **Append-Only Audit Protection:** The `audit_log` table must strictly prohibit `UPDATE` and `DELETE` grants from application roles (`kelvin_app`).

---

## 2. Directory Hierarchy

Migration files and development seeds are version-controlled in `apps/api/db/`:

```
apps/api/db/
├── migrations/
│   ├── 000001_initial_schema.up.sql    # Core tables, constraints, indexes & RLS policies
│   └── 000001_initial_schema.down.sql  # Clean rollback script
└── seeds/
    └── 001_dev_seed.sql                # Seed data for local development (tenants, users, profiles)
```

---

## 3. Migration File Naming Convention

Migration files follow the sequential 6-digit prefix format required by `golang-migrate`:

```
<version>_<short_description>.up.sql
<version>_<short_description>.down.sql
```

Example:
- `000001_initial_schema.up.sql`
- `000001_initial_schema.down.sql`
- `000002_add_scanner_profiles.up.sql`
- `000002_add_scanner_profiles.down.sql`

---

## 4. Local Execution & Tooling

### 4.1 Automated Migrations via Docker Compose
When spinning up the local environment, the `migrate` service container runs migrations automatically upon PostgreSQL readiness:

```bash
docker compose up -d
```

### 4.2 Running Migrations Manually via CLI
If you have `golang-migrate` CLI installed locally:

```bash
# Run all pending migrations
migrate -path apps/api/db/migrations -database "$KELVIN_DATABASE_URL" up

# Roll back the last migration step
migrate -path apps/api/db/migrations -database "$KELVIN_DATABASE_URL" down 1

# Check current version
migrate -path apps/api/db/migrations -database "$KELVIN_DATABASE_URL" version
```

### 4.3 Applying Development Seed Data
To populate a clean database with mock tenants, administrators, and default scan profiles:

```bash
# Via psql
psql "$KELVIN_DATABASE_URL" -f apps/api/db/seeds/001_dev_seed.sql

# Via Docker
docker exec -i kelvin-postgres psql -U kelvin -d kelvin_dev < apps/api/db/seeds/001_dev_seed.sql
```

---

## 5. Schema Rollback Procedures

If a deployment fails or a rollback is triggered:

1. **Step-Back Rollback:**
   ```bash
   migrate -path apps/api/db/migrations -database "$KELVIN_DATABASE_URL" down 1
   ```
2. **Forced Version Reset (Dirty State Recovery):**
   If a migration failed midway leaving the database in a dirty state:
   ```bash
   # Fix the underlying SQL error or data constraint
   # Force the migration version (e.g. to version 1)
   migrate -path apps/api/db/migrations -database "$KELVIN_DATABASE_URL" force 1
   ```

---

## 6. Programmatic Connection Pooling (`jackc/pgx/v5`)

The API control plane utilizes `jackc/pgx/v5/pgxpool` via `apps/api/internal/database`:

- **Pool Tuning:** Configurable `MaxConns`, `MinConns`, `MaxConnLifetime`, and `MaxConnIdleTime`.
- **Tenant Context Setting:** Transactional helper `SetTenantContext(ctx, tx, tenantID)` sets `SET LOCAL app.tenant_id = '<uuid>'` per-request before executing queries under RLS.
- **Fail-Closed Guarantee:** If `app.tenant_id` is unset, `current_tenant_id()` returns NULL, resulting in zero rows returned for all RLS-protected queries.

