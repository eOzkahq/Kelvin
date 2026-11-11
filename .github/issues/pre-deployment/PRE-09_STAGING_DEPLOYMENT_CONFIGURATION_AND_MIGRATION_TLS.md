# PRE-09 — Staging Deployment Configuration and Migration TLS

**Project:** KELVIN — Enterprise Security Assessment Platform  
**Type:** `kind/infra` (Deployment / Database Infrastructure Hardening)  
**Priority:** `P0 — Critical`  
**Milestone:** [Milestone 9: Pre-Deployment Production Hardening](../../MILESTONES.md)  
**Phase:** Pre-Deployment Engineering Hardening  
**Labels:** `infrastructure`, `staging`, `tls`, `database`, `docker`, `production-readiness`  
**Status:** `ready-for-dev`  

---

## 🎯 1. Objective

Make KELVIN deployable with:
- Supabase PostgreSQL over verified TLS (`sslmode=verify-full`)
- Supabase private Storage (`kelvin-reports` and `kelvin-evidence`)
- Managed Redis over TLS (`rediss://`)
- Oracle Linux ARM64 (1 OCPU / 6 GB RAM resource profile)
- Go API and scanner worker containers (non-root, read-only rootfs)
- Vercel-hosted frontend (restricted CORS origins)
- Keep the existing local development Docker Compose setup functional.

---

## 📐 2. Implementation Scope

1. **Migration TLS Correction**:
   - Remove insecure implicit `sslmode=disable` fallback in `Migrator.instance()`.
   - Missing SSL mode produces a clear error in staging/production.
   - Production and staging require `sslmode=verify-full`.
   - Validate `sslrootcert` CA path existence and trust.
   - Redact credentials in all error messages.

2. **Staging PostgreSQL Configuration**:
   - Apply verified TLS (`sslmode=verify-full`) requirement to staging environment in `config.Load()`.
   - Configure Oracle VM connection pool defaults: max 5, min 1 in staging/production (dev remains 25/5).
   - Reject weak/default JWT secrets and evidence signing keys in staging.

3. **Staging Docker Compose Deployment**:
   - Create `deploy/staging/docker-compose.yml` (root `docker-compose.yml` remains untouched).
   - Only API and Worker containers; no local Postgres, Redis, MinIO, or mock-target.
   - Non-root user `10001:10001`, read-only rootfs, tmpfs `/tmp`, log rotation `50m`/`5`.
   - API bound strictly to loopback `127.0.0.1:8080:8080`.
   - Total resource limits: 1.0 CPU, 5.1 GB RAM. Worker concurrency = 1.
   - Do NOT mount `/var/run/docker.sock`.

4. **One-Shot Staging Migration Workflow**:
   - Provide `apps/api/cmd/migrate` CLI supporting `up`, `down`, `version`, `force`.
   - Provide `deploy/staging/migrate.sh`.
   - Refuse migration if dirty state is detected; report starting and ending versions.

5. **API Storage Fail-Fast**:
   - Fail fatal on startup if Supabase storage cannot be used in staging/production.
   - Update `ValidateDependencies(isProduction)` to enforce `storageProvider`.

6. **Documentation**:
   - `docs/deployment/STAGING_COMPOSE.md`
   - `docs/deployment/STAGING_DATABASE_MIGRATIONS.md`
   - `docs/deployment/STAGING_ENVIRONMENT.md`
