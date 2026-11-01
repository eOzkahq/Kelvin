# Kelvin Security Platform — Secrets Management & CI/CD Injection Procedures

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Active |
| **Milestone** | Phase 1 — Foundation & Core Architecture (`P1-15`) |
| **Related Docs** | `docs/architecture/decisions/ADR-0001.md` through `ADR-0003.md`, `docs/security/THREAT_MODEL.md`, `docs/development/LOCAL_SETUP.md` |
| **Owner** | Platform Engineering / Product Security |

---

## 1. Executive Summary & Principles

The Kelvin Security Platform processes sensitive vulnerability findings, asset network locations, and assessment targets. Storing plaintext secrets in repository files, environment commits, or observability logs introduces critical risks of data leakage and infrastructure compromise (STRIDE threats T-02, T-05, T-09).

Kelvin enforces the following immutable security principles:
1. **Zero Repository Secrets:** No production, staging, or integration credentials, private keys, or API tokens may ever be committed to git.
2. **Fail-Fast Startup Validation:** Services parse and validate typed configurations via `spf13/viper` at boot time; any missing required secrets immediately abort execution before network sockets or jobs are accepted.
3. **Automated Log Redaction:** All application log output is intercepted via `packages/common/logging` (zap interceptor) to automatically redact keys matching known sensitive patterns (`password`, `token`, `secret`, `key`, `auth`, `jwt`).
4. **Environment Segregation:** Separate credentials across `development`, `testing`, `staging`, and `production` environments via `KELVIN_ENV`. Staging and production strictly enforce external configuration injection.

---

## 2. Configuration & Secrets Hierarchy

Every secret in Kelvin is modeled as a typed field in Go configuration structs (`apps/api/internal/config` and `apps/worker/internal/config`):

| Variable | Target Subsystem | Sensitivity | Production Default |
| :--- | :--- | :--- | :--- |
| `KELVIN_DATABASE_URL` | PostgreSQL (ADR-0002) | **High (Secret)** | *None — Must be injected* |
| `POSTGRES_PASSWORD` | PostgreSQL (Dev Stack) | **High (Secret)** | *None — Must be injected* |
| `KELVIN_REDIS_PASSWORD` | Redis Broker (ADR-0003) | **High (Secret)** | *None — Must be injected* |
| `MINIO_ROOT_PASSWORD` / S3 Secret | Object Store (Evidence) | **High (Secret)** | *None — Must be injected* |
| `KELVIN_JWT_SECRET` | API access-token verification | **Critical (Key)** | Required in staging/production, at least 32 bytes; inject from a secret manager. Optional in development; protected routes fail closed without it. |

---

## 3. Secret Rotation Procedures

### 3.1 Relational Database Credentials (`KELVIN_DATABASE_URL`)
1. Create a secondary database user with identical role permissions (`kelvin_app`).
2. Update the secret value in the platform secret store (e.g., HashiCorp Vault / AWS Secrets Manager).
3. Trigger a rolling restart of the API control plane (`apps/api`) and worker fleet (`apps/worker`).
4. Verify application connectivity via `/healthz`.
5. Revoke and drop the retired database user role.

### 3.2 Redis Broker Credentials (`KELVIN_REDIS_PASSWORD`)
1. Add the new password to Redis ACL as an allowed secondary password (`ACL SETUSER kelvin on >newpass`).
2. Update `KELVIN_REDIS_PASSWORD` in the secret store.
3. Perform a zero-downtime rolling restart of worker daemons and control plane.
4. Remove the deprecated password from Redis ACL (`ACL SETUSER kelvin <oldpass`).

### 3.3 MinIO / S3 Storage Credentials
1. Issue a new access key / secret key pair with scoped IAM policies limited to `kelvin-evidence` and `kelvin-reports`.
2. Update `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` or cloud provider secrets.
3. Restart consumers; verify presigned URL generation and evidence blob upload.
4. Deactivate and delete the prior credential key.

---

## 4. CI/CD Secret Injection Expectations

1. **GitHub Actions & Automated Pipelines:**
   - Secrets are stored exclusively in GitHub Repository / Environment Secrets (`Settings -> Secrets and variables -> Actions`).
   - Staging and production deployment workflows inject environment variables dynamically at deploy time into container orchestration manifests or task definitions.
   - Pull request builds from forks do **not** receive access to environment secrets.

2. **Gitleaks / Secret Scanning:**
   - CI builds run automated secret scanning (e.g., `gitleaks`) on every commit and pull request.
   - Files matching `*.env`, `*.key`, `*.pem`, `*.cert` are strictly ignored by `.gitignore`. Only `.env.example` is committed.

---

## 5. Local Development vs. Production Guidelines

- In **development** (`KELVIN_ENV=development`), safe, pre-configured development secrets are documented in `.env.example` for zero-friction local onboarding with Docker Compose.
- In **production** (`KELVIN_ENV=production`), application startup fails immediately if `KELVIN_DATABASE_URL` is omitted or malformed.

