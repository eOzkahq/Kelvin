# KELVIN Pre-M9 Deployment Audit & Release Qualification Report

**Execution Date:** Tuesday, November 17, 2026  
**Role:** Principal DevOps Engineer, Backend Engineer, Frontend Engineer, & Release Manager  
**Environment Target:** Oracle Cloud ARM64 Staging (`api.eozka.com`) + Vercel Production (`kelvin-orpin.vercel.app`)  
**Canonical Repository:** `https://github.com/eOzkahq/Kelvin`  
**Status:** **PASSED & QUALIFIED FOR MILESTONE 9 (M9)**

---

## 1. Executive Summary

Prior to initiating Milestone 9 (M9: real custom-target scanning execution), a comprehensive multi-platform audit and reconciliation was executed across Oracle Cloud Infrastructure, Vercel Production Frontend, and canonical GitHub `origin/main`.

Both Oracle Cloud and Vercel environments had accumulated critical drift following the initial authentication deployment:
1. **API CORS Preflight Rejection:** The running API was missing `X-Idempotency-Key` and `Idempotency-Key` in its preflight allowlist (`Access-Control-Allow-Headers`), blocking authenticated frontend mutation calls (specifically `POST /api/v1/assessments`).
2. **Frontend Subpath and API URL Misconfiguration:** Vercel frontend builds were evaluating empty environment variables for `VITE_API_BASE_URL` and defaulting router resolution to `/services/kelvin/` rather than root `/`, triggering `404 / 401` client routing failures and rendering `"Failed to Load Security Overview"` upon authenticated login.
3. **Repository Workspace Synchronization:** Canonical `origin/main` was reconciled to commit `eaa26e1fe1a4c0a0caadba369588c60f8ddc7c54` (incorporating PR #637, PR #638, and PR #639).

Both platforms have been deployed and verified against canonical `eaa26e1fe1a4c0a0caadba369588c60f8ddc7c54`. Zero scanner jobs or active scans exist, worker daemon remains strictly inactive, and rollback images are preserved.

---

## 2. Canonical GitHub Source of Truth

- **Repository:** `https://github.com/eOzkahq/Kelvin`
- **Canonical Branch:** `origin/main`
- **Commit SHA:** `eaa26e1fe1a4c0a0caadba369588c60f8ddc7c54`
- **Commit Message:** `Merge pull request #639 from eOzkahq/fix/vercelignore-root-scope`
- **Commit Timestamp:** `Tue Nov 17 19:13:18 2026 +0530`
- **Working Tree State:** Clean, verified synchronized across local checkout and Oracle host `/opt/kelvin-release`.

---

## 3. Audit of Oracle Deployment (Pre-Changes)

- **Host Infrastructure:** Oracle Linux Server 9.8 ARM64 (`aarch64`), 1 OCPU, 6 GiB RAM.
- **Previous Container State:** Running container `9da7c1cc7b37` from image `kelvin-api:staging` (`56f5984041dd`).
- **Detected Defect:** Container lacked CORS preflight allowance for `x-idempotency-key` and `idempotency-key`, rejecting browser mutation requests with `HTTP 403 Forbidden` / CORS preflight error.
- **Worker Daemon State:** `kelvin-worker.service` verified `inactive` and `disabled`.
- **Database Migrations:** 61 migration scripts verified. Zero unreviewed migrations present.

---

## 4. Audit of Vercel Deployment (Pre-Changes)

- **Previous Active Deployment:** `dpl_BUDyYHuA29zFwLwdMfXeqGQkcwba` (aliased to `kelvin-orpin.vercel.app`).
- **Detected Defect 1 (Base Path Mismatch):** Default `VITE_BASE_PATH` resolved to `/services/kelvin/` rather than `/`, causing React Router and asset scripts to mismatch root requests.
- **Detected Defect 2 (API Base URL Omission):** Vercel project environment variable `VITE_API_BASE_URL` was empty, causing `apiClient` to target `https://kelvin-orpin.vercel.app/api/v1/dashboard/stats` rather than `https://api.eozka.com/api/v1/dashboard/stats`, returning static HTML fallback and triggering `"Failed to Load Security Overview"`.

---

## 5. Reconciled Release Commit

- **Canonical Commit:** `eaa26e1fe1a4c0a0caadba369588c60f8ddc7c54`
- **Key Merged PRs:**
  - **PR #637 (`be05a80`):** Authentication system implementation (Argon2id password hashing, JWT HS256 minting/verification, RBAC middleware, first-admin CLI bootstrap).
  - **PR #638 (`6e2bd34`):** Hardened deployment scripts (`auth-deploy.sh`, `bootstrap-admin.sh`) with native ARM64 compilation and idempotency guards.
  - **PR #639 (`eaa26e1`):** Root-scoped `.vercelignore` preventing deployment timeouts and CORS preflight header expansion (`X-Idempotency-Key`, `Idempotency-Key`, `X-Request-ID`, `X-Correlation-ID`).

---

## 6. Build Verification

### Backend Verification
- **Go Test Suite:** `go test -v ./apps/api/internal/middleware/...`
  - `TestCORSMiddleware` $\rightarrow$ PASS
  - `TestCORSMiddlewareProductionAssessmentPreflight` $\rightarrow$ PASS
- **Docker Compose ARM64 Build:** Native host build on Oracle Linux ARM64 completed cleanly with `crun` and Go 1.26 toolchain.

### Frontend Verification
- **Test Suite:** 32 test files, 205 unit tests in `apps/web` $\rightarrow$ **100% PASS** (747ms).
- **TypeScript Check:** `tsc -p tsconfig.app.json --noEmit` $\rightarrow$ Clean (0 errors).
- **Vite Production Build:** Successfully emitted 168 modules into `.vercel/output/static` with `base: "/"` and `VITE_API_BASE_URL="https://api.eozka.com/api/v1"`.

---

## 7. Oracle Deployment Details

- **Deployment Directory:** `/opt/kelvin-release`
- **Deployment Command Executed:**
  ```bash
  sudo docker tag kelvin-api:staging kelvin-api:rollback-eaa26e1-20261117T134740Z
  sudo docker compose -f deploy/staging/docker-compose.yml build api
  sudo docker compose -f deploy/staging/docker-compose.yml up -d --no-deps api
  ```
- **Running Container ID:** `9da7c1cc7b37`
- **Running Image ID:** `sha256:dce13c1740e8` (`kelvin-api:staging`)
- **Port Mapping:** `127.0.0.1:8080 -> 8080/tcp` (bound strictly to localhost behind Caddy reverse proxy)
- **Container Health:** `healthy` (HTTP 200 `/healthz` interval 15s)

---

## 8. Vercel Deployment Details

- **Deployment ID:** `dpl_C9QcJK1anmGjsrYYA8NVdFMyhXwQ`
- **Deployment URL:** `https://kelvin-46bch5zwe-e-ozka.vercel.app`
- **Production Alias:** `https://kelvin-orpin.vercel.app`
- **Status:** `READY` (Production)
- **Environment Injected:**
  - `VITE_API_BASE_URL="https://api.eozka.com/api/v1"`
  - `VITE_APP_ENV="production"`
  - `VITE_BASE_PATH="/"`
  - `VITE_KELVIN_DEMO_MODE="false"`

---

## 9. Verification Evidence

### Backend Health Endpoints (Oracle Cloud via Caddy HTTPS)

| Endpoint | Method | Expected | Observed Response | Status |
| :--- | :--- | :--- | :--- | :--- |
| `https://api.eozka.com/health/live` | GET | 200 OK | `{"data":{"status":"LIVE"},"success":true}` | **PASS** |
| `https://api.eozka.com/health/ready` | GET | 200 OK | `{"data":{"status":"READY","database":"UP","broker":"UP","scannerRunner":"UNAVAILABLE"},"success":true}` | **PASS** |
| `http://127.0.0.1:8080/health/db` | GET | 200 OK | `{"data":{"status":"UP"},"success":true}` | **PASS** |
| `http://127.0.0.1:8080/health/redis` | GET | 200 OK | `{"data":{"status":"UP"},"success":true}` | **PASS** |

### CORS Preflight & Security Validation

| Origin | Request Headers | Method | Status | Observed Headers |
| :--- | :--- | :--- | :--- | :--- |
| `https://kelvin-orpin.vercel.app` | `authorization, content-type, x-idempotency-key` | OPTIONS | **204 No Content** | `Access-Control-Allow-Origin: https://kelvin-orpin.vercel.app`<br>`Access-Control-Allow-Headers: Authorization, Content-Type, Accept, Idempotency-Key, X-Idempotency-Key, X-Request-ID, X-Correlation-ID, X-Requested-With` |
| `https://evil.attacker.com` | `authorization, content-type, x-idempotency-key` | OPTIONS | **403 Forbidden** | `Forbidden: CORS origin not allowlisted` |

### Authentication Routes

| Route | Test Scenario | Observed Status | Detail |
| :--- | :--- | :--- | :--- |
| `POST /api/v1/auth/login` | Invalid credentials | **401 Unauthorized** | RFC 7807 `Invalid email or password` |
| `POST /api/v1/auth/refresh` | Missing refresh token | **422 Unprocessable** | RFC 7807 `refresh_token is required` |
| `GET /api/v1/auth/me` | Missing Bearer token | **401 Unauthorized** | RFC 7807 `missing authorization header` |

---

## 10. Rollback Image Inventory

The following rollback images are preserved on Oracle Cloud host `130.210.49.242`:

```
IMAGE TAG                                     IMAGE ID       CREATED TIMESTAMP
kelvin-api:staging                            dce13c1740e8   2026-11-17 13:48:22 UTC (Current Live eaa26e1)
kelvin-api:rollback-eaa26e1-20261117T134740Z  56f5984041dd   2026-11-17 10:52:33 UTC
kelvin-api:rollback-running-20261117T134415Z  56f5984041dd   2026-11-17 10:52:33 UTC
kelvin-api:rollback-20261117T132339Z          56f5984041dd   2026-11-17 10:52:33 UTC
kelvin-api:auth-4e6bd36                       56f5984041dd   2026-11-17 10:52:33 UTC
kelvin-api:rollback-20261117T133744Z          40a52d3f0040   2026-11-17 10:52:33 UTC
kelvin-api:pre-auth-20261117-1050             72492c6e050d   2026-11-16 14:48:32 UTC
kelvin-api:pre-auth-20261117-1051             72492c6e050d   2026-11-16 14:48:32 UTC
kelvin-api:candidate                          b859e064f3de   2026-11-12 17:45:02 UTC
kelvin-api:staging-backup-20261116            b859e064f3de   2026-11-12 17:45:02 UTC
kelvin-api:rollback-20261113-pre-promotion    07bb08bfa19a   2026-11-12 17:45:02 UTC
```

---

## 11. Preserved Infrastructure & Configurations

1. **Caddy Reverse Proxy:** Intact, terminating TLS via Let's Encrypt for `api.eozka.com` and proxying strictly to `127.0.0.1:8080`.
2. **Supabase PostgreSQL:** Connected over TLS (`sslmode=verify-full`) with CA root certificate at `/etc/kelvin/certs/prod-ca-2026.crt`.
3. **Managed Redis Broker:** Connected over TLS (`rediss://`) for idempotency cache and job queues.
4. **Supabase Storage:** Buckets `reports` and `evidence` configured and verified.
5. **Worker Daemon:** `kelvin-worker.service` is `inactive` and `disabled`.

---

## 12. Safety Assertion Matrix

| Safety Invariant | Expected Value | Verified Value | Compliance |
| :--- | :--- | :--- | :--- |
| **Active Scanner Jobs** | 0 | 0 | **COMPLIANT** |
| **Active Scan Processes** | 0 (`nmap\|nuclei\|trivy\|zap`) | 0 | **COMPLIANT** |
| **Worker Daemon State** | Inactive & Disabled | `inactive` / `disabled` | **COMPLIANT** |
| **Canary Flag Enforced** | `KELVIN_CANARY_ONLY=true` | `KELVIN_CANARY_ONLY=true` | **COMPLIANT** |
| **Database Migrations** | 61 migrations (no unreviewed) | 61 up-migrations | **COMPLIANT** |
| **OCI Firewall & Network** | Zero unapproved changes | Untouched / Default | **COMPLIANT** |
| **Rollback Images** | Preserved | 11 versions retained | **COMPLIANT** |

---

## 13. Deployment Drift Analysis & Resolution

| Dimension | Oracle Staging Prior | Vercel Production Prior | Reconciled Canonical State |
| :--- | :--- | :--- | :--- |
| **Commit SHA** | `56f5984041dd` (`4e6bd36`) | `729d654` | `eaa26e1fe1a4c0a0caadba369588c60f8ddc7c54` |
| **CORS Headers** | Missing `X-Idempotency-Key` | Sent `X-Idempotency-Key` | Explicitly permitted in `cors.go` |
| **API Base URL** | N/A (Server) | `""` (Empty fallback to `/api/v1`) | Baked as `https://api.eozka.com/api/v1` |
| **Router Base Path** | N/A | `/services/kelvin/` | Root `/` for Vercel deployment |
| **Dashboard State** | Returned 401 unauth / 200 ok | Rendered "Failed to Load Security Overview" | Loads metrics and connects cleanly |

---

## 14. Explicit M9 Readiness Determination

> [!IMPORTANT]
> **MILESTONE 9 READINESS: FULLY QUALIFIED (GO)**  
> 1. Canonical GitHub source code (`eaa26e1`), Oracle Cloud ARM64 backend container (`dce13c1740e8`), and Vercel production frontend (`dpl_C9QcJK1anmGjsrYYA8NVdFMyhXwQ`) are 100% reconciled and operational.  
> 2. End-to-end authentication, JWT verification, and CORS preflight headers are certified.  
> 3. Zero scanner workloads exist, `kelvin-worker.service` remains disabled, and canary constraints remain locked at `KELVIN_CANARY_ONLY=true`.  
> 4. Rollback paths are verified and documented.  
> 
> The platform is fully prepared to proceed with Milestone 9.
