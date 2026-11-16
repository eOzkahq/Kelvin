# KELVIN MILESTONE 8 — FINAL DEPLOYMENT EVIDENCE & STABILIZATION REPORT

**Document ID**: `KELVIN-M8-DEP-EVID-001`  
**Date**: November 16, 2026  
**Environment**: Staging (`staging.eozka.com` / `api.eozka.com`)  
**Canonical Repository**: `https://github.com/eOzkahq/Kelvin`  
**Deployed Canonical Commit**: `e42186d357f4f0e2a08a8a7e4ab24cdd0f99bc85` (includes PR #635)  
**Governance Policy**: ADR-0008 (Rootless Execution Plane Isolation)  
**Status**: **DEPLOYED & OPERATIONALLY STABILIZED (GATED)**  

---

## 1. Executive Summary

Milestone 8 ("Live Staging Deployment & Operational Verification") is complete and verified. The staging environment has been brought from a pre-Milestone 7 baseline into a fully deployed, operationally verified state:

1. **Control Plane API**: Natively compiled on Oracle Linux 9.8 ARM64 from canonical commit `e42186d357f4f0e2a08a8a7e4ab24cdd0f99bc85`, packaged into hardened container `kelvin-staging-api`, and hot-swapped with zero downtime.
2. **Frontend SPA**: Deployed to Vercel production at `https://kelvin-orpin.vercel.app`, with verified CORS connectivity (`204 No Content` preflight) and authenticated API proxy routing.
3. **Execution Plane Worker**: Audit complete (14/14 ADR-0008 prerequisites passing). Statically linked ARM64 binary `/opt/kelvin/bin/kelvin-worker` installed with mode `0755`. Configuration `/etc/kelvin/worker.env` secured at mode `0600` (`kelvin-worker:kelvin-worker`) with canary targets restricted exclusively to internal mock services.
4. **Safety & Gating**: Service `kelvin-worker.service` remains **strictly inactive and disabled**. Zero scanner jobs have been enqueued, dispatched, or executed. Zero database migrations were run. `KELVIN_CANARY_ONLY=true` is enforced across all services.

---

## 2. Component Verification Matrix

| Component | Target Platform | Deployed Identifier / Hash | Service / Process State | Operational Verification | Result |
|---|---|---|---|---|---|
| **Control Plane API** | Oracle Linux 9.8 (ARM64) | Image: `sha256:72492c6e...`<br>Commit: `e42186d357...` | Container: `kelvin-staging-api`<br>PID 1298318 (`/sbin/tini -- /app/kelvin-api`) | `/health/live`: `200 OK`<br>`/health/ready`: `200 OK` (DB+Broker UP) | **VERIFIED** |
| **Assessment APIs** | Oracle Linux 9.8 (ARM64) | Milestone 7 HTTP Routing Tree | Subsystem in `kelvin-staging-api` | `/api/v1/assessments/profiles`: `401 Unauthorized`<br>`POST /api/v1/assessments`: `401 Unauthorized` | **VERIFIED** |
| **Frontend Web App** | Vercel Serverless CDN | `prj_SuKGeP2gvvoXClmmrzoB7XmxgX59`<br>Commit: `5682088` (M7 Frontend) | Production Deployment<br>`https://kelvin-orpin.vercel.app` | `200 OK` HTML/JS served<br>CORS Preflight `204 No Content` | **VERIFIED** |
| **Reverse Proxy** | Oracle Host (Caddy) | Systemd: `caddy.service` | `active (running)`, Port 443 TLS | Automatic TLS certificate renewal<br>Reverse proxy to `127.0.0.1:8080` | **VERIFIED** |
| **Primary Database** | Supabase Cloud | PostgreSQL 15 Pooler (TLS) | Verified via API probe: `database: UP` | 61 migrations intact; zero changes applied | **VERIFIED** |
| **Task Broker** | Upstash Redis | Managed Redis TLS (`rediss://`) | Verified via API probe: `broker: UP` | Queue streams intact; zero pending jobs | **VERIFIED** |
| **Execution Worker** | Oracle Host (Systemd) | Binary: `/opt/kelvin/bin/kelvin-worker`<br>(ARM64 ELF, 8.9 MB, mode 0755) | Systemd: `kelvin-worker.service`<br>**INACTIVE (DEAD), DISABLED** | Host audit: 14/14 checks passed<br>Service deliberately held inactive | **STABILIZED (HELD)** |

---

## 3. Live API Endpoint Evidence

All endpoints were queried live against production domain `https://api.eozka.com` and reverse-proxy loopback `127.0.0.1:8080`:

### Liveness Probe (`GET /health/live`)
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"data":{"status":"LIVE"},"success":true}
```

### Readiness Probe (`GET /health/ready`)
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"data":{"status":"READY","database":"UP","broker":"UP","scannerRunner":"UNAVAILABLE","timestamp":"2026-11-16T15:09:24Z"},"success":true}
```
*(Note: `scannerRunner: UNAVAILABLE` is the expected architecture state under ADR-0008; the API container has no Docker socket access and communicates with the host worker exclusively through Redis Streams)*.

### Milestone 7 Assessment Profiles (`GET /api/v1/assessments/profiles`)
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json

{"type":"urn:kelvin:problem:unauthenticated","title":"Unauthenticated","status":401,"detail":"missing authorization header","instance":"/api/v1/assessments/profiles","correlation_id":"07c4aa9c-bdce-4e30-b3f4-4c9ca2c68017","timestamp":"2026-11-16T14:49:24Z"}
```
*(Prior to Milestone 8 deployment, this endpoint returned `404 Not Found`. It is now fully routed and properly protected by Supabase JWT authentication middleware)*.

### Milestone 7 Target Management (`GET /api/v1/targets`)
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json
```

### Milestone 7 Dashboard Telemetry (`GET /api/v1/dashboard/stats`)
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json
```

### Milestone 7 Assessment Creation (`POST /api/v1/assessments`)
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json
```

### CORS Preflight (`OPTIONS /api/v1/assessments/profiles`)
```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://kelvin-orpin.vercel.app
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type, Idempotency-Key, X-Correlation-ID, X-Requested-With, Accept, Origin
Access-Control-Max-Age: 86400
Via: 1.1 Caddy
```

---

## 4. Rollback and Disaster Recovery Assets

Rollback images are verified and permanently available in the staging Docker image store:

| Repository & Tag | Image Digest | Size | Role | Status |
|---|---|---|---|---|
| `kelvin-api:staging` | `sha256:72492c6e...` | 59.1 MB | Active Production API (M8) | **RUNNING** |
| `kelvin-api:staging-backup-20261116` | `sha256:b859e064...` | 50.6 MB | Pre-M8 Staging Snapshot | **PRESERVED** |
| `kelvin-api:rollback-20261113-pre-promotion` | `sha256:07bb08bf...` | 50.6 MB | Certified Baseline Snapshot | **PRESERVED** |

### Rollback Runbook (Hot Reversion)
If API instability occurs prior to Milestone 9, revert immediately without rebuild:
```bash
sudo docker tag kelvin-api:staging-backup-20261116 kelvin-api:staging
sudo docker compose -f /opt/kelvin/deploy/staging/docker-compose.yml --env-file /etc/kelvin/staging.env up -d --no-deps api
```

---

## 5. Worker Recovery Audit & Stabilization State

The worker host environment was thoroughly audited under ADR-0008 Option A:

1. **Systemd Service Unit**: `/etc/systemd/system/kelvin-worker.service`
   * Dedicated unprivileged user: `kelvin-worker` (UID 10001:10001)
   * Process sandboxing: `NoNewPrivileges=true`, `ProtectSystem=strict`, `Delegate=yes`
   * Environment configuration: `EnvironmentFile=/etc/kelvin/worker.env`
   * Binary path: `/opt/kelvin/bin/kelvin-worker`
2. **Binary Installation**:
   * Path: `/opt/kelvin/bin/kelvin-worker`
   * Permissions: `0755` (`-rwxr-xr-x`), owned by `root:root`
   * Format: `ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped`
3. **Environment Hardening (`/etc/kelvin/worker.env`)**:
   * Mode: `0600` (`-rw-------`), owned by `kelvin-worker:kelvin-worker`
   * Canary mode: `KELVIN_CANARY_ONLY=true`
   * Allowed targets: Restricted strictly to approved internal mock targets:
     ```ini
     KELVIN_CANARY_ALLOWED_TARGETS=scanner-mock.kelvin.internal,mock-target.kelvin.internal
     ```
     *(Loopback addresses `127.0.0.1` and `localhost` have been stripped per stabilization requirements)*.
4. **Rootless Podman Runtime**:
   * Podman version: `5.8.2`
   * OCI Runtime: `crun 1.27`
   * Cgroups: `v2` (controllers `cpu`, `memory`, `pids` active and delegated)
   * Subordinate UID/GID: `165536:65536` verified in `/etc/subuid` and `/etc/subgid`
   * Internal scanner network: `kelvin-scanner-net` (Subnet `10.89.10.0/24`, `internal=true`)
5. **State Gating**:
   * `systemctl is-active kelvin-worker.service` -> `inactive`
   * `systemctl is-enabled kelvin-worker.service` -> `disabled`
   * Active rootless containers: `0`
   * Queued scanner jobs: `0`

---

## 6. Safety Attestation

* **KELVIN_CANARY_ONLY**: Enforced as `true` in all control-plane and worker configurations.
* **Scanner Dispatch**: Exactly zero scan jobs were enqueued, dispatched, or executed during Milestone 8.
* **Database State**: Zero migrations were executed; existing schemas and RLS tenant isolation policies are 100% untouched.
* **Network & Firewalls**: Zero changes made to public DNS, Caddy reverse-proxy certificates, or host firewalls.
* **Secret Redaction**: Zero credentials or private keys printed or committed to version control.

---

## 7. Hand-Off & Milestone 9 Gateway

The system is in a stable, deployed, and quiescent state:
* The control-plane API and frontend SPA are live, serving, and verified.
* The execution-plane worker is fully configured, validated, and ready for activation upon separate Milestone 9 canary execution authorization.
