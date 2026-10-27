# Kelvin Security Platform — Local Development Setup Guide

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Active |
| **Milestone** | Phase 1 — Foundation & Core Architecture (`P1-14`) |
| **Related Docs** | `docs/architecture/decisions/ADR-0001.md` through `ADR-0003.md`, `docs/architecture/DATA_MODEL.md`, `docs/security/ACCEPTABLE_USE.md` |
| **Owner** | Platform Engineering |

---

## 1. Prerequisites

Before setting up Kelvin locally, ensure your workstation meets the following runtime requirements:

| Tool | Version | Purpose |
| :--- | :--- | :--- |
| **Docker Engine & Docker Compose** | Docker 24+ / Compose v2.20+ | Local container orchestration (PostgreSQL, Redis, MinIO, Mock Lab Target) |
| **Go (Golang)** | Go 1.22+ | Backend API control plane (`apps/api`) and worker daemon (`apps/worker`) |
| **Node.js & npm** | Node 20+ (LTS) & npm 10+ | Web dashboard frontend (`apps/web`) and schema validation scripts |
| **Git** | 2.30+ | Version control |

---

## 2. Architecture & Service Topology

Kelvin uses Docker Compose to orchestrate dependencies locally in a completely reproducible, containerized environment:

```
+---------------------------------------------------------------------------------+
|                               Developer Workstation                             |
|                                                                                 |
|   apps/api (Go :8080)   apps/web (Vite :5173)   apps/worker (Go Runner)         |
+---------------------------------------------------------------------------------+
                                       │
                              (docker compose up -d)
                                       ▼
+─────────────────────────────────────────────────────────────────────────────────+
|                           Docker Network (kelvin-net)                           |
|                                                                                 |
|  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────────────────┐  |
|  │ PostgreSQL 15+    │  │ Redis 7+          │  │ MinIO S3 Mock               │  |
|  │ - Port: 5432      │  │ - Port: 6379      │  │ - API Port: 9000            │  |
|  │ - RLS Enabled     │  │ - AOF Enabled     │  │ - Console: 9001             │  |
|  │ - golang-migrate  │  │ - noeviction      │  │ - Buckets: evidence/reports │  |
|  └───────────────────┘  └───────────────────┘  └─────────────────────────────┘  |
|                                                                                 |
|  ┌───────────────────────────────────────────────────────────────────────────┐  |
|  │ Mock Vulnerable Target (Isolated Sandboxed Lab)                           │  |
|  │ - Port: 8081 (Host) / 8080 (Container)                                    │  |
|  │ - Endpoints: /vulnerable/headers, /vulnerable/xss, /vulnerable/sqli       │  |
|  │ - Purpose: Safe local scanner testing without touching external networks  │  |
|  └───────────────────────────────────────────────────────────────────────────┘  |
+─────────────────────────────────────────────────────────────────────────────────+
```

---

## 3. Quickstart: 1-Command Environment Bootstrap

### Step 1: Clone and Configure Environment

```bash
# Clone the repository
git clone https://github.com/kelvin/kelvin.git
cd kelvin

# Copy the documented environment configuration
cp .env.example .env
```

### Step 2: Spin Up Infrastructure Containers

```bash
docker compose up -d
```

This single command:
1. Provisions **PostgreSQL 15+** with database health checks.
2. Runs **golang-migrate** against PostgreSQL, creating the full relational schema with Row-Level Security (RLS) tables and policies.
3. Provisions **Redis 7+** with Append-Only File (AOF) persistence and `noeviction` policy (matching ADR-0003).
4. Spins up **MinIO S3** and initializes required storage buckets (`kelvin-evidence`, `kelvin-reports`).
5. Launches the **Mock Vulnerable Target Lab** container on `http://localhost:8081`.

### Step 3: Check Container Health

```bash
docker compose ps
```

All services will show `healthy`.

---

## 4. Running Application Components

### Install Node Dependencies

```bash
npm install
```

### Run Web Dashboard

```bash
npm run dev:web
```
The React frontend dashboard is available at `http://localhost:5173`.

### Run API Control Plane (Go)

```bash
npm run dev:api
```
The API is available at `http://localhost:8080`.

### Run Scanner Worker Daemon (Go)

```bash
npm run dev:worker
```

---

## 5. Safe Local Scanner Testing (Mock Target Lab)

To prevent accidental scans against public internet infrastructure (per Acceptable Use Policy `docs/security/ACCEPTABLE_USE.md` and Threat Model T-01), test scan execution against the local isolated mock target:

- **Target URL:** `http://localhost:8081`
- **Health Check:** `http://localhost:8081/healthz`
- **Endpoints:**
  - `GET /vulnerable/headers`: Missing security headers (HSTS, CSP, X-Frame-Options) and software banner leakage.
  - `GET /vulnerable/xss?q=<payload>`: Reflected Cross-Site Scripting (XSS) endpoint.
  - `GET /vulnerable/sqli?id=1`: Error-based SQL Injection simulation.
  - `GET /vulnerable/info`: Sensitive build configuration and mock credential disclosure.

---

## 6. Environment Reset & Clean State Restoration

When switching git branches, after running large test batches, or when diagnosing database migrations, run the automated reset script to drop all containers, purge volumes, and re-provision clean state:

### Linux / macOS:
```bash
./scripts/dev-reset.sh
```

### Windows PowerShell:
```powershell
.\scripts\dev-reset.ps1
```

Or via npm:
```bash
npm run dev:reset
```

---

## 7. Verifying Tests & Schema Contracts

```bash
# Run schema and fingerprint validation tests
npm run test:schemas

# Build all applications and packages
npm run build
```

