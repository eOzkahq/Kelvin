# KELVIN Staging Docker Compose Architecture & Operations Guide (PRE-09)

## 1. Overview

The staging deployment configuration located at `deploy/staging/docker-compose.yml` provides a production-grade container topology tailored for a single **Oracle Linux ARM64** virtual machine (1 OCPU / 6 GB RAM).

Unlike the local development compose file (`docker-compose.yml`), the staging configuration does **not** run local data store containers. All stateful infrastructure is offloaded to managed cloud providers:
- **Relational Database**: Supabase PostgreSQL over verified TLS (`sslmode=verify-full`).
- **Task Broker / Queue**: Managed Redis over TLS (`rediss://`).
- **Object Storage**: Supabase Private Storage (`kelvin-reports` and `kelvin-evidence`).
- **Frontend**: Vercel Edge hosting (accessing the API via reverse proxy).

---

## 2. Architecture Comparison: Development vs. Staging

| Attribute | Local Development (`docker-compose.yml`) | Staging (`deploy/staging/docker-compose.yml`) |
| :--- | :--- | :--- |
| **PostgreSQL** | Local container (`postgres:15-alpine`) | Managed Supabase PostgreSQL with verified TLS |
| **Redis** | Local container (`redis:7-alpine`) | Managed Redis cluster over TLS (`rediss://`) |
| **Object Store** | Local MinIO container (`minio/minio`) | Managed Supabase Private Storage API |
| **Mock Target** | Local Juice Shop container | External target validation |
| **Host Ports** | `8080` (public), `5432` (internal), `6379` (internal) | `127.0.0.1:8080:8080` only (Loopback bound) |
| **Database Pool** | 25 max conns / 5 min conns | 5 max conns / 1 min conn (Bounded Oracle VM sizing) |
| **Docker Socket** | Never mounted | Never mounted (`/var/run/docker.sock` prohibited) |
| **User Context** | Non-root `10001:10001` | Non-root `10001:10001`, `read_only: true`, `cap_drop: ALL` |
| **Worker Concurrency**| Variable | Strictly `1` (1 OCPU preservation) |

---

## 3. Oracle VM ARM64 Resource Allocation Model

The staging host is configured on an Oracle Cloud Infrastructure (OCI) Ampere A1 Compute instance:
- **vCPU / OCPU**: 1 OCPU (2 vCPUs)
- **Host RAM**: 6 GB total

Container resource limits are strictly budgeted to prevent Out-Of-Memory (OOM) kernel kills and noisy-neighbor throttling:

```mermaid
flowchart TD
    Host["Oracle Linux ARM64 Host (1 OCPU / 6 GB RAM)"]
    subgraph Allocations ["Container Resource Budget"]
        API["kelvin-staging-api<br/>Limits: 0.60 CPU / 2048 MB RAM<br/>Reservations: 0.10 CPU / 512 MB RAM"]
        Worker["kelvin-staging-worker<br/>Limits: 0.40 CPU / 3072 MB RAM<br/>Reservations: 0.10 CPU / 512 MB RAM"]
        OS["OS Kernel & Buffer Reserve<br/>~1024 MB RAM / 0.10 OCPU"]
    end
    Host --> API
    Host --> Worker
    Host --> OS
```

---

## 4. Network Model & Ingress Security

1. **Loopback Port Binding**:
   The API container binds strictly to `127.0.0.1:8080:8080`. It is never exposed directly on public host interfaces (`0.0.0.0`). Ingress is routed through a host-level reverse proxy (such as Caddy or Nginx) handling TLS termination and certbot renewal.
2. **Data Stores Unmapped**:
   Neither port `5432` nor `6379` is published to the host.
3. **Bridge Network**:
   Services attach to `kelvin-staging-net` with outbound internet egress enabled to communicate with Supabase and Redis over encrypted TLS tunnels.

---

## 5. Security Controls & Container Hardening

- **Non-Root Execution**: Runs under UID/GID `10001:10001` (`kelvin`).
- **Read-Only Root Filesystem**: `read_only: true` is enforced for both API and Worker.
- **Temporary Storage**: Dedicated `tmpfs` mounts at `/tmp` (`size=256m` for API, `size=1024m` for Worker) with `noexec` and `nosuid` where applicable.
- **Capabilities & Privilege Escalation**: `cap_drop: [ALL]` and `no-new-privileges: true` block privilege escalation.
- **Log Rotation**: Docker JSON logging is capped at 5 files of 50 MB each (`max-size: "50m"`, `max-file: "5"`).
- **Socket Isolation**: Docker daemon socket (`/var/run/docker.sock`) is **never** mounted into either container.

---

## 6. Deployment Commands

```bash
# 1. Export staging environment variables
export $(cat /etc/kelvin/staging.env | xargs)

# 2. Validate configuration syntax
docker compose -f deploy/staging/docker-compose.yml config

# 3. Pull / Build ARM64 images and start services
docker compose -f deploy/staging/docker-compose.yml up -d --build

# 4. Check status and health probes
docker compose -f deploy/staging/docker-compose.yml ps
docker compose -f deploy/staging/docker-compose.yml logs -f --tail=50
```
