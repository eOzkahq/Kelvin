# KELVIN — Worker Deployment & Operational Runbook
## Architecture, Packaging, Systemd Hardening & Rollback Procedures

**Scope:** Kelvin Scanner Execution Worker (Host Daemon)  
**Milestone:** M9.1 (Issue #643)  
**Last Updated:** Tuesday, November 17, 2026  
**Audience:** DevSecOps Engineers, Platform Administrators  

---

## 1. Overview & Operational Model

The Kelvin Worker daemon consumes assessment jobs from Redis Streams (`kelvin:jobs:stream`), executes containerized scanners within rootless Podman/crun sandboxes, synchronizes state transitions to the PostgreSQL database, and exposes local diagnostics over HTTP (`:8081/healthz`, `:8081/readyz`).

```
                +------------------------------------+
                |       Redis Streams Broker         |
                |       (kelvin:jobs:stream)         |
                +-----------------+------------------+
                                  |
                                  | XREADGROUP / XAUTOCLAIM
                                  v
+--------------------------------------------------------------------+
|  Host Systemd Service (kelvin-worker.service)                      |
|  User: kelvin-worker | Cgroup: CPUQuota=200%, MemoryMax=2G         |
|                                                                    |
|  +------------------------+      +-------------------------------+ |
|  | HTTP Diagnostics       |      | Daemon Consumer Engine        | |
|  | :8081/healthz, /readyz |      | - Distributed Lease Locking   | |
|  +------------------------+      | - Schema V2 JobEnvelope       | |
|                                  | - State Synchronizer (DB)     | |
|                                  +---------------+---------------+ |
+--------------------------------------------------|-----------------+
                                                   |
                                                   v
                                  +----------------+----------------+
                                  |  Rootless Podman / crun OCI     |
                                  |  (NoNewPrivs, CapDrop, RO root) |
                                  +---------------------------------+
```

> [!IMPORTANT]
> **Safety Boundary:** In staging and production environments, `kelvin-worker.service` must remain **`inactive`** and **`disabled`** until explicit rollout approval is granted. Zero unauthorized scans may run against external targets.

---

## 2. Host Prerequisites

1. **System Service Account:**
   ```bash
   sudo useradd --system --shell /sbin/nologin --home-dir /var/lib/kelvin/worker kelvin-worker || true
   sudo mkdir -p /var/lib/kelvin/worker /run/kelvin /var/log/kelvin /opt/kelvin/bin
   sudo chown -R kelvin-worker:kelvin-worker /var/lib/kelvin/worker /run/kelvin /var/log/kelvin
   ```

2. **Rootless Podman User Session:**
   ```bash
   # Enable lingering for kelvin-worker to persist rootless runtime across logins
   sudo loginctl enable-linger kelvin-worker
   ```

3. **Environment Configuration (`/etc/kelvin/staging.env`):**
   ```ini
   KELVIN_ENV=staging
   KELVIN_LOG_LEVEL=info
   KELVIN_WORKER_ID=worker-staging-01
   KELVIN_CANARY_ONLY=true
   KELVIN_CANARY_ALLOWED_TARGETS=scanner-mock.kelvin.internal,127.0.0.1,localhost
   KELVIN_REDIS_ADDR=127.0.0.1:6379
   KELVIN_WORKER_HEALTH_ADDR=:8081
   ```

---

## 3. Worker Build & Binary Packaging

Compile the binary natively with `GOWORK=off`:

```bash
cd /opt/kelvin
GOWORK=off go build -ldflags="-s -w" -o /opt/kelvin/bin/kelvin-worker ./apps/worker/cmd/runner
sudo chown root:kelvin-worker /opt/kelvin/bin/kelvin-worker
sudo chmod 0755 /opt/kelvin/bin/kelvin-worker
```

Verify binary executable metadata:
```bash
/opt/kelvin/bin/kelvin-worker --version || true
```

---

## 4. Systemd Service Installation & Hardening

1. **Install Unit File:**
   ```bash
   sudo cp deploy/staging/kelvin-worker.service /etc/systemd/system/kelvin-worker.service
   sudo chmod 0644 /etc/systemd/system/kelvin-worker.service
   sudo systemctl daemon-reload
   ```

2. **Verify Hardening Directives:**
   The unit enforces strict Linux process isolation:
   - `ProtectSystem=strict` (read-only `/usr`, `/boot`, `/etc`)
   - `ProtectHome=true` (inaccessible `/root`, `/home`)
   - `PrivateTmp=true` (isolated `/tmp` namespace)
   - `NoNewPrivileges=true` (blocks setuid escalation)
   - `MemoryMax=2G`, `CPUQuota=200%`, `TasksMax=256` (resource caps)

3. **Verify Safe Inactive State:**
   ```bash
   sudo systemctl status kelvin-worker.service
   # Expected: Loaded: ... Active: inactive (dead)
   ```

---

## 5. Pre-Deployment Lab Verification

Run the automated local verification harness:

```bash
bash scripts/test-worker-local.sh
```

**Verification Steps Performed:**
1. Compiles worker binary in an isolated temporary location.
2. Spawns the worker bound to `127.0.0.1:8089`.
3. Probes `GET http://127.0.0.1:8089/healthz` and `GET http://127.0.0.1:8089/readyz`.
4. Sends `SIGTERM` and confirms graceful exit (code `0`) within 5 seconds.
5. Cleans up temporary artifacts.

---

## 6. Activation Procedure (Gated by Human Approval)

When explicit rollout approval is provided:

```bash
# 1. Start worker service
sudo systemctl start kelvin-worker.service

# 2. Check service status
sudo systemctl status kelvin-worker.service

# 3. Verify HTTP diagnostics
curl -s http://127.0.0.1:8081/healthz
curl -s http://127.0.0.1:8081/readyz

# 4. Verify Redis vitality heartbeat
redis-cli ttl kelvin:jobs:heartbeat:worker:worker-staging-01
# Expected: > 0 (e.g. ~90 seconds)
```

---

## 7. Emergency Rollback Procedure

If any anomaly or failure is detected upon activation:

```bash
# 1. Immediately stop worker service
sudo systemctl stop kelvin-worker.service

# 2. Disable service to prevent automatic restart on reboot
sudo systemctl disable kelvin-worker.service

# 3. Clean up active worker lease locks if necessary
redis-cli keys "kelvin:jobs:lease:*" | xargs -r redis-cli del

# 4. Confirm zero running worker processes
pgrep -f kelvin-worker || echo "✓ Zero worker processes active"
```
