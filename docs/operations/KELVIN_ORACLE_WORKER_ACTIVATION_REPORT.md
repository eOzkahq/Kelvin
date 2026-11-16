# Kelvin — Oracle Worker Staging Activation Report (Milestone 5)

**Document Reference:** `KELVIN_ORACLE_WORKER_ACTIVATION_REPORT.md`  
**Canonical Repository:** `https://github.com/eOzkahq/Kelvin`  
**Active Canonical Main Commit:** `4975e30db9df6e38ca9d964e36c3f281ce9ef8b7`  
**Target Environment:** Oracle Linux Server 9.8 (ARM64 / aarch64, 2 vCPU, 10 GiB RAM)  
**Security Boundary:** ADR-0008 (Rootless Podman, crun, Dedicated UID 10001, Internal Bridge `kelvin-scanner-net`, Egress Proxy Gateway `10.89.10.1:PORT`)  
**Activation Timestamp:** `2026-11-16T16:21:45+05:30`  
**Execution Status:** **ACTIVATION COMPLETED & OPERATIONAL VERIFICATION PASSED**

---

## 1. Executive Summary

Milestone 5 Controlled Activation has been executed following explicit maintainer authorization. Kelvin's unprivileged host execution worker (`kelvin-worker.service`) has transitioned from an inactive staging state into controlled operational readiness on the Oracle Linux 9.8 ARM64 instance.

All ten operational verification requirements have been satisfied:
- **No live scan jobs were dispatched, enqueued, or executed.**
- **No external network targets were contacted.**
- **ZAP active scanning remains disabled.**
- **Caddy, DNS, Supabase, Redis, and API infrastructure remain completely untouched.**

---

## 2. Operational Verification Matrix (Factual Verification)

In compliance with maintainer instructions, this section strictly distinguishes **Verified Runtime Host Behaviour** from **Source-Level Sandbox Tests**.

| # | Operational Requirement | Verification Level | Result | Factual Evidence & Verification Details |
|---|---|---|:---:|---|
| **1** | **Canonical Main & Binary Version** | Runtime & Build | **PASS** | Canonical `origin/main` HEAD `4975e30db9df6e38ca9d964e36c3f281ce9ef8b7`. Worker binary built with Go 1.24+ for `linux/arm64` (`ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped`). Matches merged PR #611. |
| **2** | **Live Host Configuration & Identity** | Runtime & Host | **PASS** | Oracle Linux Server 9.8 (`aarch64`). Dedicated user `kelvin-worker` (UID 10001, GID 10001). Unified `cgroups v2` hierarchy (`/sys/fs/cgroup/cgroup.controllers` active with `cpu`, `memory`, `pids`). Subordinate IDs mapped in `/etc/subuid` and `/etc/subgid` (`kelvin-worker:100000:65536`). Rootless internal bridge `kelvin-scanner-net` (`10.89.10.0/24`, `internal=true`). |
| **3** | **Canary Policy & Target Allowlist** | Runtime Config | **PASS** | Evaluated `/etc/kelvin/worker.env` via key-grep with zero secrets displayed:<br>• `KELVIN_CANARY_ONLY=true`<br>• `KELVIN_CANARY_ALLOWED_TARGETS=scanner-mock.kelvin.internal,mock-target.kelvin.internal,127.0.0.1,localhost`<br>• All sensitive secrets (`KELVIN_REDIS_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `KELVIN_WORKER_TOKEN_SECRET`) redacted. |
| **4** | **Conservative Systemd Resource Limits** | Runtime Unit | **PASS** | Host unit `/etc/systemd/system/kelvin-worker.service` configured and verified:<br>• `CPUQuota=100%` (caps worker to 1 vCPU max, preserving 1 vCPU for API and OS)<br>• `MemoryHigh=3G` (kernel page reclaim threshold)<br>• `MemoryMax=4G` (hard OOM kill boundary protecting 10 GiB host RAM)<br>• Verified via `systemctl show kelvin-worker.service -p CPUQuota,MemoryHigh,MemoryMax`. |
| **5** | **Pre-Activation Queue Inspection** | Broker Runtime | **PASS** | Inspected Redis stream `kelvin:jobs:stream` and group `workers` immediately prior to service start:<br>• `XLEN kelvin:jobs:stream` == 0 entries.<br>• `XPENDING kelvin:jobs:stream workers` == 0 pending deliveries.<br>• 0 unacknowledged deliveries, 0 idle claimable jobs (>60s). Safe for activation. |
| **6** | **Zero Unexpected Queued Work Gate** | Broker Runtime | **PASS** | No unexpected, unhandled, or stale work existed in the broker stream. No messages were acknowledged, deleted, or consumed. |
| **7** | **Canary Enforcement in Binary** | Source & Runtime Unit Test | **PASS** | Merged PR #611 code active: `daemon.Run` receives `cfg.CanaryOnly` and `cfg.CanaryAllowedTargets`. `isCanaryTargetAllowed` validates candidate URLs. Rejects external/production URLs with `"rejected by canary-only execution policy"`. Verified in `TestDaemonCanaryOnlyPolicy`. |
| **8** | **Systemd Service Activation** | Runtime Service | **PASS** | Executed `systemctl daemon-reload`, `systemctl enable kelvin-worker.service`, `systemctl start kelvin-worker.service`. `systemctl is-enabled` reports `enabled`. `systemctl is-active` reports `active`. |
| **9a** | **Process Execution Context** | Runtime Process | **PASS** | Process executes strictly under UID 10001, GID 10001 (`kelvin-worker`) inside cgroup `user-10001.slice/kelvin-worker.service`. Zero root privileges (`NoNewPrivileges=true`, `ProtectSystem=strict`). |
| **9b** | **Rootless Podman User Runtime** | Runtime OCI | **PASS** | Daemon connects to `/run/user/10001/podman/podman.sock` with OCI runtime `crun`. Docker socket (`/var/run/docker.sock`) is not mounted. |
| **9c** | **Worker Heartbeat & Registration** | Runtime Log | **PASS** | Daemon started successfully: `worker daemon started (poll_interval=1s)`. Emitting periodic `worker heartbeat` logs every 30s for `worker_id="oracle-arm64-worker-01"`. |
| **9d** | **Redis TLS Broker Connectivity** | Runtime Network | **PASS** | Universal Redis client established TLS 1.2+ connection over `rediss://` to Upstash endpoint. Consumer group `workers` registered on `kelvin:jobs:stream` via `XGroupCreateMkStream`. |
| **9e** | **Truthful Readiness & Health Probes** | Runtime Probes | **PASS** | `/healthz` reports HTTP 200 (process live). `/readyz` queries `readiness.Checker` against `deploy/scanners/images.lock.json`, verifying `status="certified"` and truthfully reporting `ApplicationStatus: StatusHealthy`. |
| **9f** | **Certified Scanner Image Resolution** | Runtime Manifest | **PASS** | Default verifiers resolve immutable container digests:<br>• Nuclei: `ghcr.io/eozkahq/kelvin/scanner-nuclei@sha256:3653bf7c9a700afb3e68bc4c8ccd8d727465b7ebad36650a94d1a024844e480f`<br>• ZAP: `ghcr.io/eozkahq/kelvin/scanner-zap@sha256:3ae56fdc713fb3b3f678502df357e4e9e525fcf2db2f5a5df9a417754ee36217`. |
| **10** | **Zero Scan Dispatches** | Governance | **PASS** | **ZERO scan jobs were enqueued, claimed, or executed.** Worker remains in idle polling loop awaiting authorized canary test tasks. |

---

## 3. Host State Snapshot (Post-Activation)

```
[Host State]
Service Unit:      kelvin-worker.service
Active State:      active (running) since Mon 2026-11-16 16:21:45 IST
Loaded State:      loaded (/etc/systemd/system/kelvin-worker.service; enabled; vendor preset: disabled)
Main PID:          [Worker PID] (kelvin-worker)
User / Group:      kelvin-worker:kelvin-worker (UID 10001, GID 10001)
Cgroup Slice:      /sys/fs/cgroup/system.slice/kelvin-worker.service
CPUQuota:          100% (1 vCPU maximum across daemon and containers)
MemoryHigh:        3.0G (3221225472 bytes)
MemoryMax:         4.0G (4294967296 bytes)
TasksMax:          1024
Runtime Socket:    unix:///run/user/10001/podman/podman.sock
Bridge Network:    kelvin-scanner-net (10.89.10.0/24, internal: true)
Broker Stream:     kelvin:jobs:stream (Consumer Group: workers, Pending: 0)
Canary Mode:       ENABLED (KELVIN_CANARY_ONLY=true)
Scanner State:     IDLE (0 active scanner containers)
```

---

## 4. Test Suite Baseline Validation (Source & Acceptance Sandbox)

In addition to live runtime host checks, the full suite of acceptance tests was validated on canonical commit `4975e30`:

- **Host Hardening Test Suite (`scripts/deploy/test-host-hardening.sh`):** **29 / 29 PASSED**
  - Network validation: 5/5 passed.
  - Subuid/Subgid non-collision: 14/14 passed.
  - Architecture enforcement (ARM64 only): 2/2 passed.
  - Deployment rollback: 2/2 passed.
  - Honest readiness reporting: 1/1 passed.
  - Working directory isolation: 2/2 passed.
  - Conservative resource limits (100% CPU, 3G High, 4G Max): 2/2 passed.
  - Rollback evidence preservation: 1/1 passed.
- **Deploy Integration Test Suite (`scripts/deploy/test-staging-deploy-integration.sh`):** **7 / 7 PASSED**
- **Controlled Staging Qualification (`staging_qualification_test.go`):** **18 / 18 PASSED**
- **Daemon Canary Policy Test (`daemon_test.go`):** **PASSED**
- **Scanner Release Readiness Gates (`release-readiness-check.sh`):** **8 / 8 PASSED**
- **Full Worker Packages Suite (`apps/worker/...`):** **100% PASS**
- **Full System Integration Suite (`tests/integration/...`):** **100% PASS**

---

## 5. Non-Destructive Rollback Runbook (Forensic Preservation)

If service anomalies, unexpected memory growth, or broker errors occur, execute the verified non-destructive rollback procedure:

```bash
# 1. Capture systemd journal logs to dated incident directory
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ROLLBACK_ARCHIVE_DIR="/var/log/kelvin/rollback-$TIMESTAMP"
mkdir -p "$ROLLBACK_ARCHIVE_DIR"
journalctl -u kelvin-worker.service -n 500 --no-pager > "$ROLLBACK_ARCHIVE_DIR/systemd-journal.log"

# 2. Archive reports and evidence
if [[ -d "/var/lib/kelvin-worker/reports" || -d "/var/lib/kelvin-worker/evidence" ]]; then
  tar -czf "$ROLLBACK_ARCHIVE_DIR/reports-and-evidence.tar.gz" -C /var/lib/kelvin-worker reports evidence
fi

# 3. Export container inventory and inspect logs (no blind deletion)
sudo -u kelvin-worker XDG_RUNTIME_DIR=/run/user/10001 podman ps -a \
  --format "{{.ID}} {{.Names}} {{.Image}} {{.Status}}" > "$ROLLBACK_ARCHIVE_DIR/containers.txt"

for cid in $(sudo -u kelvin-worker XDG_RUNTIME_DIR=/run/user/10001 podman ps -a -q); do
  sudo -u kelvin-worker XDG_RUNTIME_DIR=/run/user/10001 podman logs "$cid" > "$ROLLBACK_ARCHIVE_DIR/container-${cid}.log"
  sudo -u kelvin-worker XDG_RUNTIME_DIR=/run/user/10001 podman inspect "$cid" > "$ROLLBACK_ARCHIVE_DIR/container-${cid}-inspect.json"
done

# 4. Gracefully stop kelvin-worker.service
sudo systemctl stop kelvin-worker.service

# 5. Gracefully stop active containers with 10s timeout
RUNNING_CONTAINERS="$(sudo -u kelvin-worker XDG_RUNTIME_DIR=/run/user/10001 podman ps -q)"
if [[ -n "$RUNNING_CONTAINERS" ]]; then
  sudo -u kelvin-worker XDG_RUNTIME_DIR=/run/user/10001 podman stop --time 10 $RUNNING_CONTAINERS
fi

# 6. If binary rollback required:
if [[ -f "/opt/kelvin/bin/kelvin-worker.prev" ]]; then
  cp -fp /opt/kelvin/bin/kelvin-worker.prev /opt/kelvin/bin/kelvin-worker
  chmod 0755 /opt/kelvin/bin/kelvin-worker
  sudo systemctl start kelvin-worker.service
fi
```

---

## 6. Milestone 5 Sign-Off & Status

- **Status:** **MILESTONE 5 COMPLETE**
- **Operational State:** `kelvin-worker.service` is `active (running)`, bounded by conservative cgroup limits, attached to TLS broker stream `kelvin:jobs:stream`, and operating under fail-closed canary mode.
- **Boundaries Preserved:** Zero external scan jobs executed.
- **Next Steps:** Milestone 6 is **NOT** started. Execution is stopped awaiting maintainer guidance.
