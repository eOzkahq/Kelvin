# Kelvin Staging Scanner Activation & Operational Runbook

**Environment:** Kelvin Staging (Linux ARM64 / aarch64, Rootless Podman)  
**Governing Architecture:** [ADR-0008: Secure OCI Execution Architecture](../architecture/decisions/ADR-0008.md)  
**Classification:** Operational Runbook (Release Engineering & Security Operations)  
**Target Audience:** Security Engineers, DevOps Engineers, Staging Maintainers

---

## 1. Overview & Operational Principles

This runbook specifies the operational procedures, security boundaries, and emergency protocols for executing certified containerized vulnerability scanners (ProjectDiscovery Nuclei and OWASP ZAP) within the Kelvin staging environment.

### Core Security Mandates
1. **Unprivileged Rootless Execution:** All scanner containers execute strictly under the unprivileged `kelvin-worker` host account (UID/GID 10001) utilizing Rootless Podman and `crun`.
2. **Zero Docker Socket Exposure:** Access to `/var/run/docker.sock` or `DOCKER_HOST` is prohibited; any detected socket connection unconditionally aborts the worker daemon.
3. **Fail-Closed Release Certification:** Scanner execution is gated by `deploy/scanners/images.lock.json`. Images flagged as `not-released` or missing verified cryptographic attestations are rejected.
4. **Network Isolation & SSRF Defense:** Scanner containers are attached to an isolated internal bridge network (`10.89.10.0/24`, `internal: true`). All outbound assessment traffic must traverse the anti-SSRF egress proxy. Direct internet and private network egress is blocked at the kernel/firewall boundary.

---

## 2. Network Topology & Anti-SSRF Architecture

```
+-------------------------------------------------------------------------------+
| KELVIN STAGING HOST                                                           |
|                                                                               |
|  +--------------------+         +------------------------------------------+  |
|  | Kelvin Worker      |         | Isolated Scanner Network (Internal Bridge)|  |
|  | (UID 10001)        |         | Subnet: 10.89.10.0/24 (internal=true)    |  |
|  +---------+----------+         +--------------------+---------------------+  |
|            |                                         |                        |
|            | spawns rootless container               |                        |
|            v                                         v                        |
|  +---------+--------------------+       +------------+--------------------+   |
|  | Certified Scanner Container  | ----> | Anti-SSRF Egress Proxy           |   |
|  | (Nuclei / ZAP - UID 10001)   |       | Port: 8080                       |   |
|  +------------------------------+       +------------+--------------------+   |
+------------------------------------------------------|------------------------+
                                                       | Filtered Egress
                                                       v
                                          +------------+--------------------+
                                          | Authorized Staging Target       |
                                          | - Juice Shop (staging.internal) |
                                          | - crAPI (staging.internal)      |
                                          +---------------------------------+
                                                       |
                                          BLOCKED (Drop & Alert):
                                          - Loopback (127.0.0.1, ::1)
                                          - RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
                                          - Cloud Metadata (169.254.169.254)
```

### Prohibited Target Destinations
The Anti-SSRF Proxy and `apps/worker/internal/scopevalidator` reject scan attempts targeting:
- Loopback addresses (`127.0.0.0/8`, `::1/128`, `localhost`)
- RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Cloud instance metadata services (`169.254.169.254/32`)
- Link-local and multicast ranges (`169.254.0.0/16`, `224.0.0.0/4`, `fe80::/10`)
- Non-HTTP/HTTPS protocols (`file://`, `gopher://`, `ftp://`, `ssh://`)

---

## 3. Pre-Activation Checklist

Before activating or running scanner assessments in staging, verify:
- [ ] `deploy/scanners/images.lock.json` contains valid SHA256 digests and release status.
- [ ] Release readiness check passes: `bash scripts/scanners/release-readiness-check.sh`.
- [ ] Staging target is registered on the authorized scope allowlist.
- [ ] Supabase PostgreSQL database connections enforce TLS (`sslmode=verify-full`).
- [ ] Evidence bucket permissions in MinIO/Supabase Storage are configured with AES-256 encryption.

---

## 4. Operational Scan Execution

### 4.1 Running Assessment Scan against Authorized Target
When an assessment job is dispatched via Redis task queue:
1. Worker daemon inspects `images.lock.json` and verifies `status == "certified"`.
2. Worker validates target URL against scope allowlist (asserts public domain or allowed staging FQDN).
3. Rootless Podman spawns scanner container inside `kelvin-scanner-internal` network.
4. Container executes scan through the Anti-SSRF proxy (`http://10.89.10.1:8080`).
5. Raw output is parsed by the normalization pipeline into Kelvin Finding Schema v1.
6. Evidence artifacts (PCAP, raw HTTP requests/responses) are signed and uploaded to encrypted MinIO/Supabase storage.

### 4.2 Inspecting Worker Security Audit Logs
Monitor structured worker logs for audit events:
```bash
# View real-time security audit logs
journalctl -u kelvin-worker.service -f | grep "SECURITY_AUDIT"
```

Expected audit events:
- `scanner_certification_verified`: Image digest matched manifest.
- `scanner_certification_blocked`: Manifest was uncertified or tampered (job aborted).
- `docker_socket_forbidden`: Unauthorized Docker socket access attempted.
- `scanner_container_launch`: Container initialized with non-root UID 10001.
- `scanner_container_completed`: Container exited cleanly and was reaped.

---

## 5. Emergency Killswitch & Rapid Rollback Procedures

### Scenario A: Immediate Killswitch (Halt All Active Scans)
If an abnormal scan behavior, unintended target access, or security violation is detected:

```bash
# Step 1: Emergency stop the host worker daemon
sudo systemctl stop kelvin-worker.service

# Step 2: Force-kill any lingering rootless scanner containers
podman rm -f $(podman ps -q --filter "name=kelvin-job-") 2>/dev/null || true

# Step 3: Revert release manifest status to fail closed
# Setting status to 'not-released' immediately blocks all scanner executions across workers
python -c "
import json
with open('deploy/scanners/images.lock.json', 'r+') as f:
    d = json.load(f)
    d['status'] = 'not-released'
    f.seek(0); json.dump(d, f, indent=2); f.truncate()
"
```

### Scenario B: Atomic Staging Rollback
If a newly deployed scanner image triggers regression or failures:

```bash
# Step 1: Execute automated rollback script
sudo bash scripts/deploy/staging-deploy.sh --rollback

# Step 2: Verify truthful readiness probe reports unavailable/reverted
curl -s http://127.0.0.1:8080/healthz | jq .
```

---

## 6. Audit Sign-Off & Verification Contacts

| Role | Responsibility | Authority |
| :--- | :--- | :--- |
| **Release Lead** | Authorizes staging image certification | Production deployment gate |
| **Security Operations** | Audits Anti-SSRF bypass logs & findings | Scope expansion approval |
| **Infrastructure Lead** | Monitors host cgroups & OCI runtime health | Host capacity management |
