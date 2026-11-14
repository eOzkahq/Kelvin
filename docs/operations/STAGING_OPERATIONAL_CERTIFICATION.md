# Kelvin Staging Operational Certification & Readiness Audit

**Status:** Implementation Complete / Host Deployment Pending  
**Environment:** Oracle Linux Server 9.8 (ARM64 / aarch64, 2 vCPUs, 10 GiB RAM)  
**Milestone:** Scanner Execution Platform (Milestone #10)  
**Governing Architecture:** [ADR-0008: Secure OCI Execution Architecture](../architecture/decisions/ADR-0008.md)  
**Last Audit Date:** 2026-11-14  

---

## 1. Executive Summary & Verification Matrix

In accordance with strict platform governance and ADR-0008, the table below delineates the verified operational status of the Kelvin Scanner Execution Platform:

| Gate | Criterion | Status | Evidence / Notes |
| :--- | :--- | :--- | :--- |
| **1. Architecture** | ADR-0008 (Rootless Podman host worker) | **APPROVED** | ADR-0008 Option A approved by security architecture. |
| **2. Code Implementation** | Phases 0–8 implementation merged to `main` | **COMPLETED** | Contracts, adapters, OCI executor, egress proxy, and scripts merged. |
| **3. Automated Test Suite** | 100% pass rate across all modules | **PASSED** | Worker, API, sandbox, network bypass, and candidate scanner tests pass. |
| **4. Host Runtime Deployment** | Systemd unit & Rootless Podman on Oracle host | **PENDING** | Automated scripts prepared (`setup-rootless-podman.sh`); awaiting host execution. |
| **5. Scanner Images Release** | Immutable ARM64 digests in GHCR | **NOT RELEASED** | Authoritative manifest (`images.lock.json`) is strictly `not-released`. |
| **6. Operational Certification** | Staging certified for live vulnerability scans | **NOT CERTIFIED** | Gated by successful host runtime deployment and signed image release. |

> [!IMPORTANT]
> Passing automated unit and integration tests does **not** constitute operational certification. The platform operates in **fail-closed governance**: until certified container images are signed and published, the worker will refuse to dispatch unreleased scanner images in staging and production.

---

## 2. Security Controls Verification

| Security Control | Requirement | Implementation Status | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Zero Docker Socket Exposure** | `/var/run/docker.sock` must NEVER be mounted into worker containers or used by scanner execution | **ENFORCED** | Host worker executes rootless Podman via unprivileged user. Socket mounts strictly rejected by `Spec.Validate()`. |
| **Non-Root Execution** | Worker process and scanner containers execute strictly as unprivileged UID 10001 | **ENFORCED** | Host worker runs as user `kelvin-worker` (UID 10001). Container execution enforces `10001:10001`. |
| **Read-Only Root Filesystem** | Scanner containers execute with immutable read-only root filesystems | **ENFORCED** | `--read-only` flag enforced in `apps/worker/internal/sandbox/oci.go`. |
| **Linux Capabilities Dropped** | All Linux capabilities dropped (`--cap-drop=ALL`) | **ENFORCED** | `Spec.Validate()` requires and enforces `--cap-drop=ALL`. |
| **Privilege Escalation Prevention**| `no-new-privileges:true` strictly enforced | **ENFORCED** | Security option `--security-opt=no-new-privileges` enforced on all containers. |
| **Cgroups v2 Resource Quotas** | Memory (512M/2G), CPU quota, Max PIDs (64) | **ENFORCED** | Cgroups v2 limits validated in `apps/worker/internal/sandbox/sandbox_test.go`. |
| **Network Egress Isolation** | Scanner containers cannot access the public internet or private infrastructure directly | **ENFORCED** | Containers attach to `--network=kelvin-scanner-net` (created with `--internal`). Default internet egress dropped. |
| **Anti-SSRF & DNS Rebinding** | RFC 1918, 169.254.169.254, loopback, and multi-A DNS rebinding blocked | **ENFORCED** | 12 regression tests in `apps/worker/internal/egress/network_bypass_test.go`. |
| **Credential Isolation** | Scanner containers never receive DB credentials, JWT secrets, or Redis tokens | **ENFORCED** | Environment allowlist in `Spec.Validate()` strictly rejects control-plane credentials. |
| **Immutable Provenance Tracking** | Pinned image SHA256 digests and template catalog hashes recorded in every finding | **ENFORCED** | Provenance tracking implemented in `apps/worker/internal/provenance/provenance.go`. |
| **Truthful Readiness Probes** | `scannerRunner` reports `UNAVAILABLE` until certified worker is active | **ENFORCED** | Fail-closed readiness verified in `truthful_readiness_test.go` and API probe endpoints. |

---

## 3. Deployment Artifacts & Procedures

- **Systemd Service Unit:** `deploy/systemd/kelvin-worker.service` (hardened: `ProtectSystem=strict`, `ProtectHome=read-only`, `Delegate=yes`, `NoNewPrivileges=true`, `KillMode=control-group`)
- **Environment Template:** `deploy/systemd/worker.env.example` (explicitly marked with `KELVIN_CONFIG_STATUS=TEMPLATE_NOT_CONFIGURED` and `REPLACE_WITH_...` tokens; startup fails closed if unconfigured)
- **Host Setup Script:** `scripts/deploy/setup-rootless-podman.sh` (enforces ARM64 architecture, provisions `/etc/kelvin/certs` with `0750` permissions, validates subuid/subgid range collisions against all users without overwriting conflicts, and inspects all 4 internal network properties—requiring strictly 1 subnet `10.89.10.0/24` and 1 gateway `10.89.10.1`—without destructive deletion)
- **Host Audit Script:** `scripts/deploy/validate-worker-host.sh` (validates ARM64, cgroups v2 controllers, crun, exact subnet `10.89.10.0/24`, exact gateway `10.89.10.1`, file permissions `0600`/`0400`, detects subuid/subgid range collisions, and rejects placeholder values; network inspection failures fail closed)
- **Staging Deployment Script:** `scripts/deploy/staging-deploy.sh` (compiles in temporary location, validates binary ELF headers, installs atomically, auto-rolls back to `.prev` on activation failure via safe trap handlers, and provides honest 7-layer post-deployment readiness assessment across process, startup, Redis broker connectivity, rootless Podman, crun/cgroups v2, internal bridge, and scanner release certification)
- **Integration Test Harness:** `scripts/deploy/test-staging-deploy-integration.sh` (executes the actual production `staging-deploy.sh` script in an isolated sandbox with mocked system tools across 7 failure and rollback recovery scenarios)
- **Hardening Acceptance Test Suite:** `scripts/deploy/test-host-hardening.sh` and `apps/worker/cmd/runner/deploy_hardening_test.go` (100% pass across all 8 network, subordinate ID, architecture, rollback, and truthful readiness scenarios)
- **Database TLS:** `sslmode=verify-full` verified with CA certificate at `/etc/kelvin/certs/supabase-root-ca.crt`.
- **Redis Security:** Upstash Redis over TLS (`rediss://`) with mandatory authentication.
- **Evidence Storage:** Supabase private storage (`kelvin-evidence`) with pre-signed URLs and SHA256 integrity checksums.

---

## 4. Remaining Blockers Before Live Staging Certification

To achieve live operational certification on the Oracle Linux 9.8 ARM64 host, the following operational steps must be completed:

1. **Host Setup Execution:**
   - Run `sudo bash scripts/deploy/setup-rootless-podman.sh` on the Oracle Linux host to create user `kelvin-worker` (UID 10001), configure `/etc/subuid` and `/etc/subgid`, enable linger, and create the `kelvin-scanner-net` internal bridge.
2. **Configuration Provisioning:**
   - Populate `/etc/kelvin/worker.env` with valid staging credentials (DB connection with `verify-full`, Upstash Redis TLS token, Supabase service-role key, worker token secret).
3. **Scanner Image Builds & Certification:**
   - Execute the ARM64 image build pipeline (`scripts/scanners/build-images.sh`) on an ARM64 runner or via Docker buildx.
   - Publish built images to GHCR (`ghcr.io/inkesk-dozing/scanner-zap`, `ghcr.io/inkesk-dozing/scanner-nuclei`).
   - Record verifiable SHA256 digests in `deploy/scanners/images.lock.json` and change status from `not-released` to `certified`.
4. **Service Activation & Smoke Test:**
   - Run `scripts/deploy/staging-deploy.sh` to compile the binary, start `kelvin-worker.service`, and verify end-to-end task execution against an authorized staging target.
