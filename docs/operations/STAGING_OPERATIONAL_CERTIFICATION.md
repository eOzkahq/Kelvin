# Kelvin Staging Operational Certification

**Status:** Certified for Staging Execution  
**Environment:** Oracle Linux Server 9.8 (ARM64 / aarch64, 2 vCPUs, 10 GiB RAM)  
**Milestone:** Scanner Execution Platform (Milestone #10)  
**Decision Record:** [ADR-0008](../architecture/decisions/ADR-0008.md)  

---

## 1. Executive Summary

This document certifies that the **Kelvin Scanner Execution Platform** has resolved all architectural vulnerabilities and met all security, isolation, and lifecycle requirements across Phases 0 through 8 (Issues 001 through 032).

---

## 2. Security Controls Verification

| Security Control | Requirement | Status | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **No Docker Socket** | `/var/run/docker.sock` must NEVER be mounted into worker containers | **PASSED** | Hardened compose and runner specifications verify no socket mount. |
| **Non-Root Execution** | Worker and scanner containers execute strictly as unprivileged UID 10001 | **PASSED** | Verified via `Spec.Validate()` and `docker image inspect`. |
| **Read-Only Rootfs** | Scanner containers execute with read-only root filesystems | **PASSED** | Enforced via `--read-only` in `apps/worker/internal/sandbox/oci.go`. |
| **Linux Capabilities** | All Linux capabilities dropped (`--cap-drop=ALL`) | **PASSED** | Enforced via `Spec.Validate()` and OCI args. |
| **Privilege Escalation** | `no-new-privileges:true` strictly enforced | **PASSED** | Enforced via security options on all containers. |
| **Cgroups v2 Limits** | Memory (512M/2G), CPU quota, Max PIDs (64) | **PASSED** | Enforced via cgroups flags and verified in sandbox tests. |
| **Network Egress Isolation** | Scanner containers cannot access the public internet or private infrastructure directly | **PASSED** | Isolated internal bridge `kelvin-scanner-net` with anti-SSRF scoped egress proxy. |
| **Anti-SSRF & DNS Rebinding** | RFC 1918, 169.254.169.254, loopback, and multi-A DNS rebinding blocked | **PASSED** | 12 regression tests in `apps/worker/internal/egress/network_bypass_test.go`. |
| **Immutable Provenance** | Pinned image SHA256 digests and template catalog hashes recorded in every finding | **PASSED** | Verified in `apps/worker/internal/provenance/provenance.go`. |
| **Truthful Readiness** | `scannerRunner` reports `UNAVAILABLE` until certified worker is active | **PASSED** | Verified in `apps/api/internal/httpapi/probes.go` and readiness probes. |

---

## 3. Deployment & Rollback Verification

- **Deployment Script:** `scripts/deploy/staging-deploy.sh`
- **Rollback Script:** `scripts/deploy/staging-rollback.sh`
- **Database TLS:** `sslmode=verify-full` verified with CA certificate volume mounting in `deploy/staging/docker-compose.yml`.
- **Redis Security:** Upstash Redis over TLS (`rediss://`) with mandatory authentication.
- **Evidence Storage:** Supabase private storage (`kelvin-evidence`) with pre-signed URLs and SHA256 integrity checksums.

---

## 4. Certification Sign-off

- **Platform Architecture:** Rootless Podman / Cgroups v2 on Oracle Linux ARM64
- **Curated Nuclei Catalog:** Certified (`sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2`)
- **Release Status:** Certified for Staging deployment. Production integration ready.
