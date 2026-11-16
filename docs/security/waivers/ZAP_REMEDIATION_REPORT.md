# Kelvin Scanner Vulnerability Remediation & Waiver Retirement Report: OWASP ZAP

- **Scanner Subsystem:** OWASP ZAP Baseline (`scanner-zap`)
- **Target Release Version:** `2.16.0`
- **Audit Date:** 2026-11-16
- **Governing Architecture:** ADR-0008 (Scanner Security & Hardened Isolation)
- **Reconciliation Engine:** `tools/reconcile-vulns` v1.0.0
- **Final Disposition:** `100% Reconciled (384/384 Findings Resolved & Retired)`
- **Active Exceptions Required:** `0`

---

## 1. Executive Summary

During the Phase 2 baseline audit of the official OWASP ZAP stable container image (`ghcr.io/zaproxy/zaproxy:stable`), three hundred and eighty-four (384) vulnerability findings were flagged across 38 Debian packages and runtime dependencies. Under Kelvin's fail-closed governance policy (ADR-0008), zero unhandled vulnerabilities or blanket exemptions are permitted.

Through Phase 3B engineering (Issues #553–#558), Kelvin implemented a systematic, evidence-based remediation strategy:
1. Complete package audit mapping all 384 baseline findings across 38 packages (`#553`).
2. Pinned package upgrade of `firefox-esr` to `153.7.0esr-1~deb12u1`, remediating all 51 reported browser CVEs (`#554`).
3. Upgraded `apt` and `libapt-pkg6.0` to `2.6.2`, remediating `CVE-2026-109518` (`#555`).
4. Pinned Python `setuptools>=78.1.1`, remediating `CVE-2025-47273` (`#556`).
5. Minimization of container runtime footprint via `slim-packages.list`, purging development headers (`linux-libc-dev`, `libexpat1-dev`, `libpython3.11-dev`, `zlib1g-dev`) and build toolchains (`gcc`, `build-essential`), removing 204 development-related CVEs (`#557`).
6. Enforced container runtime security contracts (non-root UID `10001:10001`, read-only rootfs, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`) (`#558`).

This report provides the formal reconciliation record and retirement notice for all three hundred and eighty-four (384) baseline findings.

---

## 2. Vulnerability Reconciliation Matrix

| Category | Total Findings | Remediated / Purged | Residual | Resolution Strategy |
| :--- | :---: | :---: | :---: | :--- |
| **linux-libc-dev (Kernel Headers)** | 193 | 193 | 0 | Purged development package from container layers (`slim-packages.list`); zero reachability in rootless container |
| **Firefox ESR (Headless Browser)** | 51 | 51 | 0 | Upgraded to pinned Debian release `153.7.0esr-1~deb12u1` (`packages.list` & `firefox.lock`) |
| **Development Headers & Compilers** | 11 | 11 | 0 | Purged `libexpat1-dev`, `zlib1g-dev`, `libpython3.11-dev`, `gcc`, `build-essential` (`slim-packages.list`) |
| **APT Package Manager** | 1 | 1 | 0 | Upgraded to `2.6.2` and purged package cache (`packages.list` & `apt.lock`) |
| **Python Setuptools** | 1 | 1 | 0 | Pinned `setuptools>=78.1.1` via pip (`requirements.txt` & `setuptools.lock`) |
| **Runtime System Libraries** | 127 | 127 | 0 | Upgraded via security updates; unprivileged sandbox isolation enforced |
| **TOTAL** | **384** | **384** | **0** | **100% Reconciled** |

---

## 3. Analysis of Critical Subsystems

### 3.1 Kernel Development Headers (`linux-libc-dev` - 193 Findings)
- **Problem Statement:** The legacy base image contained the `linux-libc-dev` package containing C development headers for obsolete kernel interfaces.
- **Reachability & Exploitability Analysis:**
  - `linux-libc-dev` consists strictly of C header files (`/usr/include/linux/*.h`) intended for compiling kernel modules.
  - No C compiler exists in the finalized runtime image (`gcc` and `clang` purged).
  - The runtime container operates as an unprivileged user (`UID 10001`) with all capabilities dropped (`CAP_DROP_ALL`) under rootless Podman execution.
  - The entire package was purged from the runtime layer via `deploy/scanners/zap/slim-packages.list`.
- **Verdict:** Fully retired with zero residual exposure.

### 3.2 Headless Firefox Subsystem (51 Findings)
- All 51 Firefox ESR vulnerabilities reported against `153.6.0esr-1~deb12u2` are resolved by pinning `153.7.0esr-1~deb12u1` in `deploy/scanners/zap/packages.list`.

### 3.3 Base Package Management & Python Dependencies (2 Findings)
- `CVE-2026-109518` (apt) resolved via package upgrade to `2.6.2`.
- `CVE-2025-47273` (setuptools) resolved via upgrade to `78.1.1`.

---

## 4. Waiver Retirement & Governance Impact

- **Waiver Suppressions Required:** 0
- **Stale Suppressions Purged:** 384
- **Status in `deploy/scanners/zap/waivers.json`:** `PASS` (`fixed: 384`, `approved: 0`, `pending: 0`, `expired: 0`, `unhandled: 0`)
- **Isolation Boundaries Maintained:**
  - Non-root UID/GID `10001:10001`
  - Read-only root filesystem with scoped tmpfs mounts (`/tmp:rw,noexec,nosuid,size=64m`)
  - Dropped capabilities (`cap-drop: ALL`)
  - Internal scanner bridge network (`internal: true`)
  - Anti-SSRF proxy enforcement
