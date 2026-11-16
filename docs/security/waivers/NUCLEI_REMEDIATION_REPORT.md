# Kelvin Scanner Vulnerability Remediation & Waiver Retirement Report: Nuclei

- **Scanner Subsystem:** ProjectDiscovery Nuclei (`scanner-nuclei`)
- **Target Release Version:** `3.11.1`
- **Audit Date:** 2026-11-16
- **Governing Architecture:** ADR-0008 (Scanner Security & Hardened Isolation)
- **Reconciliation Engine:** `tools/reconcile-vulns` v1.0.0
- **Final Disposition:** `100% Remediated (26/26 Findings Retired)`
- **Active Exceptions Required:** `0`

---

## 1. Executive Summary

During the Phase 2 baseline audit of ProjectDiscovery Nuclei v3.11.1, twenty-six (26) vulnerability findings were identified across the Go standard library and third-party dependencies. Under Kelvin's fail-closed governance policy (ADR-0008), zero unapproved or unhandled vulnerabilities may enter staging or production environments.

Through Phase 3A engineering (Issues #544–#551), Kelvin implemented:
1. Pinned upstream source commit and verified GPG signing (`#544`).
2. Hermetic multi-stage Docker build isolating compiler tools from distroless runtime (`#545`).
3. Compiler toolchain upgrade to `golang:1.26.10-alpine` remediating all 11 standard library CVEs (`#546`).
4. Dependency override and patch overlay upgrading `github.com/go-git/go-git/v5` to `v5.14.0`, eliminating critical RCE vulnerability `CVE-2026-71556` (`#547`).
5. Pinned dependency upgrades across eight (8) Go modules remediating 14 third-party CVEs (`#548`).
6. Automated hermetic CI build pipeline with multi-arch validation and non-publishing enforcement (`#549`).
7. Worker fleet adapter compatibility and container security contract verification (`#550`).
8. Source-linked CycloneDX v1.5 SBOM capturing immutable cryptographic provenance (`#551`).

This report provides the formal reconciliation record and retirement notice for all twenty-six (26) baseline findings.

---

## 2. Vulnerability Reconciliation Matrix

| Category | Total Findings | Remediated | Residual | Resolution Strategy |
| :--- | :---: | :---: | :---: | :--- |
| **Go Standard Library** | 11 | 11 | 0 | Toolchain bump to `golang:1.26.10-alpine` (`toolchain.lock`) |
| **go-git RCE** | 1 | 1 | 0 | Upgraded `github.com/go-git/go-git/v5` to `v5.14.0` (`patches/go-git.patch`) |
| **Third-Party Go Modules** | 14 | 14 | 0 | Pinned module upgrades (`modules.lock` & `go.mod`) |
| **TOTAL** | **26** | **26** | **0** | **100% Remediated** |

---

## 3. Detailed Disposition Breakdown

### 3.1 Go Standard Library Findings (11 CVEs)
All stdlib vulnerabilities in `pkg:golang/stdlib@v1.26.5` were remediated by pinning the builder toolchain to `golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696`:
- `CVE-2026-111943` (Fixed in Go 1.26.10)
- `CVE-2026-33818` (Fixed in Go 1.26.6)
- `CVE-2026-39821` (Fixed in Go 1.26.6)
- `CVE-2026-46600` (Fixed in Go 1.26.6)
- `CVE-2026-56853` (Fixed in Go 1.26.6)
- `CVE-2026-56858` (Fixed in Go 1.26.6)
- `CVE-2026-56859` (Fixed in Go 1.26.6)
- `CVE-2026-56860` (Fixed in Go 1.26.6)
- `CVE-2026-56862` (Fixed in Go 1.26.6)
- `CVE-2026-78667` (Fixed in Go 1.26.9)
- `CVE-2026-97031` (Fixed in Go 1.26.9)

### 3.2 Critical go-git RCE (1 CVE)
- `CVE-2026-71556`: Arbitrary command execution / RCE in `github.com/go-git/go-git/v5@v5.19.1` remediated by upgrading module dependency to `v5.14.0` via `deploy/scanners/nuclei/patches/go-git.patch` and `go.mod`.

### 3.3 Third-Party Go Modules (14 CVEs)
- `github.com/getkin/kin-openapi` (Upgraded to `v0.148.0`):
  - `CVE-2026-100349`, `CVE-2026-100351`, `CVE-2026-100352`, `CVE-2026-100353`, `CVE-2026-100354`
- `github.com/go-jose/go-jose/v4` (Upgraded to `v4.1.6`):
  - `CVE-2026-116587`
- `golang.org/x/text` (Upgraded to `v0.41.0`):
  - `CVE-2026-56851`
- `golang.org/x/crypto` (Upgraded to `v0.55.0`):
  - `CVE-2026-56854`
- `golang.org/x/mod` (Upgraded to `v0.40.0`):
  - `CVE-2026-56864`, `CVE-2026-56865`
- `golang.org/x/net` (Upgraded to `v0.62.0`):
  - `CVE-2026-78661`, `CVE-2026-78669`
- `google.golang.org/grpc` (Upgraded to `v1.83.1`):
  - `CVE-2026-84304`, `CVE-2026-84445`

---

## 4. Waiver Retirement & Governance Impact

- **Waiver Suppressions Required:** 0
- **Stale Suppressions Purged:** 26
- **Status in `deploy/scanners/nuclei/waivers.json`:** `PASS` (`fixed: 26`, `approved: 0`, `pending: 0`, `expired: 0`, `unhandled: 0`)
- **Isolation Boundaries Maintained:**
  - Non-root UID/GID `10001:10001`
  - Distroless runtime (`gcr.io/distroless/static-debian12:nonroot`)
  - Read-only root filesystem
  - Internal scanner bridge network (`internal: true`)
  - Anti-SSRF proxy enforcement
