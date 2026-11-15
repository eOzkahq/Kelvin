# KELVIN Software Supply Chain and Artifact Verification Specification

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Approved — Production Release Standard |
| **Milestone** | Phase 5 — Production Hardening, Deployment & Release (`P5-08`) |
| **Parent Roadmap** | [KELVIN Engineering Roadmap](../ISSUE-02_ENGINEERING_ROADMAP.md) |
| **Parent Issue** | Issue #364 (`P5-08`) |
| **Workflow Reference** | [`.github/workflows/artifact-security.yml`](../../.github/workflows/artifact-security.yml) |
| **Review Cadence** | Bi-annual |
| **Classification** | Internal — Enterprise Security Baseline |

---

## 1. Supply Chain Architecture & SLSA Level 3 Framework

KELVIN adheres to the **Supply-chain Levels for Software Artifacts (SLSA) Level 3** framework to guarantee that every production container image and binary is tamper-evident, cryptographically signed, and traceable to verified source code:

```mermaid
flowchart TD
    subgraph SourceCode ["Source Code Repository"]
        Commit["Git Commit SHA (Signed GPG/SSH)"]
        TaggedRelease["Release Tag (v1.0.0)"]
    end

    subgraph BuildPipeline ["Secure Isolated Build Environment"]
        PinnedBase["Pinned Base Images (@sha256 digest)"]
        Build["Deterministic Container Compilation"]
        Syft["Syft: Generate CycloneDX & SPDX SBOM"]
        Trivy["Trivy: CVE Vulnerability Scan (Zero CRITICAL)"]
        Cosign["Cosign: Keyless Sigstore Signature & OIDC Attestation"]
    end

    subgraph Registry ["Container Registry (GHCR / AWS ECR)"]
        SignedImage["Immutable Image: kelvin-api@sha256:..."]
        Attestation["SLSA In-Toto Provenance Attestation"]
        SBOMArtifact["CycloneDX SBOM Envelope"]
    end

    subgraph Admission ["Production Admission Controller (Kyverno / OPA)"]
        Gate{"Verify Signature & Digest"}
        Deploy["Allow Production Pod Scheduling"]
        Reject["Block Deployment (HTTP 403 / Pod Rejection)"]
    end

    Commit --> Build
    PinnedBase --> Build
    Build --> Syft --> SBOMArtifact --> Registry
    Build --> Trivy --> Cosign
    Cosign --> SignedImage --> Registry
    Cosign --> Attestation --> Registry

    Registry --> Gate
    Gate -->|Valid Signature + Digest| Deploy
    Gate -->|Missing Signature or Mutable Tag| Reject
```

---

## 2. Base Image Pinning & Digest Governance

Mutable container tags (such as `:latest`, `:16-alpine`, `:v1`) are strictly prohibited in production Kubernetes deployments. Every container image must be referenced by its immutable SHA-256 cryptographic digest:

| Workload | Base Image Reference | Pinned Digest Standard |
| :--- | :--- | :--- |
| **Go API** | `gcr.io/distroless/static-debian12` | Strict `@sha256:...` digest pin |
| **Go Worker** | `gcr.io/distroless/static-debian12` | Strict `@sha256:...` digest pin |
| **Frontend UI** | `nginx:1.27-alpine` | Strict `@sha256:...` digest pin |
| **PostgreSQL** | `postgres:16.2-alpine` | Strict `@sha256:...` digest pin |
| **Redis Broker** | `redis:7.2-alpine` | Strict `@sha256:...` digest pin |
| **Nuclei Sandbox** | `projectdiscovery/nuclei:v3.3.0` | Controlled in `deploy/scanners/images.lock.json` |
| **ZAP Sandbox** | `zaproxy/zap-stable:2.15.0` | Controlled in `deploy/scanners/images.lock.json` |

---

## 3. Vulnerability Severity Thresholds & Blocking Rules

All container images and dependency manifests are evaluated against the following blocking gates prior to signing:

| Vulnerability Severity | Blocking Threshold | Remediation SLA | Exception Allowance |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | **0 Allowed** (Hard Deployment Blocker) | 24 Hours | Requires CISO approval & compensating WAF rule |
| **HIGH** | **0 Allowed with Vendor Patch** | 7 Days | Approved if no fix exists and unexploitable in runtime |
| **MEDIUM** | Allowed with tracking ticket | 30 Days | Non-blocking |
| **LOW / INFO** | Allowed | Routine maintenance | Non-blocking |

---

## 4. Software Bill of Materials (SBOM) Standards

- **Standard Formats:** CycloneDX 1.5 JSON (`*-cyclonedx.json`) and SPDX 2.3 JSON (`*-spdx.json`).
- **Storage:** Persisted as GitHub Actions release artifacts and pushed to the container registry as OCI artifacts attached to the image digest.
- **Auditing:** Enables rapid CVE impact analysis during zero-day disclosure events across all production dependencies.

---

## 5. Scanner Runtime Image Release Pipeline (ADR-0008)

The scanner execution platform operates under strict release governance:
- **Registry Namespaces:** `ghcr.io/inkesk-dozing/kelvin/scanner-zap` and `ghcr.io/inkesk-dozing/kelvin/scanner-nuclei`.
- **Target Platform:** `linux/arm64` (native ARM64 runner or verified QEMU binfmt emulation).
- **Execution Account:** Unprivileged UID/GID `10001:10001` with `--read-only` rootfs and dropped capabilities (`--cap-drop=ALL`).
- **Supply Chain Signing:** Sigstore Cosign keyless signing via GitHub Actions OIDC (`https://token.actions.githubusercontent.com`).
- **Attestations:** SLSA build provenance and CycloneDX SBOM attestations attached to the exact registry manifest digest.
- **Authoritative Manifest:** `deploy/scanners/images.lock.json` remains strictly `not-released` until all gates pass. The worker daemon fails closed if live container execution is attempted against uncertified images.
- **Automated Gates:** Verified by `scripts/scanners/test-scanner-release-pipeline.sh` (15 acceptance conditions) and `apps/worker/internal/manifest/scanner_release_test.go`.
