# KELVIN Approved Software, Dependency & Scanner Inventory

## 1. Core Platform Binaries & Runtimes

| Component | Target Artifact | Approved Runtime | License | Base Container Image |
|---|---|---|---|---|
| **API Server** | `apps/api` | Go 1.23+ | Proprietary | `gcr.io/distroless/static-debian12:nonroot` |
| **Worker Engine** | `apps/worker` | Go 1.23+ | Proprietary | `debian:bookworm-slim` (Hardened, non-root `10001:10001`) |
| **Web Console** | `apps/web` | Node.js 20 LTS (Next.js) | Proprietary | `node:20-alpine` (Hardened, non-root `1001:1001`) |

---

## 2. Integrated Security Scanner Engines

| Engine | Version Pin | Source / Registry | License Verification | Execution Sandbox Policy |
|---|---|---|---|---|
| **Nmap** | `7.95-r0` | Alpine Main / Debian Official | NPSL (Compliant) | Non-root `nobody`, drops all capabilities except `CAP_NET_RAW` |
| **Trivy** | `v0.56.2` | Aqua Security Official OCI | Apache-2.0 | Read-only root filesystem, isolated ephemeral mount |
| **Nuclei** | `v3.3.4` | ProjectDiscovery Official | MIT License | Zero Linux capabilities, egress restricted via K8s NetworkPolicy |
| **OWASP ZAP** | `2.15.0` | OWASP Official Docker Hub | Apache-2.0 | Bound solely to loopback proxy port, ephemeral memory storage |

---

## 3. Database & Broker Software

| Component | Engine Version | Hosting Topology | Security Hardening |
|---|---|---|---|
| **PostgreSQL** | 16.3+ | AWS RDS Multi-AZ / Self-Managed | TLS 1.3 enforced, encrypted EBS KMS, PgBouncer role segregation |
| **Redis** | 7.2+ | AWS ElastiCache / Redis Cluster | TLS in-transit encryption, AUTH password rotation, `noeviction` |
| **Object Storage** | S3 API Compatible | AWS S3 / MinIO | AES-256 KMS SSE-KMS, TLS 1.3, Cross-Region Replication, WORM |

---

## 4. Upstream Dependency Management Verification

All direct Go module dependencies are recorded in [`go.mod`](file:///e:/Projects/kelvin%202/Kelvin/go.mod) and cryptographically checksummed in [`go.sum`](file:///e:/Projects/kelvin%202/Kelvin/go.sum).
All Node dependencies are recorded in `package.json` and locked via `package-lock.json`.

Nightly verification jobs inspect both ecosystems for CVE advisories, retracted versions, and license compliance.
