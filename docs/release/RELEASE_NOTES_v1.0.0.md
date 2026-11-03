# KELVIN v1.0.0 Release Notes — General Availability (GA)

**Release Version:** `v1.0.0`  
**Release Date:** 3 November 2026  
**Status:** General Availability (GA)  

---

## 🌟 Welcome to KELVIN 1.0

KELVIN is an enterprise-grade automated security assessment platform designed to deliver orchestrated vulnerability intelligence, continuous asset discovery, rigorous risk scoring, and tamper-evident audit transparency.

v1.0.0 represents the general availability release, hardened across five comprehensive engineering phases.

---

## 🚀 Key Feature Highlights

### 1. Multi-Tenant Organization & Workspace Architecture (Phase 1)
- Strict cryptographic tenant isolation with row-level and workspace-level boundaries.
- Role-Based Access Control (RBAC) with granular permissions (`OrgAdmin`, `SecurityAnalyst`, `WorkspaceAdmin`, `Auditor`).
- Single Sign-On (SSO) via SAML 2.0 / OIDC and secure session lifecycle management.

### 2. Multi-Engine Security Assessment Pipeline (Phase 2)
- Unified orchestration engine integrating Nmap, Aqua Trivy, ProjectDiscovery Nuclei, and OWASP ZAP.
- Target boundary safety guardrails preventing accidental or unauthorized scanning of RFC 1918 private subnets, loopback interfaces, or cloud metadata services (`169.254.169.254`).
- Distributed asynchronous task queue powered by Redis with automatic retry and rate-limiting controls.

### 3. Finding Intelligence, Correlation & Risk Engine (Phase 3)
- Deterministic finding fingerprinting eliminating duplicate alerts across multi-engine assessments.
- Contextual risk engine evaluating base CVSS, asset business criticality, network exposure, and environmental factors.
- Full explainability breakdown detailing why a vulnerability received its risk score.
- Secure evidence management with cryptographic integrity verification, automated redaction of sensitive credentials, and PDF/HTML report exports.

### 4. Enterprise Integrations & Audit Transparency (Phase 4)
- Outbound signed webhooks with replay protection (HMAC-SHA256 signatures).
- Two-way Jira issue tracking and ticketing synchronization.
- Real-time Slack and Microsoft Teams notification channels.
- Tamper-evident, hash-chained audit logging providing an immutable record of all security decisions and system modifications.

### 5. Production Hardening & Operational Resilience (Phase 5)
- **Infrastructure as Code**: Modular Terraform modules for VPC networking, EKS/ECS compute, RDS PostgreSQL, Redis, and S3.
- **Container Security**: Non-root execution (`runAsNonRoot: true`), read-only root filesystems, and Cosign keyless image signing (SLSA Level 3).
- **Safe Migrations**: PostgreSQL advisory locks (`84930219`) preventing concurrent schema drift with 100% reversible up/down migration pairs.
- **Observability**: Distributed W3C `traceparent` tracing, sensitive credential masking in structured logs, and 8 core SLIs/SLOs in Prometheus/Grafana.
- **Disaster Recovery**: Automated continuous WAL archiving, S3 WORM Object Lock, validated point-in-time recovery (RPO 2m 14s, RTO 21m 45s).
- **Performance & Scale**: Verified under k6 soak testing at 500 RPS with zero memory or goroutine leaks.

---

## ⚙️ Operational Boundaries & Known Limitations

1. **Integrated Scanner Sandbox**: Scanner worker containers operate with dropped Linux capabilities and restricted egress network policies. Raw packet manipulation requiring elevated root privileges is prohibited by design.
2. **Scanner Target Concurrency**: By default, each workspace allows up to 10 concurrent active scanning tasks. High-concurrency enterprise quotas can be adjusted in workspace settings.
3. **Database Migration Policy**: Online zero-downtime schema migrations follow the expand-and-contract pattern. Destructive column drops must occur in the subsequent release milestone.

---

## 🛠️ Upgrading & Deployment

For deployment instructions and Kubernetes helm charts, refer to [`infra/k8s/`](file:///e:/Projects/kelvin%202/Kelvin/infra/k8s/) and the production runbooks in [`docs/runbooks/`](file:///e:/Projects/kelvin%202/Kelvin/docs/runbooks/).

For technical assistance or to report security findings, contact `security@kelvin.io`.
