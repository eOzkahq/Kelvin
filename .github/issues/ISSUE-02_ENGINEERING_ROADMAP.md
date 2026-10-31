---
title: "[ROADMAP] Master Engineering Roadmap & 225-Issue Evolutionary Lifecycle"
labels: ["kind/roadmap", "area/project-management", "area/docs", "priority/high", "status/accepted"]
assignees: ["@lead-maintainer", "@core-pm"]
milestone: "Master Release Roadmap (Phases 1-6)"
parent_issue: null
---

# 🗺️ [ROADMAP] Master Engineering Roadmap & 225-Issue Evolutionary Lifecycle

## 1. Executive Overview & Delivery Strategy

The Kelvin Security Platform is engineered across a multi-phased trajectory spanning **225 structured issues** divided into **six major engineering phases**. Each phase produces a self-contained, validated, and security-hardened capability increment.

This master roadmap establishes project milestones, timeline projections, repository branching workflows, and tracking metrics utilizing GitHub's native Mermaid visualization and Project Health Insights.

---

## 2. Project Lifecycle & Timeline Diagrams

### 2.1 Multi-Phase Engineering Gantt Chart
The roadmap is scheduled across a 12-month engineering delivery timeline, ensuring rigorous security validation between milestone boundaries:

```mermaid
gantt
    title Kelvin Security Platform — Engineering Lifecycle (225 Issues)
    dateFormat  YYYY-MM
    axisFormat  %b %Y

    section Phase 1: Foundation (P1-01 to P1-25)
    Threat Model, Scoping Engine & Anti-SSRF     :done, p1_1, 2026-10, 2026-11
    API Scaffolding, PostgreSQL RLS & Queue FSM :done, p1_2, 2026-11, 2026-12
    Milestone 1 Baseline Sign-Off               :milestone, m1, 2026-12, 0d

    section Phase 2: Engine Integration (P2-01 to P2-45)
    Scanner Architecture & Adapter Contracts     :active, p2_1, 2026-12, 2027-01
    Built-in Checks, ZAP Baseline & Nuclei Engine:active, p2_2, 2027-01, 2027-02
    Worker Orchestration, Egress & Resource Caps :p2_3, 2027-01, 2027-02
    Result Parsing & Canonical Schema Normalizer :p2_4, 2027-02, 2027-03
    Milestone 2 MVP Engine Release               :milestone, m2, 2027-03, 0d

    section Phase 3: Findings & Evidence (P3-01 to P3-45)
    Vulnerability Deduplication & Fingerprinting :p3_1, 2027-03, 2027-04
    Remediation Tracking & Evidence Redaction    :p3_2, 2027-03, 2027-04
    Report Generation (PDF / CSV / JSON)         :p3_3, 2027-04, 2027-05
    Milestone 3 Findings Intelligence            :milestone, m3, 2027-05, 0d

    section Phase 4: Enterprise & Governance (P4-01 to P4-40)
    Multi-Organization Hierarchy & SAML/OIDC SSO :p4_1, 2027-05, 2027-06
    Fine-Grained RBAC & Tamper-Proof Audit Trail :p4_2, 2027-06, 2027-07
    Milestone 4 Enterprise Ready                 :milestone, m4, 2027-07, 0d

    section Phase 5: Continuous Monitoring (P5-01 to P5-35)
    Cron Scheduling & Attack Surface Monitoring  :p5_1, 2027-07, 2027-08
    SIEM, Slack, Jira & Webhook Dispatchers      :p5_2, 2027-08, 2027-09
    Milestone 5 Continuous Protection            :milestone, m5, 2027-09, 0d

    section Phase 6: Extensibility & AI (P6-01 to P6-35)
    Scanner Plugin SDK & Registry Protocol       :p6_1, 2027-09, 2027-10
    AI Remediation Analysis & Verification Engine:p6_2, 2027-10, 2027-11
    Milestone 6 Platform v1.0 GA                 :milestone, m6, 2027-11, 0d
```

---

### 2.2 Repository Branching & Contribution Model (Gitgraph)
Kelvin enforces strict Trunk-Based Gitflow with required pull request reviews, status checks, and linear history. Direct commits to `main` are strictly blocked.

```mermaid
gitGraph
    commit id: "v0.1.0-alpha: Init"
    commit id: "Phase 1 Foundation" tag: "M1"
    branch develop
    checkout develop
    commit id: "feat: job queue fsm"
    
    branch feat/p2-01-scanner-matrix
    checkout feat/p2-01-scanner-matrix
    commit id: "docs: p2-01 scanner matrix"
    commit id: "test: matrix conformance"
    checkout develop
    merge feat/p2-01-scanner-matrix id: "squash-merge #102"
    
    branch feat/p2-08-scanner-images
    checkout feat/p2-08-scanner-images
    commit id: "docker: unprivileged zap runner"
    commit id: "docker: nuclei runner digest"
    checkout develop
    merge feat/p2-08-scanner-images id: "squash-merge #108"
    
    branch release/v0.2.0-beta
    checkout release/v0.2.0-beta
    commit id: "chore: bump version v0.2.0-beta"
    commit id: "test: e2e scanner verification"
    
    checkout main
    merge release/v0.2.0-beta id: "Release v0.2.0-beta" tag: "v0.2.0-beta"
    
    branch hotfix/anti-ssrf-dns-pinning
    checkout hotfix/anti-ssrf-dns-pinning
    commit id: "fix: socket-level dns rebind guard"
    checkout main
    merge hotfix/anti-ssrf-dns-pinning id: "Hotfix v0.2.1" tag: "v0.2.1"
    checkout develop
    merge main id: "sync main to develop"
```

---

## 3. Release Milestones & Phased Issue Allocation

| Phase | Milestone Title | Issues | Focus Areas | Exit Criteria |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | **Foundation & Core Architecture** | `P1-01` to `P1-25` | Scope engine, Threat model, Go API gateway, PostgreSQL RLS, Redis job FSM, CI/CD | All RFC-1918 addresses rejected; DB migrations tested; deterministic state machine |
| **Phase 2** | **Assessment Engine & Scanner Integrations** | `P2-01` to `P2-45` | Rootless worker sandboxes, Preflight, TLS, ZAP Baseline, Nuclei catalog, Output parsers, Canonical normalizer | Scanners run in unprivileged containers; output converts into `finding.v1.json`; E2E test passes |
| **Phase 3** | **Findings Intelligence & Reporting** | `P3-01` to `P3-45` | Vulnerability deduplication, CWE/CVSS scoring, finding lifecycle, evidence redaction, PDF/JSON export | Zero redundant findings across repeated scans; automated token redaction; report downloads |
| **Phase 4** | **Multi-Tenancy & Enterprise Governance** | `P4-01` to `P4-40` | Organizations, Teams, SAML 2.0 / OIDC SSO, Fine-grained RBAC, Cryptographic audit log | Cross-tenant isolation verified by pentest; immutable audit trails; SOC 2 Type 1 ready |
| **Phase 5** | **Continuous Assessment & Automation** | `P5-01` to `P5-35` | Recurring cron assessments, Delta asset discovery, Webhooks, Slack / Jira bidirectionality | Automated notification on newly discovered CVEs; diff engine highlights attack surface changes |
| **Phase 6** | **Extensibility, Marketplace & Advanced AI** | `P6-01` to `P6-35` | Custom Scanner SDK, Third-party plugins, AI-guided remediation analysis, Safe PoC verification | Community scanner plugin published; LLM assists analyst with verified patch guidance |

---

## 4. Built-in GitHub Insights & Project Health Guidance

To maintain enterprise transparency, contributor velocity, and software supply chain integrity, team leads and open-source contributors must monitor the following GitHub Insights metrics:

### 4.1 Contributors Graph (Team Velocity & Ownership)
* **Location:** `Repository -> Insights -> Contributors`
* **Purpose:** Evaluates commit volume, lines of code added/deleted over time, and active maintainer distribution.
* **Target Health Metrics:**
  - Healthy distribution of commits across core team members (avoiding single-point-of-failure "bus factor").
  - Predictable weekly commit pacing aligned with sprint cycles.
  - Review of onboarding velocity for new community contributors.

### 4.2 Commits & Activity Graph (Frequency & Maintenance Cadence)
* **Location:** `Repository -> Insights -> Commits / Code Frequency`
* **Purpose:** Tracks code churn, pull request merge frequency, and active maintenance index.
* **Target Health Metrics:**
  - Steady code frequency without erratic multi-month stagnation.
  - Pull Request cycle time under 48 hours for review and merge.
  - Clean squash merges maintaining a high signal-to-noise ratio in git history.

### 4.3 Network Graph (Forks & Upstream Ecosystem Alignment)
* **Location:** `Repository -> Insights -> Network`
* **Purpose:** Visualizes all forks, external branches, and collaborative research initiatives across the ecosystem.
* **Target Health Metrics:**
  - Identifies active research forks experimenting with new scanner adapters (e.g. Trivy, Amass, Semgrep).
  - Assesses whether forks are rebasing cleanly against `main` or drifting out of sync.
  - Facilitates proactive outreach to researchers contributing enhancements.

### 4.4 Dependency Graph & Software Supply Chain Security
* **Location:** `Repository -> Insights -> Dependency Graph & Security Advisories`
* **Purpose:** Automatically scans and inventories every third-party Go module (`go.mod`), npm package (`package.json`), and container base image.
* **Security & Compliance Requirements:**
  - Zero critical or high-severity vulnerabilities in dependencies (monitored by Dependabot / Trivy CI).
  - Automated generation of Software Bill of Materials (SBOM) in SPDX and CycloneDX formats on every release tag.
  - Compatibility verification with Kelvin's Apache-2.0 licensing policy.

---

## 5. Review & Approval Sign-Off

- [x] 6-phase trajectory and 225-issue allocation reviewed.
- [x] Mermaid Gantt Chart and Gitgraph diagrams validated for GitHub rendering.
- [x] Phase 2 assessment engine milestones synchronized with Workstreams A through E.
- [x] GitHub Insights health monitoring standards formalized for core maintainers.

