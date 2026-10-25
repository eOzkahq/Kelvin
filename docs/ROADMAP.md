# Kelvin Platform Engineering Roadmap (225-Issue Trajectory)

## 1. Overview & Phased Trajectory

Kelvin's product development is organized into six major evolutionary phases spanning 225 planned issues. Each phase delivers a functional, tested increment of capability while preserving zero-trust security invariants.

```mermaid
gantt
    title Kelvin Security Platform — Engineering Roadmap
    dateFormat  YYYY-MM
    section Phase 1: Foundation
    Requirements, Threat Model & Scope Engine  :active, p1_1, 2026-10, 2026-11
    API Scaffolding, DB & Queue Abstraction     :active, p1_2, 2026-11, 2026-12
    Milestone 1 Completion (Issues 01-25)      :milestone, m1, 2026-12, 0d
    section Phase 2: Engine Integration
    Sandboxed Runner & Scanner Adapters       :p2_1, 2026-12, 2027-01
    Finding Normalization Pipeline            :p2_2, 2027-01, 2027-02
    section Phase 3: Findings & Evidence
    Deduplication, Correlation & Risk Scoring :p3_1, 2027-02, 2027-03
    Executive Reporting & Export Engine        :p3_2, 2027-03, 2027-04
    section Phase 4: Enterprise & Tenancy
    Multi-Tenancy, SSO/SAML & RBAC            :p4_1, 2027-04, 2027-05
    Audit Logging & Compliance Controls        :p4_2, 2027-05, 2027-06
    section Phase 5: Continuous Monitoring
    Scheduled Scans & Change Detection        :p5_1, 2027-06, 2027-07
    Alerting & SIEM / Webhook Integrations    :p5_2, 2027-07, 2027-08
    section Phase 6: Ecosystem & Advanced AI
    Custom Plugin SDK & Marketplace           :p6_1, 2027-08, 2027-09
    AI Remediation Analysis & Verification     :p6_2, 2027-09, 2027-10
```

---

## 2. Release Milestones & Phase Breakdown

| Phase | Milestone Title | Issue Range | Focus Areas | Exit Criteria |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | **Foundation & Core Architecture** | `P1-01` to `P1-25` *(Current)* | Scope enforcement, threat model, API scaffolding, job queues, persistence, CI/CD | Secure baseline control plane; verifiable scope rejection; job state machine |
| **Phase 2** | **Scanner Engines & Worker Isolation** | `P2-26` to `P2-65` | Worker daemon, Docker sandbox, network discovery, web scanner adapters, finding normalizers | Isolated containerized execution; 3 integrated scanner engines |
| **Phase 3** | **Findings Pipeline & Risk Intelligence**| `P3-66` to `P3-110` | Vulnerability deduplication, CWE/CVE mapping, severity calculation, evidence redaction, PDF/JSON reporting | Normalized vulnerability database; zero redundant alerts for duplicate runs |
| **Phase 4** | **Multi-Tenancy & Enterprise Governance**| `P4-111` to `P4-150`| Organization hierarchies, fine-grained RBAC, OIDC/SAML authentication, tamper-proof audit trails | Multi-tenant isolation verified by penetration tests; SOC2 readiness |
| **Phase 5** | **Continuous Assessment & Automation**   | `P5-151` to `P5-185`| Cron-based scanning, differential attack surface mapping, Slack/Jira/Webhook dispatchers | Automated alerting on newly exposed services; CI/CD pipeline scanner plugin |
| **Phase 6** | **Extensibility & Advanced Analytics**  | `P6-186` to `P6-225`| Third-party plugin SDK, distributed worker clustering, heuristic prioritization, automated PoC verification | Community plugin ecosystem; enterprise-scale distributed deployment |

---

## 3. Branching & Contribution Strategy

Kelvin enforces strict branch protection and Trunk-Based Gitflow with squash merges. Direct commits to `main` are prohibited.

```mermaid
gitGraph
    commit id: "v0.0.1 (Initial)"
    branch develop
    checkout develop
    commit id: "feat: repo structure"
    branch feature/scope-validator
    checkout feature/scope-validator
    commit id: "feat: anti-ssrf check"
    commit id: "test: rebinding cases"
    checkout develop
    merge feature/scope-validator id: "PR #25 merged"
    branch feature/job-queue
    checkout feature/job-queue
    commit id: "feat: redis queue abstraction"
    checkout develop
    merge feature/job-queue id: "PR #24 merged"
    checkout main
    merge develop tag: "v0.1.0-alpha (Phase 1)"
```

### Git Workflow Rules
1. **Branch Naming:**
   - Features: `feature/<issue-number>-<short-description>` (e.g. `feature/p1-25-target-validation`)
   - Bugfixes: `fix/<issue-number>-<short-description>`
   - Documentation: `docs/<issue-number>-<short-description>`
2. **Pull Request Quality Gates:**
   - 100% passing automated CI (linting, static analysis, unit tests)
   - Mandatory security negative tests for input validation and authentication
   - Minimum 1 approved code review from code owners
   - Linear Git history maintained via Squash & Merge
