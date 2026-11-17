# KELVIN — Milestone 9 (M9) Implementation Tracker
## Worker Infrastructure • Scanner Isolation • Target Authorization • Egress Security • Real Scanning • Findings • Validation

**Status:** IN PROGRESS  
**Canonical Repository:** `https://github.com/eOzkahq/Kelvin`  
**Current Canonical Commit:** `957cee1`  
**Last Updated:** Tuesday, November 17, 2026

---

## 1. Milestones Overview

| Milestone | Title | GitHub Milestone | Status | Issues Open/Closed | PRs Merged |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **M9.1** | Worker Deployment and Redis Connectivity | Milestone #14 | **ACTIVE** | 0 / 0 | 0 |
| **M9.2** | Scanner Isolation using Podman/crun | Milestone #15 | PLANNED | 0 / 0 | 0 |
| **M9.3** | Target Authorization, Scope Enforcement & SSRF | Milestone #16 | PLANNED | 0 / 0 | 0 |
| **M9.4** | Controlled Egress Proxy & Network Restrictions | Milestone #17 | PLANNED | 0 / 0 | 0 |
| **M9.5** | Real Scanner Execution (Nmap, Nuclei, ZAP) | Milestone #18 | PLANNED | 0 / 0 | 0 |
| **M9.6** | Finding Normalization & Evidence Collection | Milestone #19 | PLANNED | 0 / 0 | 0 |
| **M9.7** | End-to-End Real Scan Validation | Milestone #20 | PLANNED | 0 / 0 | 0 |

---

## 2. Issues & PR Work Breakdown Structure

| Milestone | Issue # | Title | Branch | PR # | Commit SHA | Tests | Review | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| M9.1 | #640 | M9.1-01: Redis Streams Consumer Group, Claim & Distributed Lease Engine | `feat/m9-1-redis-consumer-engine` | #644 | `1e38211` | Passed (100%) | Passed | MERGED |
| M9.1 | #641 | M9.1-02: Authoritative Assessment Job Envelope & Schema Contract | `feat/m9-1-job-envelope-state-sync` | TBD | Pending | Passed (100%) | Passed | Ready for PR |
| M9.1 | #642 | M9.1-03: Worker Daemon Lifecycle, Heartbeats, State Sync & Graceful Shutdown | `feat/m9-1-worker-daemon-lifecycle` | TBD | TBD | Pending | Pending | In Backlog |
| M9.1 | #643 | M9.1-04: Worker Systemd Service, Packaging & Staging Deployment Hardening | `feat/m9-1-worker-deployment-hardening` | TBD | TBD | Pending | Pending | In Backlog |

---

## 3. Active Safety Invariants

- `KELVIN_CANARY_ONLY=true` (strictly enforced in staging/production)
- `kelvin-worker.service` is `inactive` and `disabled` on Oracle Cloud until explicit deployment approval
- 0 scanner jobs and 0 active scans
- All production migrations require separate approval and disposable test database validation
- Rollback images preserved
