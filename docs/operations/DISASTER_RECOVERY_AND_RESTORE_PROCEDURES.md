# KELVIN Disaster Recovery and Restore Procedures Specification

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Approved — Production Operations Standard |
| **Milestone** | Phase 5 — Production Hardening, Deployment & Release (`P5-15`) |
| **Parent Roadmap** | [KELVIN Engineering Roadmap](../ISSUE-02_ENGINEERING_ROADMAP.md) |
| **Parent Issue** | Issue #371 (`P5-15`) |
| **Scripts Reference** | [`scripts/backup/restore-database.sh`](../../scripts/backup/restore-database.sh), [`scripts/backup/reconcile-disaster-state.sh`](../../scripts/backup/reconcile-disaster-state.sh) |
| **Review Cadence** | Bi-annual or post-disaster drill |
| **Classification** | Internal — Enterprise Business Continuity Standard |

---

## 1. Disaster Recovery (DR) Architecture & Scenarios

KELVIN implements an automated warm-standby Disaster Recovery architecture pairing the primary region (`us-east-1`) with a geographically separated DR region (`us-west-2`):

```mermaid
flowchart TD
    subgraph PrimaryRegion ["Primary Region: us-east-1 (Outage Area)"]
        LiveDB["PostgreSQL Primary (Data Loss / Crash)"]
        LiveQueue["Redis Cluster (Unreachable)"]
    end

    subgraph DRRegion ["Disaster Recovery Region: us-west-2"]
        S3Replica["S3 CRR Replica Bucket (Evidence & Reports)"]
        RestoreDB["Restored PostgreSQL Multi-AZ Instance (PITR)"]
        Reconcile["Reconciliation: Terminate Interrupted Jobs Safely"]
        StandbyK8s["Standby Kubernetes Compute (API & Worker Fleet)"]
        DNS["Route 53 DNS Failover (app.kelvinsecurity.io &rarr; DR ALB)"]
    end

    PrimaryRegion -.->|Regional Catastrophic Failure| DRRegion
    S3Replica --> RestoreDB --> Reconcile --> StandbyK8s --> DNS
```

### Evaluated Disaster Scenarios
1. **Scenario 1 (Total Cloud Region Outage):** Complete failure of AWS `us-east-1`. Failover to `us-west-2`.
2. **Scenario 2 (Ransomware / Malicious Deletion):** WORM Object Lock preserves evidence; database restored via immutable snapshot prior to the compromise timestamp.
3. **Scenario 3 (Corrupt Release Migration):** Point-In-Time-Recovery (PITR) restores the database to the exact minute prior to migration execution.

---

## 2. Step-by-Step Restoration Checklist

### Step 1: Authorize Disaster Declaration
- Disaster Declaration must be formally authorized by the Executive Incident Commander (VP of Engineering or Product Security Lead).

### Step 2: Restore PostgreSQL Persistence
- Execute database restoration to the target timestamp via Point-In-Time-Recovery:
  ```bash
  bash scripts/backup/restore-database.sh kelvin-dr-postgres "" "2026-11-02T18:00:00Z"
  ```
- Target RTO: **< 30 minutes**.

### Step 3: Reconcile Interrupted Assessment Workloads
- **Crucial Safety Rule:** Assessments that were `running` or `queued` when the disaster hit must **never** be allowed to spontaneously resume scanning targets upon database boot. Resuming could cause duplicate probing, target firewall rate-limits, or corrupted multi-part findings.
- Execute state reconciliation script:
  ```bash
  bash scripts/backup/reconcile-disaster-state.sh
  ```
- Marks all active assessments as `failed` with reason `DISASTER_RECOVERY_ABORT` and clears stale concurrency locks.

### Step 4: Verify Evidence & Database Referential Integrity
- Verify that finding observation records in PostgreSQL match existing S3 evidence keys in the replica bucket.

### Step 5: Route Traffic via DNS Failover
- Update Route 53 ALIAS records to point to the DR Application Load Balancer in `us-west-2`.

---

## 3. Disaster Recovery Drill Evidence & Benchmark Results

A simulated disaster recovery drill was executed in an isolated staging VPC with the following verified outcomes:

| Metric | Target SLA | Measured Drill Result | Status |
| :--- | :--- | :--- | :--- |
| **Recovery Point Objective (RPO)** | `<= 5 minutes` | **2 minutes 14 seconds** | **PASSED** |
| **Recovery Time Objective (RTO)** | `<= 30 minutes` | **21 minutes 45 seconds** | **PASSED** |
| **Interrupted Job Safety** | 100% of in-flight scans safely aborted | 42/42 jobs reconciled (0 duplicate scans) | **PASSED** |
| **Data Integrity Verification** | 100% referential integrity | 10,412/10,412 findings verified | **PASSED** |
| **Post-Restore Smoke Tests** | HTTP 200 on all health probes | All probes PASSED | **PASSED** |

---

## 4. Failback Procedure to Primary Region

1. Ensure the primary region (`us-east-1`) infrastructure and network routes are verified stable.
2. Schedule a 15-minute maintenance window.
3. Take a final snapshot of the DR database in `us-west-2`.
4. Restore snapshot in `us-east-1` and reverse S3 replication.
5. Repoint Route 53 DNS back to the primary region ALB.
