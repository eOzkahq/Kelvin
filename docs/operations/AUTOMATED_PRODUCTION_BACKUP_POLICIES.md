# KELVIN Automated Production Backup Policies Specification

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Approved — Production Engineering Specification |
| **Milestone** | Phase 5 — Production Hardening, Deployment & Release (`P5-14`) |
| **Parent Roadmap** | [KELVIN Engineering Roadmap](../ISSUE-02_ENGINEERING_ROADMAP.md) |
| **Parent Issue** | Issue #370 (`P5-14`) |
| **Policy Reference** | [`deploy/backup/backup-policy.yaml`](../../deploy/backup/backup-policy.yaml) |
| **Review Cadence** | Quarterly |
| **Classification** | Internal — Enterprise Data Protection Standard |

---

## 1. Backup Architecture & Resilience Topologies

KELVIN establishes an automated, encrypted, multi-tier backup architecture designed to satisfy strict recovery point and recovery time baselines:

```mermaid
flowchart TD
    subgraph PrimaryRegion ["Primary Production Region (us-east-1)"]
        subgraph LiveData ["Live Persistence Tier (Zone 4)"]
            PG["PostgreSQL 16 Multi-AZ"]
            S3Primary["S3 Evidence & Reports (SSE-KMS)"]
        end

        subgraph ContinuousBackup ["Continuous Backup Tier"]
            WAL["Continuous WAL Archiving (pgBackRest to S3)"]
            DailySnapshot["Automated Daily Snapshot (02:00 UTC)"]
            WeeklySnapshot["Automated Weekly Snapshot (Sunday 03:00 UTC)"]
        end
    end

    subgraph DRRegion ["Disaster Recovery Region (us-west-2)"]
        S3Replica["S3 Cross-Region Replica (WORM Object Lock)"]
        KMS_DR["Dedicated Backup KMS CMK (Separate IAM Vault)"]
    end

    PG -->|Continuous WAL Stream| WAL
    PG -->|Daily EBS Volume Snapshots| DailySnapshot
    DailySnapshot --> WeeklySnapshot
    S3Primary -->|S3 Cross-Region Replication (CRR)| S3Replica
    KMS_DR -->|Encrypts Replica Data| S3Replica
```

---

## 2. Recovery Objectives (RPO & RTO)

| Persistence Component | Recovery Point Objective (RPO) | Recovery Time Objective (RTO) | Backup Mechanism |
| :--- | :--- | :--- | :--- |
| **PostgreSQL Database** | **<= 5 minutes** | **<= 30 minutes** | Continuous WAL archiving + Automated Multi-AZ Snapshots |
| **Evidence & Report S3** | **<= 15 minutes** | **<= 1 hour** | S3 Cross-Region Replication (CRR) + Versioning |
| **Kubernetes State / IaC** | **0 minutes** (Deterministic) | **<= 15 minutes** | Git version-controlled Terraform & Kustomize manifests |
| **Redis Broker (Queues)** | **<= 1 second** | **<= 5 minutes** | Append-Only File (AOF) with `everysec` fsync + Multi-AZ Sentinel |

---

## 3. Storage Retention & Immutability Governance

1. **Database Retention Schedule:**
   - Daily snapshots: retained for **35 days** with Point-In-Time-Recovery (PITR) support to any second within the window.
   - Weekly full backups: retained for **90 days**.
   - Monthly compliance archives: retained for **365 days** (or tenant compliance SLA).
2. **WORM Object Lock & Ransomware Defense:**
   - Evidence and report buckets enforce S3 Object Lock in **COMPLIANCE** mode for 365 days.
   - Even root cloud credentials cannot delete or truncate compliance-locked evidence objects before expiration.
3. **IAM Privilege Segregation:**
   - Primary application and worker IAM roles (`kelvin-api-role`, `kelvin-worker-role`) are explicitly denied `s3:DeleteBucket`, `s3:DeleteObject`, and `rds:DeleteDBSnapshot` permissions.
   - Restoration and snapshot deletion can only be authorized by the dedicated, hardware-MFA-enforced `kelvin-backup-operator-role`.

---

## 4. Monitoring & Integrity Verification

- **Automated Alerts:**
  - `BackupJobFailed`: Triggered immediately if an automated daily snapshot or WAL segment transfer fails.
  - `SnapshotAgeAlert`: Triggered if the most recent database snapshot is older than 26 hours.
- **Verification Cadence:**
  - Automated integrity script `scripts/backup/verify-backup-integrity.sh` runs every 24 hours.
  - Quarterly automated restore drills test end-to-end database recreation in an isolated staging VPC (Issue #371 / `P5-15`).
