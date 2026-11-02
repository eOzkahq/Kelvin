# KELVIN Operational Runbooks Catalog

This directory contains standardized, executable runbooks for responding to production platform incidents, security compromises, and operational failures.

| Runbook ID | Title | Severity | Primary Responsible Role |
| :--- | :--- | :--- | :--- |
| **[RB-01](RB-01_API_UNAVAILABILITY.md)** | API Unavailability & High Latency Triage | SEV-1 | Platform On-Call |
| **[RB-02](RB-02_WORKER_AND_QUEUE_FAILURE.md)** | Worker Fleet Crash & Redis Queue Saturation | SEV-1 / SEV-2 | Platform On-Call |
| **[RB-03](RB-03_DATABASE_FAILOVER_AND_POOLING.md)** | PostgreSQL Failover & PgBouncer Pool Recovery | SEV-1 | Database / Infra Ops |
| **[RB-04](RB-04_CREDENTIAL_COMPROMISE_AND_REVOCATION.md)** | Emergency Credential Compromise & Secret Revocation | SEV-0 / SEV-1 | Product Security Lead |
| **[RB-05](RB-05_TENANT_ISOLATION_BREACH.md)** | Suspected Multi-Tenant Data Isolation Breach | SEV-0 | Product Security Lead |
| **[RB-06](RB-06_ABNORMAL_ASSESSMENT_KILL_SWITCH.md)** | Emergency Assessment Kill Switch & Rogue Scan Interruption | SEV-1 | Incident Commander |
