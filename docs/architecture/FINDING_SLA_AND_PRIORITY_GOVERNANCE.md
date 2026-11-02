# Finding SLA and Priority Governance Architecture

## 1. Overview
The Finding SLA and Priority Governance subsystem manages deterministic remediation deadlines, breach tracking, risk exceptions, and priority alignment across organizational boundaries. It decouples governance compliance status from the finding lifecycle while enforcing auditable remediation requirements.

## 2. SLA Lifecycle and Clock State Machine

```mermaid
stateDiagram-v2
    [*] --> ON_TRACK: Finding Ingested (Triage & Remediation Deadlines Set)
    ON_TRACK --> AT_RISK: Nearing Remediation Deadline (<= Warning Threshold)
    ON_TRACK --> BREACHED: Remediation Deadline Passed
    AT_RISK --> BREACHED: Remediation Deadline Passed
    ON_TRACK --> PAUSED: Exception or Verification Hold Active
    AT_RISK --> PAUSED: Exception or Verification Hold Active
    PAUSED --> ON_TRACK: Exception Concluded / Extended Deadline Resumed
    ON_TRACK --> MET: Finding Resolved Prior to Deadline
    AT_RISK --> MET: Finding Resolved Prior to Deadline
    BREACHED --> BREACHED_RESOLVED: Finding Resolved After Deadline
```

## 3. SLA Evaluation Engine Architecture

```mermaid
flowchart TD
    subgraph Intake
        F[Finding Detected / Ingested] --> Calc[Calculate SLA Deadlines]
        Policy[Organization SLA Policy] --> Calc
    end

    subgraph StateManagement
        Calc --> T[Finding SLA Tracker]
        Exc[Risk Exception / Hold Triggered] --> Pause[Pause SLA Clock]
        Pause --> T
        Resume[Risk Exception Expired / Revoked] --> Ext[Extend Deadline by Paused Duration]
        Ext --> T
    end

    subgraph Evaluation
        T --> Eval[Periodic / Event-driven SLA Evaluator]
        Eval --> Status{Deadline Check}
        Status -->|Resolved <= DueDate| Met[Status: MET]
        Status -->|Resolved > DueDate| BreachedResolved[Status: BREACHED_RESOLVED]
        Status -->|Open & Now > DueDate| Breached[Status: BREACHED]
        Status -->|Open & Remaining <= Warning| AtRisk[Status: AT_RISK]
        Status -->|Open & Healthy| OnTrack[Status: ON_TRACK]
    end
```

## 4. Key Architectural Guarantees
1. **Deterministic Severity Deadlines**: Standardized defaults across `CRITICAL` (14d), `HIGH` (30d), `MEDIUM` (60d), `LOW` (90d), and `INFO` (180d) with 24-72h triage windows.
2. **Deterministic Clock Suspension & Extension**: Clock pausing freezes SLA evaluation; resumption adjusts the `remediation_due_date` by the exact elapsed paused duration, preventing artificial breaches during authorized risk holds.
3. **Decoupled Governance Status**: Governance SLA status (`ON_TRACK`, `AT_RISK`, `BREACHED`, `MET`, `BREACHED_RESOLVED`) is tracked orthogonally to technical finding states (`OPEN`, `TRIAGED`, `RESOLVED`, `FALSE_POSITIVE`).
4. **Tenant Isolation**: All policies and SLA tracking records enforce strict tenant boundary isolation via composite primary keys and foreign keys.
