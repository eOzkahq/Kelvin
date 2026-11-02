# Enterprise Assignment and Escalation Rules Architecture

## 1. Overview
The Enterprise Assignment and Escalation Rules subsystem extends Kelvin's remediation capabilities by providing multi-tenant, policy-driven owner assignment, fallback hierarchies, and automated escalation chains triggered by SLA breach conditions.

## 2. Assignment and Escalation Architecture

```mermaid
flowchart TD
    FindingEvent["Finding Created / Ingested"] --> RuleEngine["Assignment Rule Engine"]
    RuleEngine --> CriteriaCheck{"Match Priority Rules?\n(Workspace / Tag / Vuln Class / Severity)"}

    CriteriaCheck -- Matched --> ValidateAssignee{"Is Primary Assignee Active?"}
    ValidateAssignee -- Active --> AssignPrimary["Assign Primary Owner (Source: RULE_MATCH)"]
    ValidateAssignee -- Inactive --> FallbackCheck{"Rule Fallback Available & Active?"}
    FallbackCheck -- Yes --> AssignFallback["Assign Fallback Owner (Source: DEFAULT_FALLBACK)"]
    FallbackCheck -- No --> OrgDefault["Assign Org Default Owner (Source: DEFAULT_FALLBACK)"]

    CriteriaCheck -- No Match --> OrgDefault

    AssignPrimary --> SLAMonitor["Monitor Finding SLA Tracker"]
    AssignFallback --> SLAMonitor
    OrgDefault --> SLAMonitor

    SLAMonitor --> EscalationCheck{"SLA Breach / Warning Triggered?"}
    EscalationCheck -- Yes --> ManualLock{"Manual Override Active?"}
    ManualLock -- Active --> SkipAuto["Skip Automated Escalation (Audit Notice)"]
    ManualLock -- Inactive --> Escalate["Escalate to Next Level Policy (Source: ESCALATION)"]
```

## 3. Anti-Circular Escalation & Cycle Defense

```mermaid
flowchart LR
    P1["Policy L1 (Dev Lead)"] --> P2["Policy L2 (SecOps Lead)"]
    P2 --> P3["Policy L3 (CISO)"]
    P3 -.->|Cycle Detected - Rejected!| P1
```

## 4. Key Architectural Guarantees
1. **Deterministic Rule Priority**: Rules are evaluated in strict priority order (lower priority integer evaluated first); the first rule whose workspace, target tag, vulnerability class, and severity criteria match is selected.
2. **Strict Identity & Tenant Isolation**: Assignments and escalations validate assignee activity and organization tenancy via `EntityValidator`. Inactive or cross-tenant entities are strictly rejected.
3. **Graceful Fallback Hierarchy**: If a matched rule's primary assignee is inactive, the engine falls back to the rule-level designated fallback, and subsequently to the organization default owner.
4. **Anti-Circular Escalation Defense**: Escalation chains are verified via graph cycle detection during policy configuration and execution, capped at a maximum depth ceiling (`MaxEscalationDepth = 5`).
5. **Auditable Manual Override**: Authorized operators can manually reassign findings with mandatory justification, placing a lock on automated escalation policies to prevent conflicting automated reassignments.
