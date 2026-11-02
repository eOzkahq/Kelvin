# Finding Status Transition Commands and API

## Overview

The Finding Status Transition Command subsystem enables authenticated security analysts and internal orchestration services to move findings along the defined lifecycle state machine. It guarantees strict multi-tenant boundary isolation, verifies state validity against established transition matrices, mandates documentation rationale for sensitive overrides, and protects against silent write collisions via optimistic concurrency control.

---

## Architecture & Workflow

```mermaid
flowchart TD
    Client["Client / Analyst"] -->|"POST /api/v1/findings/{id}/transition"| Router["HTTP Router & Auth Middleware"]
    Router --> CheckTenant{"Valid Tenant Context?"}
    CheckTenant -- No --> Err401["401 Unauthenticated"]
    CheckTenant -- Yes --> Handler["handleTransitionFinding"]

    Handler --> ParseUUID{"Valid UUID v4?"}
    ParseUUID -- No --> Err422ID["422 Validation Failed (id)"]
    ParseUUID -- Yes --> ParseJSON{"Valid JSON Body?"}

    ParseJSON -- No --> Err400["400 Malformed JSON"]
    ParseJSON -- Yes --> CheckReason{"Sensitive Transition?\n(FALSE_POSITIVE | ACCEPTED_RISK)"}

    CheckReason -- "Missing Reason" --> Err422Reason["422 Validation Failed (reason required)"]
    CheckReason -- "Valid / Non-sensitive" --> Repo["PostgresFindingRepository.UpdateFindingStatus"]

    subgraph DBTx ["Atomic Optimistic Update"]
        Fetch["Fetch Finding (tenant_id, finding_id)"]
        ValidateSM{"Permitted Transition?"}
        ValidateSM -- No --> Err409SM["409 Conflict (Illegal Transition)"]
        ValidateSM -- Yes --> ExecUpdate["UPDATE findings SET status=$new, updated_at=$now\nWHERE tenant_id=$tenant AND id=$id AND status=$from"]
        ExecUpdate --> CheckRows{"Rows Affected == 1?"}
        CheckRows -- No --> ConcurrencyCheck["Check if finding exists / status changed"]
        ConcurrencyCheck -- "Status Changed" --> Err409Conflict["409 Conflict (Concurrent Modification)"]
        ConcurrencyCheck -- "Finding Missing" --> Err404["404 Not Found (IDOR-safe)"]
        CheckRows -- Yes --> RecordEvent["INSERT INTO finding_events (triage event)"]
    end

    Repo --> Return200["200 OK (TransitionFindingResponse: finding + event)"]
```

---

## Transition Rules & State Constraints

| Source Status | Permitted Target Statuses | Mandatory Reason? |
|---|---|---|
| `NEW` | `CONFIRMED`, `IN_PROGRESS`, `FALSE_POSITIVE`, `ACCEPTED_RISK` | Yes (for `FALSE_POSITIVE`, `ACCEPTED_RISK`) |
| `CONFIRMED` | `IN_PROGRESS`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `RESOLVED` | Yes (for `FALSE_POSITIVE`, `ACCEPTED_RISK`) |
| `IN_PROGRESS` | `RESOLVED`, `FALSE_POSITIVE`, `ACCEPTED_RISK` | Yes (for `FALSE_POSITIVE`, `ACCEPTED_RISK`) |
| `RESOLVED` | `REOPENED` | No |
| `REOPENED` | `IN_PROGRESS`, `RESOLVED`, `FALSE_POSITIVE`, `ACCEPTED_RISK` | Yes (for `FALSE_POSITIVE`, `ACCEPTED_RISK`) |
| `FALSE_POSITIVE` | None (Terminal) | N/A |
| `ACCEPTED_RISK` | None (Terminal) | N/A |

---

## Optimistic Concurrency Control

To prevent silent overwrites when multiple triage analysts or automated workflows update a finding simultaneously:
1. The repository reads the current finding status.
2. The SQL `UPDATE` statement predicates on `status = $fromStatus`.
3. If zero rows are affected, the repository re-inspects the record:
   - If the finding exists with a different status, an optimistic concurrency conflict error is returned (`409 Conflict`).
   - If the finding does not exist or belongs to another tenant, an IDOR-safe `404 Not Found` is returned.

---

## Auditability & Event Traceability

Every successful transition generates a corresponding `FindingEvent` record (`event_type = 'TRIAGE'`) persisted atomically with the finding status change. The audit event captures:
- `from_status` and `to_status`
- `actor_user_id` (when initiated by authenticated user)
- `note` / reason
- `correlation_id` propagated from the incoming request context
- Timestamp (`created_at`)
