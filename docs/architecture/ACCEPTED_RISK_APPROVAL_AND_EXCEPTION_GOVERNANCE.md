# Accepted-Risk Approval and Exception Governance Architecture

## 1. Overview
The Accepted-Risk Approval and Exception Governance subsystem manages the formal lifecycle for risk exceptions, business justifications, and compensating control waivers. It enforces separation of duties, mandatory dual approval for critical risks, strict maximum duration ceilings, and automated expiration state transitions without compromising underlying audit or evidence data.

## 2. Risk Exception Approval Lifecycle

```mermaid
flowchart TD
    Submit["Submit Exception Request\n(Finding, Rationale, Compensating Controls, Requested Days)"] --> MaxCheck{"Requested Days <= 90?"}
    MaxCheck -- No --> RejectDuration["Reject: Duration Exceeds 90-Day Ceiling"]
    MaxCheck -- Yes --> DualCheck{"Finding Severity == CRITICAL?"}

    DualCheck -- Yes --> DualReq["Flag RequiresDualApproval = TRUE"]
    DualCheck -- No --> SingleReq["Flag RequiresDualApproval = FALSE"]

    DualReq --> ReviewGate["Approver Submits Decision"]
    SingleReq --> ReviewGate

    ReviewGate --> SoDCheck{"Approver == Submitter?"}
    SoDCheck -- Yes --> RejectSoD["Reject: Separation of Duties Violation"]
    SoDCheck -- No --> RoleAuth{"Approver In Authorized Roles?"}
    RoleAuth -- No --> RejectRole["Reject: Unauthorized Approver Role"]
    RoleAuth -- Yes --> DecisionBranch{"Decision == APPROVED?"}

    DecisionBranch -- No --> StatusRejected["Status = REJECTED"]
    DecisionBranch -- Yes --> ApprovalCheck{"Requires Dual Approval?"}

    ApprovalCheck -- Yes (Approvals < 2) --> PendingNext["Remain Status = PENDING (Awaiting 2nd Approval)"]
    ApprovalCheck -- Yes (Approvals >= 2) --> ActivateApproved["Status = APPROVED\nCompute ExpiresAt & ReviewDate"]
    ApprovalCheck -- No (Single Approval) --> ActivateApproved

    ActivateApproved --> ExpiryWatch["Periodic / Event Expiry Evaluation"]
    ExpiryWatch --> Expired{"Now > ExpiresAt?"}
    Expired -- Yes --> TransitionExpired["Status = EXPIRED\nReopen Finding SLA Clock"]
    
    ActivateApproved --> ManualRevoke["Authorized Operator Revocation"]
    ManualRevoke --> StatusRevoked["Status = REVOKED\nReopen Finding SLA Clock"]
```

## 3. Key Architectural Guarantees
1. **Mandatory Separation of Duties (Anti-Self-Approval)**: The user submitting the risk exception cannot sign off on or approve their own request under any circumstances.
2. **Dual-Authorization for Critical Severity**: Findings with severity `CRITICAL` mandate sign-offs from two distinct authorized principals (e.g., Security Lead + CISO) before activating.
3. **90-Day Maximum Expiration Ceiling**: Exception durations cannot exceed 90 days. A formal review milestone is automatically set prior to expiration.
4. **Automated Expiry and Clock Resumption**: Expired or revoked exceptions transition automatically to `EXPIRED` or `REVOKED`, re-engaging active SLA remediation clocks and notifying finding workflows.
5. **Data and Evidence Preservation**: Accepting risk modifies governance state while leaving original finding fingerprints, scanner envelopes, and collected evidence untouched.
