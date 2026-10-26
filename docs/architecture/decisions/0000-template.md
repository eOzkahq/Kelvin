# ADR-XXXX: [Decision Title]

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Proposed / Accepted / Superseded / Deprecated |
| **Date** | YYYY-MM-DD |
| **Author** | Name / Team |
| **Planning Reference** | P1-07 |
| **Supersedes** | ADR-XXXX (if applicable) |
| **Superseded by** | ADR-XXXX (if applicable) |
| **Reviewers** | Names / Teams |
| **Classification** | Internal — Engineering Record |

---

## 1. Context and Problem Statement

Describe the issue driving this decision. What is the problem we are trying to solve? Why does it need to be solved now? Include relevant background, constraints, and any business or regulatory drivers.

---

## 2. Decision Drivers

List the forces that shape this decision (e.g., security isolation, operational simplicity, team expertise, licensing, performance, cost, maintainability, compliance). Rank them by priority where helpful.

---

## 3. Considered Alternatives

| Alternative | Pros | Cons | Verdict |
| :--- | :--- | :--- | :--- |
| **Option A** | ... | ... | Rejected / Selected |
| **Option B** | ... | ... | Rejected / Selected |
| **Option C** | ... | ... | Rejected / Selected |

---

## 4. Decision

State the chosen option clearly and unambiguously. Include specific versions, configuration parameters, and any constraints on usage (e.g., "PostgreSQL 15+ with row-level security enabled; no direct client access").

---

## 5. Consequences

### Positive Consequences
- Benefit 1
- Benefit 2

### Negative Consequences
- Trade-off 1 (and mitigation)
- Trade-off 2 (and mitigation)

### Risks
- Risk 1 (likelihood, impact, mitigation)

---

## 6. Related Decisions

- ADR-XXXX: [related decision]
- `docs/PRODUCT_VISION.md`, `docs/security/THREAT_MODEL.md`, `docs/architecture/SYSTEM_ARCHITECTURE.md`

---

## 7. Notes

Any additional context, links to RFCs, benchmarks, or spike results.

---

*This record follows the MADR (Markdown Architectural Decision Records) format, a lightweight adaptation of Michael Nygard's ADR template. Once Accepted, this file is immutable: changes require a new ADR that supersedes this one.*
