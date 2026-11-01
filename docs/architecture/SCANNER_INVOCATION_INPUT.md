# Kelvin — Scanner Invocation Input Contract

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Phase 2 contract (`P2-03`) |
| **Contract version** | `scanner-invocation.v1` (`schema_version: 1.0`) |
| **Go implementation** | `apps/worker/internal/adapters/execution_input.go` |
| **JSON Schema** | `packages/schemas/scanner-invocation.v1.json` |
| **Related** | `SCANNER_ADAPTER_CONTRACT.md`, `MVP_SCANNER_SELECTION.md`, `SCAN_PROFILES.md`, `TARGET_SCOPE_ENFORCEMENT.md`, `EXECUTION_ISOLATION.md` |

## Purpose and trust boundary

The invocation input is a least-privilege description of one scanner execution. It is built inside the trusted worker from a validated task, an authorization context, a Phase 1 `scope.Policy`, and a validated resource policy. It must never be decoded directly from the queue or accepted as a user-provided replacement for authorization context. `BuildExecutionInput` revalidates the canonical target and captures the checked DNS addresses; failure to resolve or validate rejects the invocation before scanner traffic.

The payload contains identifiers and execution policy, not secrets. `authorization_id` is optional when the assessment does not need a separate authorization record. Future credentials must be represented by opaque references resolved through a separate worker-controlled secret mechanism; secret values must never be serialized into this payload, environment, logs, or scanner arguments. Environment variables and arbitrary CLI arguments are not contract fields.

## Version 1 fields

| Field | Required | Meaning |
| :--- | :--- | :--- |
| `schema_version` | Yes | Exact contract version, currently `1.0`. Unknown versions are rejected. |
| `assessment.id`, `assessment.tenant_id` | Yes | UUIDs identifying assessment and tenant. |
| `assessment.authorization_id` | No | UUID reference to the authorization record when separately applicable; never an authorization token. |
| `target.canonical` | Yes | Canonical HTTP(S) target produced by the shared scope package. |
| `target.pinned_ips` | Yes | Non-empty, validated DNS/IP results used by the egress layer to prevent rebinding. Prohibited addresses are rejected. |
| `scope.id`, `scope.target` | Yes | Approved scope reference and exact target authorized for this job. `scope.target` must exactly equal `target.canonical`. The broader project allow-list is not disclosed. |
| `profile.id` | Yes | Selected, server-approved scan profile reference. It is not an override channel. |
| `scanner.name` | Yes | Registered adapter name. |
| `scanner.config` | No | Adapter-specific JSON object validated by that adapter. Target, URL, command/argv, environment, template path, and similar execution overrides are prohibited. |
| `execution.resource_policy_id` | Yes | Reference to the approved worker resource policy. |
| `execution.deadline`, `timeout_seconds` | Yes | Absolute UTC deadline and bounded duration. The task timeout may not exceed the resource policy ceiling. |
| `execution.requests_per_second`, `max_requests_per_target`, `max_concurrent_connections` | Yes | Request pacing and target traffic/concurrency budgets. Enforced by worker/egress controls; scanner flags are not authoritative. |
| `execution.cpu_quota`, `memory_limit`, `disk_limit`, `max_pids` | Yes | Worker-enforced container resource bounds. |
| `trace.job_id` | Yes | Job UUID for audit correlation. |
| `trace.correlation_id` | No | Opaque request trace identifier. |

The Go type and JSON Schema are versioned together. Additive or incompatible changes require a new contract version and schema; producers and adapters must reject unsupported versions and unknown schema fields.

## Construction and validation

`BuildExecutionInput` requires a valid `Task`, UUID scope and optional authorization references, a resource policy, a bounded requests-per-second value, a policy ID, and the Phase 1 `scope.Policy`. It calls `Policy.Validate`, records canonical target and pinned IPs, verifies that task timeout is no greater than the resource policy deadline, and rejects malformed or prohibited input. This function is the only supported constructor for an authorized invocation.

`ExecutionInput.Validate` checks version, identifiers, canonical HTTP(S) target shape, exact target/scope equality, pinned address syntax and prohibition rules, required profile/scanner/resource fields, and complete resource bounds. Validation does not independently grant authorization; that comes from construction with trusted scope and authorization context. Scanner config is separately validated by the registered adapter before dispatch.

The input contains no free-form environment map or argument vector. Adapters convert validated configuration to a fixed, allow-listed invocation. Scope enforcement, DNS pinning, redirects, and egress denial remain active at runtime; payload validation alone is not a substitute for them.

## Example

```json
{
  "schema_version": "1.0",
  "assessment": {
    "id": "22222222-2222-2222-2222-222222222222",
    "tenant_id": "33333333-3333-3333-3333-333333333333",
    "authorization_id": "55555555-5555-5555-5555-555555555555"
  },
  "target": {
    "canonical": "https://example.com/",
    "pinned_ips": ["93.184.216.34"]
  },
  "scope": {
    "id": "44444444-4444-4444-4444-444444444444",
    "target": "https://example.com/"
  },
  "profile": { "id": "kelvin.profile.standard.v1" },
  "scanner": { "name": "zap", "config": { "mode": "baseline" } },
  "execution": {
    "resource_policy_id": "kelvin.resource.standard.v1",
    "deadline": "2026-11-01T00:10:00Z",
    "timeout_seconds": 600,
    "requests_per_second": 25,
    "max_requests_per_target": 5000,
    "max_concurrent_connections": 10,
    "cpu_quota": "1",
    "memory_limit": "512m",
    "disk_limit": "2g",
    "max_pids": 64
  },
  "trace": {
    "job_id": "11111111-1111-1111-1111-111111111111",
    "correlation_id": "request-abc"
  }
}
```

This example shows the contract shape; the values are not defaults. Actual profile and worker limits are supplied by trusted policy and must agree before dispatch.
