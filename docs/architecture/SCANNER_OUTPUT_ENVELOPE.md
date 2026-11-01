# Kelvin — Scanner Output Envelope

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Phase 2 contract (`P2-04`) |
| **Contract version** | `scanner-output.v1` (`schema_version: 1.0`) |
| **Go implementation** | `apps/worker/internal/adapters/output.go` |
| **JSON Schema** | `packages/schemas/scanner-output.v1.json` |
| **Related** | `SCANNER_ADAPTER_CONTRACT.md`, `SCANNER_INVOCATION_INPUT.md`, `FINDING_SCHEMA.md`, `EXECUTION_ISOLATION.md` |

## Contract

Every adapter returns `adapters.ScannerOutputEnvelope` (aliased as `adapters.Result` for the adapter lifecycle API). The output is versioned and carries assessment/scanner/run identity, engine and adapter versions, correlation ID, start/end timestamps, status, exit code, duration, normalized findings, diagnostics, scanner-specific metadata, partial-result state, and references to separately stored stdout/stderr artifacts.

`findings` contains only records that already conform to `finding.v1.json`. Raw scanner output is never placed in `findings`; bounded raw content belongs in `raw_payload`, and larger stdout/stderr data belongs in opaque `artifact://<uuid>` references. Both raw channels are untrusted and must be redacted before persistence and escaped before display. Artifact references cannot point to external URLs.

## Status semantics

| Status | Meaning | Required consistency |
| :--- | :--- | :--- |
| `COMPLETED` | Scanner exited successfully with no warnings and all planned work completed. | Exit code is `0`; `partial` is false; no warning/error diagnostics. |
| `COMPLETED_WITH_WARNINGS` | Scanner completed successfully but reports non-fatal skipped/degraded checks. | Exit code is `0`; `partial` is false; at least one warning diagnostic and no error diagnostic. |
| `PARTIAL` | Some usable normalized findings were produced, but planned work did not complete. | `partial` is true; at least one finding and warning diagnostic. Include a reason code such as `DEADLINE_NEAR`, `TARGET_UNAVAILABLE`, or `OUTPUT_TRUNCATED`. |
| `FAILED` | Execution or parsing failed; the result is not a successful complete scan. | `partial` is false; an error diagnostic is required. Include the process exit code when one exists. Malformed raw output is retained only as bounded untrusted diagnostics/artifact, never as a finding. |
| `TIMED_OUT` | Worker deadline stopped execution. | `DEADLINE_EXCEEDED` diagnostic required. If usable partial findings are retained, set `partial: true`; otherwise false. |
| `CANCELLED` | Explicit job cancellation stopped execution. | `CANCELLED` diagnostic required. If usable partial findings are retained, set `partial: true`; otherwise false. |

`exit_code` is optional for built-in checks that do not have a process exit code; external process results should include it. A non-zero process exit is never silently interpreted as `COMPLETED`. Diagnostics use `info`, `warning`, or `error`, a stable machine code, and a sanitized human-readable message. Do not put credentials, tokens, or unredacted target response content in diagnostic messages.

## Validation and failure handling

`EncodeOutputEnvelope` and `DecodeOutputEnvelope` validate the status rules, required metadata, timestamps, finding schema, bounded raw payload, and opaque artifact references. Decode rejects unknown fields and trailing JSON. An invalid envelope, malformed finding, or scanner crash fails the job; raw output remains separate and is not promoted to normalized findings. The worker must validate each finding again at ingestion and apply canonical redaction and server-assigned fields per `FINDING_SCHEMA.md`.

The envelope schema references `finding.v1.json` for each finding. The Go validator performs structural checks; the ingestion service remains responsible for full JSON Schema validation, secret redaction, canonicalization, and persistence. Scanner metadata is untrusted and may not override envelope metadata or server-owned finding fields.

## Example

```json
{
  "schema_version": "1.0",
  "metadata": {
    "assessment_id": "22222222-2222-2222-2222-222222222222",
    "scanner_id": "zap",
    "scanner_version": "2.16.1",
    "adapter_version": "1.0.0",
    "run_id": "11111111-1111-1111-1111-111111111111",
    "started_at": "2026-11-01T00:00:00Z",
    "completed_at": "2026-11-01T00:00:02Z",
    "correlation_id": "request-abc"
  },
  "status": "COMPLETED_WITH_WARNINGS",
  "exit_code": 0,
  "duration_ms": 2000,
  "findings": [],
  "diagnostics": [{ "level": "warning", "code": "RULE_SKIPPED", "message": "An optional passive rule was unavailable" }],
  "partial": false,
  "raw_artifacts": { "stdout_ref": "artifact://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/stdout" },
  "raw_payload": { "format": "text", "content": "bounded raw scanner output" }
}
```
