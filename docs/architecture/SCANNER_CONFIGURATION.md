# Kelvin — Scanner Configuration Contract

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Phase 2 contract (`P2-05`) |
| **Configuration version** | `scanner-config.v1` (`schema_version: 1.0`) |
| **Go implementation** | `apps/worker/internal/adapters/scanner_config.go` |
| **JSON Schema** | `packages/schemas/scanner-config.v1.json` |
| **Related** | `MVP_SCANNER_SELECTION.md`, `SCAN_PROFILES.md`, `SCANNER_INVOCATION_INPUT.md`, `SCANNER_OUTPUT_ENVELOPE.md` |

## Model and precedence

Configuration is split into two layers:

1. The product scan profile owns target authorization, check categories, request budgets, concurrency, and hard deadlines.
2. Scanner configuration chooses safe implementation details within those bounds. It cannot enable active mode, expand scope, raise a profile budget, add a binary flag, choose an arbitrary template, or inject environment variables.

`scanner-config.v1.json` is a versioned `oneOf` schema covering each MVP scanner. `DecodeScannerConfig` decodes into a typed Go configuration, applies documented defaults, rejects unknown fields, and validates scanner-specific bounds. `ValidateWithinProfile` requires scanner request rate, concurrency, and duration to fit under the product profile. Invocation construction records the configuration version and validated effective values.

`PASSIVE` is Kelvin's check-policy category: it excludes intrusive or state-changing checks. It does not mean zero network traffic. ZAP Baseline crawls with ordinary requests, and Nuclei sends requests defined by the approved safe template set. Nuclei's rate is scanner-enforced; the ZAP Baseline CLI has no documented strict request pacing option, so the ZAP container remains network-disabled until scoped pacing egress is available.

Configuration is JSON at the worker boundary. A UI or API may accept YAML as an authoring format only if it converts to this JSON contract and applies the same strict validation before enqueue. Queue values remain untrusted until worker-side decoding succeeds.

## Shared settings

| Setting | Default | Allowed range | Notes |
| :--- | ---: | ---: | :--- |
| `execution_mode` | `PASSIVE` | `PASSIVE` only | `ACTIVE` is rejected for all shipped MVP scanners. |
| `request_timeout_seconds` | 10 | 1–30 | Per-request timeout. |
| `max_duration_seconds` | Scanner-specific | 1–3600 | Must be at least the request timeout and no greater than the active product profile deadline. |
| `requests_per_second` | Scanner-specific | 1–5 | Scanner-local pacing where supported. ZAP is fixed to 1 as its approved policy value, but networking is disabled until an egress gate can enforce that rate. |
| `max_concurrency` | Scanner-specific | 1–2 | Scanner-local cap; cannot exceed profile or worker limits. |

These defaults do not enlarge product profile budgets. If a profile is stricter, the stricter value wins or the configuration is rejected before execution.

## Per-scanner schemas and defaults

| Scanner ID | Defaults | Scanner-specific options / boundary |
| :--- | :--- | :--- |
| `http_preflight` | 10s request timeout, 30s max duration, 2 requests/s, concurrency 1 | No scanner-specific options. Uses bounded HTTP methods and revalidates every redirect. |
| `tls_assessor` | 10s, 60s, 2 requests/s, concurrency 1 | No scanner-specific options. No exhaustive cipher brute force. |
| `http_security_headers` | 10s, 60s, 2 requests/s, concurrency 1 | No scanner-specific options. Ordinary state-free requests only. |
| `zap` | 10s timeout, up to 600s, one worker | `zap.safety_profile` is fixed to `kelvin.zap.baseline.v1`; `zap.max_children` defaults to 10 per spider node (1–10) and `zap.max_depth` to 2 (1–2). Duration must be a whole minute in 60–600 seconds. Baseline mode only; no active scan, modern spider (`-j`), alpha rules, custom config, context, hooks, or user flags. Network remains disabled until scope aware pacing egress is available. |
| `nuclei` | 10s, 300s, 2 requests/s, concurrency 2 | `nuclei.template_set_id` is fixed to `kelvin.safe.web.v1`; severity allow-list defaults to `info`, `low`, `medium`. No custom templates, workflow, path, remote download, or arbitrary template ID. |

Built-in settings blocks are forbidden on external scanners and vice versa. JSON Schema and Go validation reject wrong scanner IDs, unknown fields, unsupported versions, cross-scanner settings, invalid ranges, duplicate severities, and values outside the approved template set.

## Version and assessment metadata

Each configuration has `schema_version: 1.0`; the invocation envelope records `scanner.config_version` alongside the selected scanner and the fully defaulted effective config. Persist that version and effective config (or a canonical digest plus schema version) in assessment metadata for reproducibility. Changes to fields, semantics, or defaults require a schema version change; pin the schema version with worker/scanner image releases.

## Failure behavior

Invalid, incomplete, unsupported, or unknown configuration is rejected before target traffic with a structured validation error. There is no fallback to scanner-native defaults. Scanner command flags are generated only from the validated typed config and a fixed adapter allow-list; config never contains argv, command, environment, target, URL, credential values, arbitrary Nuclei template paths, or ZAP policy files.

Credentials are not supported by the MVP scanner configurations. If a future authorized profile introduces credentials, configuration may carry only an opaque secret reference, never the secret itself; a separate security review must define reference format, retrieval, scope, and redaction before enabling it.
