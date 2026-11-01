# Curated Nuclei Template Catalog Specification

KELVIN enforces a versioned, strictly curated template catalog for Nuclei executions (`kelvin.safe.web.v1`). In alignment with ADR-0005 and MVP safety invariants, unreviewed upstream templates, remote downloads (`-duc` enforced), intrusive payloads, denial-of-service tests, and state-changing checks are strictly excluded.

## 1. Catalog Architecture & Storage

The curated catalog is structured under `deploy/scanners/templates/kelvin.safe.web.v1`:

```
deploy/scanners/templates/kelvin.safe.web.v1/
├── catalog.json               # Catalog manifest with review policy and template hashes
└── templates/
    ├── env-file.yaml          # Sensitive environment file exposure check (GET)
    ├── git-config.yaml        # Git repository configuration exposure check (GET)
    ├── robots-txt.yaml        # robots.txt discovery check (GET)
    └── security-txt.yaml      # security.txt presence verification (GET)
```

At container build time, this immutable tree is copied to `/opt/kelvin/templates/kelvin.safe.web.v1` in the minimal distroless scanner image.

## 2. Review Policy & Safety Requirements

Every template admitted to `kelvin.safe.web.v1` must satisfy the following safety criteria:

- **Review Status**: Explicitly marked `review_status: "approved"` by the Product Security team.
- **Allowed HTTP Methods**: Read-only safe methods only (`GET`, `HEAD`, `OPTIONS`). `POST`, `PUT`, `DELETE`, and `PATCH` are strictly rejected.
- **No Intrusive or Destructive Payloads**: No command injection exploits, SQL injection exfiltration, template injection attacks, memory corruptions, or data modification.
- **No Denial-of-Service**: No stress tests, resource exhaustion loops, or payload flooding.
- **No Out-of-Band Callbacks**: No Interactsh or remote DNS/OAST callback dependencies that could communicate with unapproved external networks.
- **Cryptographic Traceability**: The manifest records the SHA-256 checksum of each individual template file, and the entire catalog manifest is fingerprinted by its SHA-256 digest (`template_catalog_digest`).

## 3. Go Validation & Runtime Guardrails

The worker package `adapters` provides:
- `CuratedCatalogManifest`: Strongly typed manifest parser.
- `LoadCuratedCatalog`: Computes manifest SHA-256 digest, checks review policy, and validates every template file against its declared checksum.
- `IsTemplateAllowed`: O(1) membership check ensuring only approved template IDs are selected.

## 4. Update, Rollback & Lifecycle Governance

1. **Adding/Modifying Templates**:
   - Create or update the template YAML under `templates/`.
   - Update `catalog.json` with updated file checksums, version bump, and reviewer metadata.
   - Run `go test ./...` in `apps/worker` to ensure all catalog integrity tests pass.
2. **Rollback**:
   - Because catalog versions and digests are immutable and recorded in `images.lock.json` and output envelopes, rollback is achieved by reverting the version policy to the previous known-good catalog version and SHA-256 digest.
