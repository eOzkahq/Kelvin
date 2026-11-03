# Security and Privacy Baseline Audit Report

## 1. Executive Security Evaluation

As part of the cross-phase quality gate, the KELVIN web application and underlying API surfaces were audited against OWASP Top 10, ASVS Level 2, and ADR-0002 multi-tenancy requirements.

| Security Domain | Standard / Benchmark | Verification Technique | Findings / Status |
|---|---|---|:---:|
| **Tenant Isolation & RLS** | ADR-0002 Multi-Tenancy | Direct API cross-tenant UUID tampering tests | **PASS (0 Leaks)** |
| **Authentication & Tokens** | JWT HMAC-SHA256 / OAuth 2.0 | Session hijacking, expiration, and replay sweeps | **PASS** |
| **Server-Side Authorization** | RBAC 52-Permission Catalog | Least-privilege matrix and role escalation checks | **PASS** |
| **Secret & Token Exposure** | ADR-0005 Redaction Spec | Client bundle static scan + regex token sweeping | **PASS** |
| **Input Validation & XSS** | Contextual Output Encoding | React auto-escaping & malicious payload injection | **PASS** |
| **Transport & HTTP Headers** | Production TLS & HSTS | Security headers inspection | **PASS** |
| **Rate Limiting & DoS Defense** | RFC 6585 Throttling | Concurrency stress & token bucket fuzzing | **PASS** |
| **Tamper-Evident Audit** | SHA-256 Hash Chaining | Chain mutation & deletion detection verification | **PASS** |

---

## 2. Itemized Verification Results

### A. Multi-Tenant Boundary & Anti-IDOR Enforcement
- Verified that PostgreSQL Row Level Security (`tenant_isolation_*` policies) and API middleware enforce tenant boundaries strictly.
- When an authenticated session from Tenant A executes:
  `GET /api/v1/findings/3fa85f64-5717-4562-b3fc-2c963f66afa6` (a resource belonging to Tenant B), the server strictly returns `HTTP 404 Not Found` (preventing IDOR existence oracle) or `HTTP 403 Forbidden`.
- Client-supplied `X-Tenant-ID` headers are ignored; tenant identity is derived solely from the cryptographically validated session context (`tenant.ID(ctx)`).

### B. Client-Side Secret Leakage Prevention
- Scanned frontend production build chunks (`dist/assets/*.js`) for:
  - AWS access keys (`AKIA[0-9A-Z]{16}`)
  - Kelvin live API keys (`klv_live_[a-f0-9]{32,64}`)
  - Webhook secrets (`whsec_[a-f0-9]{32,64}`)
  - Private key blocks (`-----BEGIN RSA PRIVATE KEY-----`)
  - Database connection strings (`postgres://...`)
- **Result:** Zero secrets found in compiled assets. Environment configuration is limited strictly to public `VITE_*` parameters.

### C. Automated Secret Redaction (ADR-0005)
- Automated redaction pipeline (rules R1–R10 from `docs/security/DATA_LIFECYCLE.md`) actively sanitizes:
  - Bearer and Basic authentication headers
  - Passwords and secret form inputs
  - AWS access keys and JWT tokens
  - PEM private key blocks
- Verified across:
  - Findings evidence viewer
  - Assessment comparison diffs
  - Outbound Slack / MS Teams notification envelopes
  - Audit search outputs and data governance export bundles

### D. Security Response Headers Baseline
The API gateway and web server emit the following mandatory headers on all responses:

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' /api/v1; frame-ancestors 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
```

### E. Rate Limiting & Egress Anti-SSRF
- Sliding-window rate limiting is enforced (Standard: 100 req/min; Expensive: 10 req/min).
- Egress proxy validates all external webhook and integration endpoints against private RFC 1918, loopback (`127.0.0.1`), link-local (`169.254.169.254`), and CGNAT address blocks to block Server-Side Request Forgery (SSRF).
