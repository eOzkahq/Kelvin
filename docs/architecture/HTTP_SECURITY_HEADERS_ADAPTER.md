# HTTP Security Header and Cookie Adapter

`adapters.NewHTTPSecurityHeadersAdapter` creates the built-in
`http_security_headers` adapter. It requires the trusted Phase 1 scope-policy
provider, validates the task target, and uses the scope-aware HTTP client. It
sends one `HEAD` request, follows only redirects approved by the shared redirect
policy, caps response headers at 64 KiB, and never reads the response body.
Cookie findings are emitted only for `Set-Cookie` values actually returned;
the adapter does not infer cookies from an absent header.

## Rules (`kelvin.http_headers.rules.v1`)

| Rule | Detection and applicability | Default severity / confidence |
| --- | --- | --- |
| `hsts_missing` | HTTPS final response must contain exactly one valid `Strict-Transport-Security` value with one positive `max-age`. HTTP responses are not assessed for HSTS. | MEDIUM / 0.90 |
| `csp_missing` | HTML response (`text/html` or `application/xhtml+xml`) has no CSP. | MEDIUM / 0.75 |
| `csp_unsafe_script` | HTML CSP has `unsafe-eval`, or `unsafe-inline` in a script directive without a nonce/hash source. Raw CSP values and nonce values are not copied into evidence. | MEDIUM / 0.80 |
| `content_type_options` | A response with a declared Content-Type does not set `X-Content-Type-Options: nosniff`. | LOW / 0.85 |
| `frame_protection` | HTML response has neither X-Frame-Options `DENY`/`SAMEORIGIN` nor a restrictive CSP `frame-ancestors`. | MEDIUM / 0.75 |
| `referrer_policy` | HTML response does not declare one of `no-referrer`, `same-origin`, `strict-origin`, or `strict-origin-when-cross-origin`. | LOW / 0.80 |
| `permissions_policy` | HTML response explicitly grants `camera`, `microphone`, or `geolocation` to `*`. An absent header alone is not reported. | MEDIUM / 0.85 |
| `cookie_secure` | Cookie returned over HTTPS lacks Secure. Cookies from HTTP responses are not evaluated for Secure. | MEDIUM / 0.90 |
| `cookie_httponly` | Returned cookie lacks HttpOnly. Client-readable cookies may be intentional, so this is LOW confidence. | LOW / 0.65 |
| `cookie_samesite` | Returned cookie omits SameSite or sets `SameSite=None` without Secure. | LOW / 0.70 |

Document policies are evaluated only for HTML responses. Cookie attributes are
evaluated per cookie but aggregated by rule; evidence lists at most ten
attribute-only summaries. Cookie names and values are never copied into
findings. The Set-Cookie value is explicitly marked redacted in evidence.
Finding endpoints omit query strings and fragments. Each finding is a
canonical `finding.v1` object in the common scanner output envelope.

The adapter does not crawl, read response bodies, or infer session purpose from
cookie names. It cannot confirm how a client uses a cookie, so the HttpOnly and
SameSite checks carry lower confidence. HEAD responses can differ from GET
responses; a missing `Set-Cookie` on HEAD is treated as no cookie evidence,
not as a pass or failure.

Tests in `apps/worker/internal/adapters/http_headers_test.go` cover a local
scope-bound request, compliant and weak header/cookie fixtures, query/value
redaction, and context-sensitive suppression. They do not access external
targets.
