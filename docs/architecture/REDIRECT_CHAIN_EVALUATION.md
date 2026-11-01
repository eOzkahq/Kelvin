# Safe Redirect Chain Evaluation

Redirect handling is enforced by `packages/common/scope.Policy.NewHTTPClient`
through `http.Client.CheckRedirect`. Scanner adapters must use this client (or
the corresponding pinned transport) and must not trust scanner-reported final
URLs as authorization evidence.

For every proposed hop, the client:

1. Rejects schemes other than HTTP and HTTPS, including HTTPS-to-HTTP
   downgrades.
2. Allows only the initial target's effective port or the destination scheme's
   standard web port (HTTP 80, HTTPS 443). This lets a target retain its
   explicitly authorized service port without allowing a redirect to pivot to
   an unrelated port.
3. Normalizes and checks the destination against the task's approved scope.
   The pinned transport independently rechecks DNS answers and address policy
   at socket connection time.
4. Rejects a previously visited canonical URL as a loop and stops after ten
   followed redirect hops.

The scope package exposes stable errors for loop, hop-limit, port, scheme,
out-of-scope, and prohibited-address rejections. The HTTP preflight adapter
maps those to structured warning diagnostics such as `REDIRECT_LOOP`,
`REDIRECT_LIMIT_EXCEEDED`, `REDIRECT_PORT_REJECTED`,
`REDIRECT_SCHEME_REJECTED`, and `REDIRECT_SCOPE_REJECTED`. The redirect
response itself is retained as an observation; the blocked destination is
never requested.

Tests in `packages/common/scope/scope_test.go` exercise loops, the hop limit,
out-of-scope hosts, unsupported schemes, and unapproved ports using local
servers. The HTTP preflight tests verify blocked redirect diagnostics and that
the returned response records the redirect status without following it.
