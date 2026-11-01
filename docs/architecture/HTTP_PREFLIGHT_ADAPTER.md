# HTTP/HTTPS Preflight Adapter

`adapters.NewHTTPPreflightAdapter` constructs the built-in `http_preflight`
scanner. It issues one `HEAD` request to the canonical, scope-validated target;
it does not crawl, enumerate links, or issue a fallback `GET` request. It
captures HTTP status, protocol, response latency, redirect information, and TLS
version/cipher when a TLS response is available.

## Scope and construction

The constructor requires a `ScopePolicyProvider`. The provider must return the
trusted Phase 1 scope policy for the given task and tenant context. The adapter
fails initialization without this dependency, validates the requested target
before sending traffic, uses the scope package's pinned HTTP transport, and
revalidates each redirect before following it. Do not build the provider from
scanner config or user-controlled payload fields.

```go
adapter := adapters.NewHTTPPreflightAdapter(func(ctx context.Context, task adapters.Task) (scope.Policy, error) {
    // Resolve the task's authorized scope from trusted worker context here.
    return scopePolicyForAuthorizedTask(ctx, task)
})
```

The worker must pass a deadline-bearing context. The adapter further limits
total work to the lesser of the configured maximum duration and task deadline,
and limits the HTTP request to the lesser of its request timeout and remaining
total duration. Cancellation is inherited through the context. It caps its own
request rate at the lesser configured value and the adapter capability limit.

## Output and failure outcomes

Results use the common versioned scanner output envelope. The namespaced
`http_preflight.observation` metadata contains one of `HTTP_RESPONDED` or
`UNREACHABLE`, the canonical target, HTTP status/protocol, latency, redirect
flag/final URL, optional TLS details, and a bounded error category. Network,
TLS, and scope-rejected redirect outcomes are completed with warnings;
deadline and cancellation outcomes use the corresponding envelope status and
diagnostic code. Scope/configuration failures before a request are returned as
adapter errors. No raw response body or cookies are collected.

## Tests

`apps/worker/internal/adapters/http_preflight_test.go` uses local HTTP/TLS test
servers with the repository's signed testing-only lab mode. It covers HEAD
response capture, out-of-scope redirect rejection, TLS verification failure,
task-deadline enforcement, invalid schemes, and missing scope-provider
configuration. The tests do not access external targets.
