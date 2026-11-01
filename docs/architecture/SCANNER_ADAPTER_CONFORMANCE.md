# Scanner Adapter Conformance Harness

The worker package `internal/adapters/adaptertest` provides reusable, offline
conformance checks for implementations of `adapters.ScannerAdapter`. The
harness checks lifecycle readiness, valid and invalid configuration, declared
capabilities, runtime version identity, execution result envelopes, result
retrieval, correlation identifiers, scope admission, and cancellation.

## Usage

An adapter package supplies its own valid and invalid configuration, a valid
baseline task, and scenarios that describe expected result statuses or errors.
The harness does not start real scanner binaries or access the network.

```go
adaptertest.Run(t, adaptertest.Suite{
    Adapter:       adapter,
    ValidConfig:   validConfig,
    InvalidConfig: invalidConfig,
    Task:          baselineTask,
    Scenarios: []adaptertest.Scenario{
        {Name: "completed", Task: baselineTask, ExpectedStatus: adapters.StatusCompleted},
    },
})
```

Use `FakeProcess` / `FakeProcessFunc` and `EnvelopeRunner` to exercise byte
output parsing deterministically. `Fixture` loads the checked-in fixtures:

| Fixture | Expected handling |
| --- | --- |
| `valid-output.json` | Valid completed envelope |
| `malformed-output.json` | Rejected with `adapters.ErrMalformedOutput` |
| `empty-output.json` | Rejected with `adapters.ErrMalformedOutput` |
| `partial-output.json` | Valid partial envelope |
| `scanner-failure.json` | Valid failed-execution envelope |

`PreparedFixture` updates assessment, scanner, version, and correlation metadata
for the supplied test task while preserving the rest of the fixture.

## Scope checks

`ScannerAdapter.Execute` receives a validated worker task but does not grant
authorization to its target. The assessment worker must enforce Phase 1 scope
before dispatch. A suite can pass that admission check as `ScopeGuard`, with an
in-scope task and an out-of-scope task; the harness verifies the rejected task
does not get dispatched as an execution scenario. Integrations should use the
real Phase 1 policy or invocation builder in their adapter-package tests.

## CI

The worker CI job runs `go test ./...`, which includes this package and its
fixtures. Tests use only fakes and embedded data, so they do not need unrestricted
internet access or installed scanner images. The reference adapter scenarios
exercise both a built-in preflight identity and an external ZAP-style identity;
they validate the contract plumbing and do not claim that production scanner
integrations are already implemented or certified.
