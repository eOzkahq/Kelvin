# TLS Configuration Assessment Adapter

`adapters.NewTLSAssessmentAdapter` creates the built-in `tls_assessor`. It
requires a trusted Phase 1 `ScopePolicyProvider`; each task is scope-validated
before its host and authorized port are dialed through `scope.PinnedTransport`.
The adapter sends no HTTP request or application data.

## Bounded protocol evaluation

The adapter makes at most four sequential TLS handshakes, one each constrained
to TLS 1.0, 1.1, 1.2, and 1.3. This reveals which protocol versions the server
accepts without crawling or running exploit checks. The task deadline,
configured request timeout, and request rate bound the probes. It reports the
negotiated cipher for every successful version. Its cipher rule flags CBC,
3DES, RC4, and NULL suites when negotiated; Go's TLS implementation does not
implement RC4, so the adapter cannot negotiate or independently verify an
RC4-only endpoint.

The adapter selects the highest successful protocol's peer chain for
certificate evaluation. It checks validity dates, SAN/hostname match, and
chain trust against the injected trust roots or the host system root store. It
uses a handshake-only TLS config that skips Go's automatic verification so an
expired or mismatched certificate can still be inspected; it then performs
explicit hostname and `x509.Verify` checks before generating findings. The
scope-bound TCP dial remains independently enforced. No certificate data is
accepted from task configuration.

## Rule set and results

Rules are versioned as `kelvin.tls.rules.v1` in scanner metadata. Current
findings identify deprecated TLS 1.0/1.1 support, negotiated weak ciphers,
expired or not-yet-valid certificates, hostname mismatch, and untrusted
chains. Certificate/protocol findings use canonical `finding.v1` objects in
the common versioned output envelope. Connection failures, protocol
negotiation failures, timeouts, cancellation, and unavailable trust roots are
reported as diagnostics rather than security findings.

The adapter does not enumerate every cipher preference or test TLS extensions,
renegotiation, compression, or downgrade behavior. It reports the versions
and ciphers accepted by its bounded four-handshake matrix. Tests use local TLS
servers for valid and expired certificates, hostname and trust errors,
TLS 1.0/CBC negotiation, connection refusal, and invalid scope/configuration.
