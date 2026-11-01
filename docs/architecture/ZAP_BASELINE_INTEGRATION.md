# OWASP ZAP Baseline Integration

The worker invokes only `/zap/zap-baseline.py` with a validated HTTP(S) target, a bounded duration, the `-I` baseline behavior, and fixed spider depth, child count, and thread limits. User configuration cannot add command-line flags. The invocation writes JSON to `/tmp/kelvin-zap-report.json`; the OCI executor copies that one fixed file out before removing the container and rejects empty reports or reports larger than 4 MiB.

The worker treats the report as untrusted JSON. It checks the report version against the verified runtime version, maps ZAP risk levels to Kelvin severity, validates every normalized finding, and creates the versioned `ScannerOutputEnvelope`. Target identity is taken from the worker task, never from report fields. Scanner-reported instance URLs and raw evidence are omitted from findings to avoid accepting out-of-scope locations or leaking query secrets.

ZAP runs the Baseline passive scan and its bounded spider; it does not use the active scan or arbitrary hooks/configuration. ZAP documents `-J` as the JSON report file option and describes Baseline as spidering followed by passive scanning. See the [ZAP Baseline documentation](https://www.zaproxy.org/docs/docker/baseline-scan/).

## Release gate

`deploy/scanners/images.lock.json` currently has `status: not-released` and no approved ZAP version or immutable image digest. The registry's version policy rejects a sandboxed scanner without that identity. A reviewed image build must populate the lock, and production wiring must provide a verifier that measures the actual runtime image and executable version before ZAP can be registered.

The worker queue currently records completion state but has no result-output storage contract. The daemon validates the ZAP output envelope before completion; durable delivery of that envelope belongs to the worker ingestion/output integration. In addition, the current worker only structurally validates the task target and does not load the Phase 1 authorization context. Network egress is disabled by the current sandbox profile. Live target access must remain disabled until both Phase 1 scope authorization and the scoped egress policy are wired into dispatch.
