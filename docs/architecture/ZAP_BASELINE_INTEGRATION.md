# OWASP ZAP Baseline Safety Profile

KELVIN's approved configuration is `kelvin.zap.baseline.v1`. It is fixed to the ZAP Baseline script and rejects other safety profile identifiers, active execution mode, unknown options, and scanner settings above these bounds:

| Setting | Profile limit |
| --- | --- |
| Spider depth | 1–2 |
| Children per spider node | 1–10 (default 10) |
| Spider threads | 1 |
| ZAP connect/read timeout | 1–30 seconds (default 10) |
| Configured duration | Whole minutes, 1–10 (default 10) |
| Worker deadline | Minimum of job/profile deadline and scanner duration |
| Container network | Disabled until scope aware egress is available |

The adapter constructs argv itself, including ZAP's `network.connection.timeoutInSecs` setting. It does not pass `-j` (which adds the modern spider), `-a` (alpha passive rules), user rule config (`-c`/`-u`), context (`-n`), authentication (`-U`), hooks, Automation Framework overrides, or arbitrary user options. ZAP Baseline's documented behavior is a bounded spider followed by passive scanning without active attacks; the spider still sends HTTP requests. See the [ZAP Baseline documentation](https://www.zaproxy.org/docs/docker/baseline-scan/) and [ZAP config key guidance](https://www.zaproxy.org/faq/how-do-you-find-out-what-key-to-use-to-set-a-config-value-on-the-command-line/).

The child limit is per spider node, not a total request ceiling. With depth 2 and at most 10 children per node, the crawl fanout is bounded, but each page may still cause related HTTP traffic (for example redirects and linked resources). Passive rules inspect the resulting traffic and do not intentionally send exploit payloads. A spidered GET endpoint can still have application side effects, so operators should use authorized test targets and schedule scans appropriately.

The daemon applies the scanner duration as an execution-context deadline, in addition to the queue/job deadline. The ZAP invocation sets a single spider thread, maximum depth, maximum children, and matching Baseline spider/passive wait minutes. The approved `requests_per_second` value is fixed at 1 in configuration, but the Baseline CLI does not provide a documented strict pacing option. Therefore live network execution remains unavailable: sandbox validation requires ZAP networking to stay disabled until the scope aware egress gate can enforce target scope and pacing. This also prevents discovered URLs and redirects from being contacted while that gate is absent; a ZAP `OUTOFSCOPE` reporting rule alone would not be a network access control.

The normalizer records the safety profile version in the output envelope and treats all report data as untrusted. It checks the report version against the verified runtime, uses the worker task target rather than scanner reported URLs, strips instance URLs/raw evidence, and validates each canonical finding.

## Release gates

`deploy/scanners/images.lock.json` is still `not-released` and has no approved ZAP version or immutable digest. Registry policy rejects an external scanner until a reviewed image build records that identity. The worker also needs Phase 1 authorization context, a scoped and paced egress path, and a durable output-envelope contract before ZAP can execute real assessments.
