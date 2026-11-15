module github.com/projectdiscovery/nuclei/v3

go 1.26

// Hermetic module dependency overrides for Nuclei v3.11.1
// Remediates 15 reported Go module CVEs across third-party dependencies:
// - github.com/getkin/kin-openapi (CVE-2026-100349, CVE-2026-100351, CVE-2026-100352, CVE-2026-100353, CVE-2026-100354)
// - github.com/go-jose/go-jose/v4 (CVE-2026-116587)
// - golang.org/x/text (CVE-2026-56851)
// - golang.org/x/crypto (CVE-2026-56854)
// - golang.org/x/mod (CVE-2026-56864, CVE-2026-56865)
// - github.com/go-git/go-git/v5 (CVE-2026-71556)
// - golang.org/x/net (CVE-2026-78661, CVE-2026-78669)
// - google.golang.org/grpc (CVE-2026-84304, CVE-2026-84445)
require (
	github.com/getkin/kin-openapi v0.148.0
	github.com/go-git/go-git/v5 v5.14.0
	github.com/go-jose/go-jose/v4 v4.1.6
	golang.org/x/crypto v0.55.0
	golang.org/x/mod v0.40.0
	golang.org/x/net v0.62.0
	golang.org/x/text v0.41.0
	google.golang.org/grpc v1.83.1
)

replace (
	github.com/getkin/kin-openapi => github.com/getkin/kin-openapi v0.148.0
	github.com/go-git/go-git/v5 => github.com/go-git/go-git/v5 v5.14.0
	github.com/go-jose/go-jose/v4 => github.com/go-jose/go-jose/v4 v4.1.6
	golang.org/x/crypto => golang.org/x/crypto v0.55.0
	golang.org/x/mod => golang.org/x/mod v0.40.0
	golang.org/x/net => golang.org/x/net v0.62.0
	golang.org/x/text => golang.org/x/text v0.41.0
	google.golang.org/grpc => google.golang.org/grpc v1.83.1
)
