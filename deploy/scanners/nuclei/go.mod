module github.com/projectdiscovery/nuclei/v3

go 1.26

// Remediates CVE-2026-71556 (go-git arbitrary command execution / RCE)
require (
	github.com/go-git/go-git/v5 v5.14.0
)

replace github.com/go-git/go-git/v5 => github.com/go-git/go-git/v5 v5.14.0
