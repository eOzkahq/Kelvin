// Package schemas embeds the canonical Kelvin JSON contracts so that Go
// services (apps/api, apps/worker) consume the exact same bytes as the
// TypeScript tooling — one source of truth, zero duplication (P1-11, P1-13).
package schemas

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed *.json fixtures
var files embed.FS

// FS exposes the embedded schema tree for io/fs consumers (walkers, validators).
func FS() fs.FS {
	return files
}

// Read returns the raw bytes of an embedded schema or fixture by its
// package-relative path, e.g. "finding.v1.json" or "fixtures/positive/nuclei.cve-2021-44228.json".
func Read(name string) ([]byte, error) {
	b, err := files.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("schemas: %q not embedded: %w", name, err)
	}
	return b, nil
}

// MustRead is Read for compile-time known asset names; it panics only if the
// embedded asset was removed from the package (a build-breaking repository error).
func MustRead(name string) []byte {
	b, err := Read(name)
	if err != nil {
		panic(err)
	}
	return b
}
