// Package validation holds wire-format helpers shared by the API and worker
// (API_STANDARDS.md §5.2: lowercase UUID identifiers, RFC 3339 UTC timestamps,
// SCREAMING_SNAKE_CASE enums).
package validation

import (
	"regexp"
	"time"
)

var (
	uuidV4   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	uuidAny  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	enumWire = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	correlat = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// IsUUIDV4 reports whether s is a lowercase UUID v4 string (§5.2 identifiers).
func IsUUIDV4(s string) bool { return uuidV4.MatchString(s) }

// IsUUID reports whether s is any lowercase UUID.
func IsUUID(s string) bool { return uuidAny.MatchString(s) }

// IsWireEnum reports whether s is SCREAMING_SNAKE_CASE (§5.2 enums).
func IsWireEnum(s string) bool { return enumWire.MatchString(s) }

// IsCorrelationID reports whether s satisfies the inbound X-Correlation-ID
// contract (§10.1: ^[A-Za-z0-9._-]{1,128}$).
func IsCorrelationID(s string) bool { return correlat.MatchString(s) }

// IsRFC3339UTC reports whether s parses as RFC 3339 with a Z suffix (§5.2).
func IsRFC3339UTC(s string) bool {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return false
	}
	return t.Location() == time.UTC
}

// OneOf reports whether s is a member of allowed.
func OneOf(s string, allowed ...string) bool {
	for _, a := range allowed {
		if s == a {
			return true
		}
	}
	return false
}
