// Package scope exposes the shared target validation service to API handlers.
package scope

import (
	"context"
	"errors"
	"net/netip"

	apierrors "github.com/kelvin/kelvin/packages/common/errors"
	shared "github.com/kelvin/kelvin/packages/common/scope"
)

type Target = shared.Target
type Policy = shared.Policy
type Resolver = shared.Resolver
type PinnedTransport = shared.PinnedTransport

var ErrTarget = shared.ErrTarget
var ErrProhibited = shared.ErrProhibited
var ErrOutOfScope = shared.ErrOutOfScope

func Normalize(raw string) (Target, error) { return shared.Normalize(raw) }
func IsProhibited(ip netip.Addr) bool      { return shared.IsProhibited(ip) }
func NewPolicy(domains, cidrs []string, resolver Resolver) (Policy, error) {
	return shared.NewPolicy(domains, cidrs, resolver)
}
func Validate(ctx context.Context, policy Policy, raw string) (Target, []netip.Addr, error) {
	return policy.Validate(ctx, raw)
}
func LabModeFromEnv() bool { return shared.LabModeFromEnv() }

// Problem converts target validation failures into the API's safe RFC 7807 422.
func Problem(err error) *apierrors.API {
	if errors.Is(err, shared.ErrTarget) || errors.Is(err, shared.ErrProhibited) || errors.Is(err, shared.ErrOutOfScope) {
		return apierrors.NewTargetScopeViolation("target is malformed, prohibited, or outside the approved assessment scope")
	}
	return apierrors.NewTargetScopeViolation("target could not be validated against the approved assessment scope")
}
