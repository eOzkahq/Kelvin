// Package egress binds worker HTTP traffic to shared scope enforcement.
// Scanner adapters should use NewHTTPClient for target network requests.
package egress

import (
	"net/http"

	"github.com/kelvin/kelvin/packages/common/scope"
)

type Policy = scope.Policy
type Resolver = scope.Resolver
type PinnedTransport = scope.PinnedTransport

func NewPolicy(domains, cidrs []string, resolver Resolver) (Policy, error) {
	return scope.NewPolicy(domains, cidrs, resolver)
}
func NewHTTPClient(policy Policy) *http.Client    { return policy.NewHTTPClient() }
func NewTransport(policy Policy) *PinnedTransport { return (&policy).NewTransport() }
