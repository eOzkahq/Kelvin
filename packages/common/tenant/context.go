// Package tenant carries a validated tenant identifier across request and
// background-job boundaries. Tenant identity is never read from request headers.
package tenant

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

var ErrMissingTenant = errors.New("tenant context is required")
var ErrInvalidTenant = errors.New("invalid tenant identifier")

type contextKey struct{}

func WithID(ctx context.Context, id uuid.UUID) (context.Context, error) {
	if id == uuid.Nil {
		return nil, ErrInvalidTenant
	}
	return context.WithValue(ctx, contextKey{}, id), nil
}

func ParseAndWithID(ctx context.Context, raw string) (context.Context, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return nil, ErrInvalidTenant
	}
	return WithID(ctx, id)
}

func ID(ctx context.Context) (uuid.UUID, error) {
	id, ok := ctx.Value(contextKey{}).(uuid.UUID)
	if !ok || id == uuid.Nil {
		return uuid.Nil, ErrMissingTenant
	}
	return id, nil
}
