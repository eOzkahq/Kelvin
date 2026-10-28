package tenant

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestTenantContextRoundTripAndValidation(t *testing.T) {
	id := uuid.New()
	ctx, err := WithID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ID(ctx)
	if err != nil || got != id {
		t.Fatalf("got=%s err=%v", got, err)
	}
	if _, err := ID(context.Background()); err != ErrMissingTenant {
		t.Fatalf("missing tenant error=%v", err)
	}
	if _, err := ParseAndWithID(context.Background(), "not-a-uuid"); err != ErrInvalidTenant {
		t.Fatalf("invalid tenant error=%v", err)
	}
	if _, err := WithID(context.Background(), uuid.Nil); err != ErrInvalidTenant {
		t.Fatalf("zero tenant error=%v", err)
	}
}
