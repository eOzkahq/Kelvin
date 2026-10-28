package database

import (
	"context"
	"testing"
)

func TestBeginTenantTxFailsClosedBeforePoolUse(t *testing.T) {
	if _, err := BeginTenantTx(context.Background(), nil); err == nil {
		t.Fatal("unscoped worker transaction accepted")
	}
}
