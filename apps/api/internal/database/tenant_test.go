package database

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

func TestSetTenantContextUsesValidatedParameter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(regexp.QuoteMeta("SET LOCAL ROLE kelvin_app")).WillReturnResult(sqlmock.NewResult(0, 0))
	id := uuid.New()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('app.tenant_id', $1, true)")).WithArgs(id.String()).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := SetTenantContext(context.Background(), tx, id.String()); err != nil {
		t.Fatal(err)
	}
	mock.ExpectCommit()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSetTenantContextRejectsMalformedIDBeforeSQL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetTenantContext(context.Background(), tx, "x'; RESET ROLE; --"); err == nil {
		t.Fatal("malformed tenant was accepted")
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTenantPredicateRequiresContextAndStaticQualifier(t *testing.T) {
	ctx, idErr := tenant.ParseAndWithID(context.Background(), uuid.NewString())
	if idErr != nil {
		t.Fatal(idErr)
	}
	predicate, arg, err := TenantPredicate(ctx, "f")
	if err != nil || predicate != "f.tenant_id = $1" || arg != mustTenantID(t, ctx) {
		t.Fatalf("predicate=%q arg=%v err=%v", predicate, arg, err)
	}
	if _, _, err := TenantPredicate(context.Background(), "f"); err == nil {
		t.Fatal("missing tenant context accepted")
	}
	if _, _, err := TenantPredicate(ctx, "f; DELETE FROM findings"); err == nil {
		t.Fatal("dynamic SQL qualifier accepted")
	}
}

func TestBeginTenantTxFailsClosedWithoutTenantBeforePoolUse(t *testing.T) {
	_, err := BeginTenantTx(context.Background(), nil)
	if err == nil {
		t.Fatal("expected missing tenant error before accessing pool")
	}
}

func mustTenantID(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()
	id, err := tenant.ID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
