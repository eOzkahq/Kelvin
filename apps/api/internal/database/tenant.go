package database

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

var relationQualifier = regexp.MustCompile(`^(?:[a-z_][a-z0-9_]*\.)?[a-z_][a-z0-9_]*$`)

// BeginTenantTx starts a transaction and sets the transaction-local tenant GUC
// from authenticated or worker context. RLS policies fail closed without it.
func BeginTenantTx(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	tenantID, err := tenant.ID(ctx)
	if err != nil {
		return nil, fmt.Errorf("database: refusing unscoped transaction: %w", err)
	}
	if pool == nil {
		return nil, errors.New("database: connection pool is required")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("database: begin tenant transaction: %w", err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE kelvin_app"); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("database: assume tenant-scoped application role: %w", err)
	}
	if _, err = tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID.String()); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("database: set tenant context: %w", err)
	}
	return tx, nil
}

// TenantPredicate returns an explicit repository predicate in addition to RLS.
// qualifier must be a static SQL relation or alias, never request input.
func TenantPredicate(ctx context.Context, qualifier string) (string, any, error) {
	id, err := tenant.ID(ctx)
	if err != nil {
		return "", nil, err
	}
	if qualifier != "" && !relationQualifier.MatchString(qualifier) {
		return "", nil, errors.New("database: invalid static relation qualifier")
	}
	column := "tenant_id"
	if qualifier != "" {
		column = qualifier + ".tenant_id"
	}
	return column + " = $1", id, nil
}
