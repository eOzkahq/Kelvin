// Package database contains the worker's fail-closed tenant transaction helper.
package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

// BeginTenantTx assumes the restricted application role and sets transaction-
// local tenant context before any worker database query can run.
func BeginTenantTx(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	id, err := tenant.ID(ctx)
	if err != nil {
		return nil, fmt.Errorf("worker database: tenant context required: %w", err)
	}
	if pool == nil {
		return nil, fmt.Errorf("worker database: connection pool required")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("worker database: begin tenant transaction: %w", err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE kelvin_app"); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("worker database: assume tenant-scoped role: %w", err)
	}
	if _, err = tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", id.String()); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("worker database: set tenant context: %w", err)
	}
	return tx, nil
}
