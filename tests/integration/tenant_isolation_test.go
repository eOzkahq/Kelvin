package integration

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func TestPostgresTenantRLSAndNestedOwnership(t *testing.T) {
	dsn := os.Getenv("KELVIN_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KELVIN_DATABASE_URL to a migrated PostgreSQL database")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Ping(); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err = db.QueryRow(`SELECT to_regclass('public.projects') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Skip("tenant schema has not been migrated")
	}
	tenantA, tenantB := uuid.New(), uuid.New()
	projectA, projectB := uuid.New(), uuid.New()
	cleanup := func() {
		tx, e := db.Begin()
		if e != nil {
			return
		}
		defer tx.Rollback()
		if _, e = tx.Exec(`SET LOCAL ROLE kelvin_app`); e != nil {
			return
		}
		for _, id := range []uuid.UUID{tenantA, tenantB} {
			if _, e = tx.Exec(`SELECT set_config('app.tenant_id',$1,true)`, id.String()); e != nil {
				return
			}
			if _, e = tx.Exec(`DELETE FROM projects WHERE tenant_id=$1`, id); e != nil {
				return
			}
			if _, e = tx.Exec(`DELETE FROM tenants WHERE id=$1`, id); e != nil {
				return
			}
		}
		_ = tx.Commit()
	}
	defer cleanup()

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`SET LOCAL ROLE kelvin_app`); err != nil {
		_ = tx.Rollback()
		t.Fatalf("database role must be able to assume kelvin_app: %v", err)
	}
	for _, seed := range []struct{ tenant, project uuid.UUID }{{tenantA, projectA}, {tenantB, projectB}} {
		if _, err = tx.Exec(`SELECT set_config('app.tenant_id',$1,true)`, seed.tenant.String()); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err = tx.Exec(`INSERT INTO tenants(id,name,slug) VALUES($1,$2,$3)`, seed.tenant, "Tenant isolation integration", "ti-"+strings.ReplaceAll(seed.tenant.String(), "-", "")); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err = tx.Exec(`INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,$3)`, seed.project, seed.tenant, "tenant-boundary-"+seed.project.String()); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	readTx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readTx.Exec(`SET LOCAL ROLE kelvin_app`); err != nil {
		_ = readTx.Rollback()
		t.Fatal(err)
	}
	if _, err = readTx.Exec(`SELECT set_config('app.tenant_id',$1,true)`, tenantA.String()); err != nil {
		_ = readTx.Rollback()
		t.Fatal(err)
	}
	rows, err := readTx.Query(`SELECT id FROM projects WHERE id IN ($1,$2)`, projectA, projectB)
	if err != nil {
		_ = readTx.Rollback()
		t.Fatal(err)
	}
	var visible []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			_ = readTx.Rollback()
			t.Fatal(err)
		}
		visible = append(visible, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		_ = readTx.Rollback()
		t.Fatal(err)
	}
	_ = rows.Close()
	if err = readTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 || visible[0] != projectA.String() {
		t.Fatalf("tenant A saw projects %v", visible)
	}

	writeTx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writeTx.Exec(`SET LOCAL ROLE kelvin_app`)
	_, _ = writeTx.Exec(`SELECT set_config('app.tenant_id',$1,true)`, tenantA.String())
	_, err = writeTx.Exec(`INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,$3)`, uuid.New(), tenantB, "cross-tenant-write")
	if err == nil {
		_ = writeTx.Rollback()
		t.Fatal("RLS allowed cross-tenant project insert")
	}
	_ = writeTx.Rollback()

	nestedTx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = nestedTx.Exec(`SET LOCAL ROLE kelvin_app`)
	_, _ = nestedTx.Exec(`SELECT set_config('app.tenant_id',$1,true)`, tenantA.String())
	_, err = nestedTx.Exec(`INSERT INTO assets(id,tenant_id,project_id,target_type,value) VALUES($1,$2,$3,'DOMAIN','foreign.example')`, uuid.New(), tenantA, projectB)
	if err == nil {
		_ = nestedTx.Rollback()
		t.Fatal("composite ownership FK allowed cross-tenant parent link")
	}
	_ = nestedTx.Rollback()
}
