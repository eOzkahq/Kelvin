package findings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// mockRow implements pgx.Row for testing QueryRow.
type mockRow struct {
	scanFn func(dest ...any) error
}

func (r *mockRow) Scan(dest ...any) error {
	if r.scanFn != nil {
		return r.scanFn(dest...)
	}
	return nil
}

// mockRows implements pgx.Rows for testing Query.
type mockRows struct {
	data   [][]any
	index  int
	closed bool
	err    error
}

func (r *mockRows) Close() {
	r.closed = true
}

func (r *mockRows) Err() error {
	return r.err
}

func (r *mockRows) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag("SELECT 1")
}

func (r *mockRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}

func (r *mockRows) Next() bool {
	if r.closed || r.index >= len(r.data) {
		return false
	}
	r.index++
	return true
}

func (r *mockRows) Scan(dest ...any) error {
	if r.index <= 0 || r.index > len(r.data) {
		return errors.New("no row to scan")
	}
	row := r.data[r.index-1]
	for i, val := range row {
		if i >= len(dest) {
			break
		}
		switch d := dest[i].(type) {
		case *uuid.UUID:
			if u, ok := val.(uuid.UUID); ok {
				*d = u
			}
		case **uuid.UUID:
			if u, ok := val.(*uuid.UUID); ok {
				*d = u
			}
		case *string:
			if s, ok := val.(string); ok {
				*d = s
			}
		case *FindingStatus:
			if s, ok := val.(FindingStatus); ok {
				*d = s
			}
		case *float64:
			if f, ok := val.(float64); ok {
				*d = f
			}
		case **float64:
			if f, ok := val.(*float64); ok {
				*d = f
			}
		case *[]string:
			if s, ok := val.([]string); ok {
				*d = s
			}
		case *time.Time:
			if t, ok := val.(time.Time); ok {
				*d = t
			}
		case **time.Time:
			if t, ok := val.(*time.Time); ok {
				*d = t
			}
		case *int64:
			if n, ok := val.(int64); ok {
				*d = n
			}
		case *[]byte:
			if b, ok := val.([]byte); ok {
				*d = b
			}
		}
	}
	return nil
}

func (r *mockRows) Values() ([]any, error) {
	return nil, nil
}

func (r *mockRows) RawValues() [][]byte {
	return nil
}

func (r *mockRows) Conn() *pgx.Conn {
	return nil
}

func (r *mockRows) TypeMap() *pgtype.Map {
	return pgtype.NewMap()
}

// mockDBTX implements DBTX for unit testing repository queries.
type mockDBTX struct {
	execFn     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	queryFn    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
}

func (m *mockDBTX) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	if m.execFn != nil {
		return m.execFn(ctx, sql, arguments...)
	}
	return pgconn.NewCommandTag("INSERT 1"), nil
}

func (m *mockDBTX) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if m.queryFn != nil {
		return m.queryFn(ctx, sql, args...)
	}
	return &mockRows{}, nil
}

func (m *mockDBTX) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if m.queryRowFn != nil {
		return m.queryRowFn(ctx, sql, args...)
	}
	return &mockRow{}
}

func TestPostgresFindingRepositorySaveAndGetByID(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	projectID := uuid.New()
	findingID := uuid.New()
	asmtID := uuid.New()
	jobID := uuid.New()
	now := time.Now().UTC()

	var executedSQL string
	mock := &mockDBTX{
		execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			executedSQL = sql
			return pgconn.NewCommandTag("INSERT 1"), nil
		},
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return &mockRow{
				scanFn: func(dest ...any) error {
					// Populate destination fields
					*dest[0].(*uuid.UUID) = findingID
					*dest[1].(*uuid.UUID) = tenantID
					*dest[2].(*uuid.UUID) = projectID
					*dest[3].(*uuid.UUID) = asmtID
					*dest[4].(*uuid.UUID) = jobID
					*dest[5].(**uuid.UUID) = nil
					*dest[6].(**uuid.UUID) = nil
					*dest[7].(*string) = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
					*dest[8].(*string) = "SQL Injection in User Search"
					*dest[9].(*string) = "CRITICAL"
					*dest[10].(*float64) = 0.98
					*dest[11].(**float64) = nil
					*dest[12].(*string) = "CWE-89"
					*dest[13].(*[]string) = []string{"CVE-2023-1234"}
					*dest[14].(*FindingStatus) = StatusOpen
					*dest[15].(*string) = "https://api.example.com/search"
					*dest[16].(*[]byte) = []byte(`{"scanner":"nuclei"}`)
					*dest[17].(*[]string) = []string{"injection", "cwe-89"}
					*dest[18].(*time.Time) = now
					*dest[19].(*time.Time) = now
					*dest[20].(*uuid.UUID) = jobID
					*dest[21].(**uuid.UUID) = &jobID
					*dest[22].(*int64) = 1
					*dest[23].(*time.Time) = now
					*dest[24].(*time.Time) = now
					return nil
				},
			}
		},
	}

	repo := NewPostgresFindingRepository(mock)

	finding := &PersistentFinding{
		ID:               findingID,
		TenantID:         tenantID,
		ProjectID:        projectID,
		AssessmentID:     asmtID,
		JobID:            jobID,
		Fingerprint:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Title:            "SQL Injection in User Search",
		Severity:         "CRITICAL",
		Confidence:       0.98,
		CWEID:            "CWE-89",
		CVEIDs:           []string{"CVE-2023-1234"},
		Status:           StatusOpen,
		AffectedEndpoint: "https://api.example.com/search",
		FirstSeenAt:      now,
		LastSeenAt:       now,
		FirstJobID:       jobID,
		OccurrenceCount:  1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	// 1. Test SaveFinding
	err := repo.SaveFinding(ctx, finding)
	if err != nil {
		t.Fatalf("SaveFinding failed: %v", err)
	}
	if executedSQL == "" {
		t.Errorf("expected SQL execution for SaveFinding")
	}

	// 2. Test GetFindingByID
	found, err := repo.GetFindingByID(ctx, tenantID, findingID)
	if err != nil {
		t.Fatalf("GetFindingByID failed: %v", err)
	}
	if found.ID != findingID {
		t.Errorf("ID mismatch: got %s, want %s", found.ID, findingID)
	}
	if found.Title != "SQL Injection in User Search" {
		t.Errorf("Title mismatch: got %s", found.Title)
	}
	if found.ScannerData["scanner"] != "nuclei" {
		t.Errorf("ScannerData unmarshal failed: %v", found.ScannerData)
	}
}

func TestPostgresFindingRepositoryGetObservationsByFinding(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	findingID := uuid.New()
	obsID := uuid.New()
	asmtID := uuid.New()
	jobID := uuid.New()
	now := time.Now().UTC()

	mock := &mockDBTX{
		queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			return &mockRows{
				data: [][]any{
					{
						obsID,
						tenantID,
						findingID,
						asmtID,
						jobID,
						"zap-baseline",
						now,
						[]byte(`["ev-001", "ev-002"]`),
						[]byte(`{"rule_id":"10020"}`),
						now,
					},
				},
			}, nil
		},
	}

	repo := NewPostgresFindingRepository(mock)

	observations, err := repo.GetObservationsByFinding(ctx, tenantID, findingID, 10, 0)
	if err != nil {
		t.Fatalf("GetObservationsByFinding failed: %v", err)
	}

	if len(observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(observations))
	}

	obs := observations[0]
	if obs.ID != obsID {
		t.Errorf("obs ID mismatch: got %s, want %s", obs.ID, obsID)
	}
	if obs.ScannerID != "zap-baseline" {
		t.Errorf("scanner ID mismatch: got %s", obs.ScannerID)
	}
	if len(obs.EvidenceRefs) != 2 || obs.EvidenceRefs[0] != "ev-001" {
		t.Errorf("evidence refs unmarshal failed: %v", obs.EvidenceRefs)
	}
	if obs.RawMetadata["rule_id"] != "10020" {
		t.Errorf("metadata unmarshal failed: %v", obs.RawMetadata)
	}
}

func TestPostgresFindingRepositorySaveObservationAndEvent(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	findingID := uuid.New()
	corrID := uuid.New()

	var execCount int
	mock := &mockDBTX{
		execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			execCount++
			return pgconn.NewCommandTag("INSERT 1"), nil
		},
	}

	repo := NewPostgresFindingRepository(mock)

	obs := &FindingObservation{
		ID:           uuid.New(),
		TenantID:     tenantID,
		FindingID:    findingID,
		AssessmentID: uuid.New(),
		JobID:        uuid.New(),
		ScannerID:    "nuclei",
		ObservedAt:   time.Now().UTC(),
		EvidenceRefs: []string{"ev-123"},
		RawMetadata:  map[string]any{"cve": "CVE-2021-44228"},
		CreatedAt:    time.Now().UTC(),
	}

	if err := repo.SaveObservation(ctx, obs); err != nil {
		t.Fatalf("SaveObservation failed: %v", err)
	}

	fromStatus := StatusOpen
	ev := &FindingEvent{
		ID:            uuid.New(),
		TenantID:      tenantID,
		FindingID:     findingID,
		FromStatus:    &fromStatus,
		ToStatus:      StatusConfirmed,
		EventType:     EventTriage,
		Note:          "Confirmed via curl reproduction",
		CorrelationID: corrID,
		CreatedAt:     time.Now().UTC(),
	}

	if err := repo.SaveEvent(ctx, ev); err != nil {
		t.Fatalf("SaveEvent failed: %v", err)
	}

	if execCount != 2 {
		t.Errorf("expected 2 executions, got %d", execCount)
	}
}
