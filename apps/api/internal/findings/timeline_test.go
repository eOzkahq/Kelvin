package findings

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestTimelineRedaction(t *testing.T) {
	rawPayload := map[string]any{
		"scanner": "nuclei",
		"auth": map[string]any{
			"authorization": "Bearer super-secret-token-12345",
			"password":      "SuperSecretPassword!",
			"cookie":        "session_id=abcdef123456",
		},
		"endpoint": "https://api.example.com/v1/auth",
	}

	sanitized := SanitizePayload(rawPayload)

	authMap, ok := sanitized["auth"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth submap, got %T", sanitized["auth"])
	}

	if authMap["authorization"] != "[REDACTED]" {
		t.Errorf("expected authorization to be [REDACTED], got %v", authMap["authorization"])
	}
	if authMap["password"] != "[REDACTED]" {
		t.Errorf("expected password to be [REDACTED], got %v", authMap["password"])
	}
	if authMap["cookie"] != "[REDACTED]" {
		t.Errorf("expected cookie to be [REDACTED], got %v", authMap["cookie"])
	}
	if sanitized["scanner"] != "nuclei" {
		t.Errorf("expected non-sensitive scanner to be preserved, got %v", sanitized["scanner"])
	}
}

func TestRecordTimelineEventValidation(t *testing.T) {
	repo := &PostgresFindingRepository{db: nil}
	ctx := context.Background()

	// Nil entry
	if err := repo.RecordTimelineEvent(ctx, nil); err == nil {
		t.Errorf("expected error on nil entry")
	}

	// Missing tenant
	if err := repo.RecordTimelineEvent(ctx, &TimelineEntry{
		FindingID: uuid.New(),
		EventType: TimelineEventFindingCreated,
	}); err != ErrTenantRequired {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}

	// Missing finding
	if err := repo.RecordTimelineEvent(ctx, &TimelineEntry{
		TenantID:  uuid.New(),
		EventType: TimelineEventFindingCreated,
	}); err != ErrFindingIDRequired {
		t.Errorf("expected ErrFindingIDRequired, got %v", err)
	}

	// Missing event type
	if err := repo.RecordTimelineEvent(ctx, &TimelineEntry{
		TenantID:  uuid.New(),
		FindingID: uuid.New(),
		EventType: "   ",
	}); err != ErrEventTypeRequired {
		t.Errorf("expected ErrEventTypeRequired, got %v", err)
	}
}

func TestGetTimelineByFindingValidation(t *testing.T) {
	repo := &PostgresFindingRepository{db: nil}
	ctx := context.Background()

	// Missing tenant
	if _, err := repo.GetTimelineByFinding(ctx, uuid.Nil, uuid.New(), 10, 0); err != ErrTenantRequired {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}

	// Missing finding
	if _, err := repo.GetTimelineByFinding(ctx, uuid.New(), uuid.Nil, 10, 0); err != ErrFindingIDRequired {
		t.Errorf("expected ErrFindingIDRequired, got %v", err)
	}
}
