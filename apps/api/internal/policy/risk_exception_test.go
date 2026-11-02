package policy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRiskException_SubmissionValidation(t *testing.T) {
	ctx := context.Background()
	validator := NewMemoryRiskApproverValidator()
	svc := NewRiskExceptionService(validator)

	orgID := uuid.New()
	findingID := uuid.New()
	requester := "developer-alice"

	t.Run("valid submission for business justification", func(t *testing.T) {
		req, err := svc.SubmitRequest(
			ctx,
			orgID,
			findingID,
			CategoryBusinessJustification,
			"HIGH",
			"Legacy system migration scheduled for next quarter",
			"WAF rule blocking external malicious payloads",
			requester,
			60,
		)
		require.NoError(t, err)
		assert.Equal(t, StatusPending, req.Status)
		assert.False(t, req.RequiresDualApproval)
		assert.Equal(t, 60, req.RequestedDays)
	})

	t.Run("critical severity automatically requires dual approval", func(t *testing.T) {
		req, err := svc.SubmitRequest(
			ctx,
			orgID,
			findingID,
			CategoryCompensatingControl,
			"CRITICAL",
			"Air-gapped enclave with physical isolation",
			"Isolated VLAN + Mutual TLS",
			requester,
			30,
		)
		require.NoError(t, err)
		assert.True(t, req.RequiresDualApproval)
	})

	t.Run("rejects duration over 90 days", func(t *testing.T) {
		_, err := svc.SubmitRequest(
			ctx,
			orgID,
			findingID,
			CategoryBusinessJustification,
			"MEDIUM",
			"Valid rationale",
			"",
			requester,
			91,
		)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDurationExceedsMax)
	})

	t.Run("rejects empty rationale", func(t *testing.T) {
		_, err := svc.SubmitRequest(
			ctx,
			orgID,
			findingID,
			CategoryBusinessJustification,
			"MEDIUM",
			"   ",
			"",
			requester,
			30,
		)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyRationale)
	})
}

func TestRiskException_ApprovalAndSeparationOfDuties(t *testing.T) {
	ctx := context.Background()
	validator := NewMemoryRiskApproverValidator()
	svc := NewRiskExceptionService(validator)

	orgID := uuid.New()
	findingID := uuid.New()
	requester := "alice"
	approver1 := "bob-lead"
	approver2 := "carol-ciso"

	req, err := svc.SubmitRequest(
		ctx,
		orgID,
		findingID,
		CategoryBusinessJustification,
		"CRITICAL",
		"Production freeze in effect",
		"Network isolation",
		requester,
		30,
	)
	require.NoError(t, err)
	assert.True(t, req.RequiresDualApproval)

	t.Run("separation of duties: requester cannot approve own request", func(t *testing.T) {
		_, err := svc.ReviewRequest(ctx, req.ID, requester, "SECURITY_ADMIN", DecisionApproved, "I approve my own request")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSeparationOfDutiesViolation)
	})

	t.Run("unauthorized role cannot approve", func(t *testing.T) {
		_, err := svc.ReviewRequest(ctx, req.ID, "junior-dev", "SOFTWARE_ENGINEER", DecisionApproved, "Looks ok")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnauthorizedApproverRole)
	})

	t.Run("first approval leaves critical request pending", func(t *testing.T) {
		reviewed, err := svc.ReviewRequest(ctx, req.ID, approver1, "SECURITY_ADMIN", DecisionApproved, "Approved by SecOps")
		require.NoError(t, err)
		assert.Equal(t, StatusPending, reviewed.Status)
		require.Len(t, reviewed.Approvals, 1)
	})

	t.Run("duplicate approver is rejected", func(t *testing.T) {
		_, err := svc.ReviewRequest(ctx, req.ID, approver1, "SECURITY_ADMIN", DecisionApproved, "Approve again")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDuplicateApprover)
	})

	t.Run("second approval activates approved status and computes review/expiry dates", func(t *testing.T) {
		reviewed, err := svc.ReviewRequest(ctx, req.ID, approver2, "CISO", DecisionApproved, "Final CISO Sign-off")
		require.NoError(t, err)
		assert.Equal(t, StatusApproved, reviewed.Status)
		assert.NotNil(t, reviewed.ApprovedAt)
		assert.NotNil(t, reviewed.ExpiresAt)
		assert.NotNil(t, reviewed.ReviewDate)
		require.Len(t, reviewed.Approvals, 2)
	})
}

func TestRiskException_RevocationAndExpiry(t *testing.T) {
	ctx := context.Background()
	validator := NewMemoryRiskApproverValidator()
	svc := NewRiskExceptionService(validator)

	orgID := uuid.New()
	findingID := uuid.New()
	requester := "alice"
	approver := "secops-bob"

	req, err := svc.SubmitRequest(
		ctx,
		orgID,
		findingID,
		CategoryBusinessJustification,
		"HIGH",
		"De-scoped module",
		"Firewall restriction",
		requester,
		14,
	)
	require.NoError(t, err)

	// Single approval for HIGH severity activates exception
	reviewed, err := svc.ReviewRequest(ctx, req.ID, approver, "SECURITY_ADMIN", DecisionApproved, "Approved")
	require.NoError(t, err)
	assert.Equal(t, StatusApproved, reviewed.Status)

	t.Run("evaluating expiry marks overdue exception as expired", func(t *testing.T) {
		// Before expiry
		expired := svc.EvaluateExpirations(time.Now().UTC())
		assert.Empty(t, expired)

		// After expiry (15 days later)
		future := time.Now().UTC().Add(15 * 24 * time.Hour)
		expired = svc.EvaluateExpirations(future)
		assert.Contains(t, expired, req.ID)

		fetched, err := svc.GetRequest(req.ID)
		require.NoError(t, err)
		assert.Equal(t, StatusExpired, fetched.Status)
	})

	t.Run("revoking an active exception updates status to revoked", func(t *testing.T) {
		// New request to test revocation
		req2, err := svc.SubmitRequest(
			ctx,
			orgID,
			uuid.New(),
			CategoryCompensatingControl,
			"MEDIUM",
			"Temporary risk",
			"",
			requester,
			10,
		)
		require.NoError(t, err)

		approved, err := svc.ReviewRequest(ctx, req2.ID, approver, "SECURITY_ADMIN", DecisionApproved, "Approved")
		require.NoError(t, err)
		assert.Equal(t, StatusApproved, approved.Status)

		revoked, err := svc.RevokeException(ctx, req2.ID, approver, "SECURITY_ADMIN", "Compensating control failed audit")
		require.NoError(t, err)
		assert.Equal(t, StatusRevoked, revoked.Status)
	})
}
