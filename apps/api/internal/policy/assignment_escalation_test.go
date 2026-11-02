package policy

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssignmentEscalation_RuleConfiguration(t *testing.T) {
	ctx := context.Background()
	validator := NewMemoryEntityValidator()
	svc := NewAssignmentEscalationService(validator)

	orgID := uuid.New()
	userAlice := "alice-123"
	userBob := "bob-456"

	// Register alice as active
	validator.RegisterEntity(orgID, AssigneeUser, userAlice)

	t.Run("configure valid assignment rule", func(t *testing.T) {
		rule := &AssignmentRule{
			OrganizationID:     orgID,
			Name:               "Critical RCE to Alice",
			Priority:           10,
			VulnerabilityClass: "RCE",
			MinSeverity:        "CRITICAL",
			AssigneeType:       AssigneeUser,
			AssigneeID:         userAlice,
		}

		configured, err := svc.ConfigureAssignmentRule(ctx, rule)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, configured.ID)
		assert.Equal(t, 1, configured.Version)
		assert.True(t, configured.IsActive)
	})

	t.Run("reject rule with inactive assignee", func(t *testing.T) {
		rule := &AssignmentRule{
			OrganizationID: orgID,
			Name:           "Assign to inactive Bob",
			AssigneeType:   AssigneeUser,
			AssigneeID:     userBob, // not registered
		}

		_, err := svc.ConfigureAssignmentRule(ctx, rule)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInactiveAssignee)
	})

	t.Run("update existing rule increments version", func(t *testing.T) {
		rule := &AssignmentRule{
			OrganizationID: orgID,
			Name:           "Original Rule",
			AssigneeType:   AssigneeUser,
			AssigneeID:     userAlice,
		}
		saved, err := svc.ConfigureAssignmentRule(ctx, rule)
		require.NoError(t, err)

		saved.Description = "Updated Description"
		updated, err := svc.ConfigureAssignmentRule(ctx, saved)
		require.NoError(t, err)
		assert.Equal(t, saved.ID, updated.ID)
		assert.Equal(t, 2, updated.Version)
	})
}

func TestAssignmentEscalation_Evaluation(t *testing.T) {
	ctx := context.Background()
	validator := NewMemoryEntityValidator()
	svc := NewAssignmentEscalationService(validator)

	orgID := uuid.New()
	wsID := uuid.New()

	userSecOps := "secops-alice"
	userWebTeam := "web-bob"
	userFallback := "fallback-charlie"
	orgDefaultAdmin := "ciso-dan"

	validator.RegisterEntity(orgID, AssigneeUser, userSecOps)
	validator.RegisterEntity(orgID, AssigneeUser, userWebTeam)
	validator.RegisterEntity(orgID, AssigneeUser, userFallback)
	validator.RegisterEntity(orgID, AssigneeUser, orgDefaultAdmin)

	err := svc.SetDefaultFallback(orgID, AssigneeUser, orgDefaultAdmin)
	require.NoError(t, err)

	// Rule 1: High Priority: Critical Web Vulnerabilities to SecOps
	rule1 := &AssignmentRule{
		OrganizationID:     orgID,
		Name:               "Critical Web Vulns to SecOps",
		Priority:           10,
		TargetTag:          "production-web",
		MinSeverity:        "CRITICAL",
		AssigneeType:       AssigneeUser,
		AssigneeID:         userSecOps,
		FallbackAssigneeType: AssigneeUser,
		FallbackAssigneeID:   userFallback,
	}
	_, err = svc.ConfigureAssignmentRule(ctx, rule1)
	require.NoError(t, err)

	// Rule 2: Lower Priority: All Web App vulns to Web Team
	rule2 := &AssignmentRule{
		OrganizationID:     orgID,
		Name:               "Web Team Generic",
		Priority:           50,
		TargetTag:          "production-web",
		AssigneeType:       AssigneeUser,
		AssigneeID:         userWebTeam,
	}
	_, err = svc.ConfigureAssignmentRule(ctx, rule2)
	require.NoError(t, err)

	t.Run("matches high priority rule for critical finding", func(t *testing.T) {
		finding := FindingContext{
			OrganizationID: orgID,
			WorkspaceID:    wsID,
			FindingID:      uuid.New(),
			TargetTag:      "production-web",
			Severity:       "CRITICAL",
		}

		res, err := svc.EvaluateAssignment(ctx, finding)
		require.NoError(t, err)
		assert.Equal(t, userSecOps, res.AssignedToID)
		assert.Equal(t, SourceRuleMatch, res.AssignmentSource)
	})

	t.Run("matches lower priority rule when severity is medium", func(t *testing.T) {
		finding := FindingContext{
			OrganizationID: orgID,
			WorkspaceID:    wsID,
			FindingID:      uuid.New(),
			TargetTag:      "production-web",
			Severity:       "MEDIUM",
		}

		res, err := svc.EvaluateAssignment(ctx, finding)
		require.NoError(t, err)
		assert.Equal(t, userWebTeam, res.AssignedToID)
		assert.Equal(t, SourceRuleMatch, res.AssignmentSource)
	})

	t.Run("uses rule fallback when primary assignee is deactivated", func(t *testing.T) {
		validator.DeactivateEntity(orgID, AssigneeUser, userSecOps)

		finding := FindingContext{
			OrganizationID: orgID,
			WorkspaceID:    wsID,
			FindingID:      uuid.New(),
			TargetTag:      "production-web",
			Severity:       "CRITICAL",
		}

		res, err := svc.EvaluateAssignment(ctx, finding)
		require.NoError(t, err)
		assert.Equal(t, userFallback, res.AssignedToID)
		assert.Equal(t, SourceDefaultFallback, res.AssignmentSource)

		// restore secops
		validator.RegisterEntity(orgID, AssigneeUser, userSecOps)
	})

	t.Run("uses organization default fallback when no rule criteria match", func(t *testing.T) {
		finding := FindingContext{
			OrganizationID: orgID,
			WorkspaceID:    wsID,
			FindingID:      uuid.New(),
			TargetTag:      "internal-database", // No rule for internal-database
			Severity:       "LOW",
		}

		res, err := svc.EvaluateAssignment(ctx, finding)
		require.NoError(t, err)
		assert.Equal(t, orgDefaultAdmin, res.AssignedToID)
		assert.Equal(t, SourceDefaultFallback, res.AssignmentSource)
	})
}

func TestAssignmentEscalation_EscalationAndCycleDefense(t *testing.T) {
	ctx := context.Background()
	validator := NewMemoryEntityValidator()
	svc := NewAssignmentEscalationService(validator)

	orgID := uuid.New()
	devLead := "lead-dev"
	securityLead := "lead-sec"
	ciso := "ciso"

	validator.RegisterEntity(orgID, AssigneeUser, devLead)
	validator.RegisterEntity(orgID, AssigneeUser, securityLead)
	validator.RegisterEntity(orgID, AssigneeUser, ciso)

	t.Run("detects and rejects circular escalation policy", func(t *testing.T) {
		policy1ID := uuid.New()
		policy2ID := uuid.New()

		p1 := &EscalationPolicy{
			ID:                     policy1ID,
			OrganizationID:         orgID,
			Name:                   "Level 1 Escalation",
			TriggerCondition:       TriggerSLABreached,
			EscalationLevel:        1,
			EscalateToType:         AssigneeUser,
			EscalateToID:           devLead,
			NextEscalationPolicyID: &policy2ID,
		}
		_, err := svc.ConfigureEscalationPolicy(ctx, p1)
		require.NoError(t, err)

		// Circular: p2 points back to p1
		p2 := &EscalationPolicy{
			ID:                     policy2ID,
			OrganizationID:         orgID,
			Name:                   "Level 2 Escalation Circular",
			TriggerCondition:       TriggerSLABreached,
			EscalationLevel:        2,
			EscalateToType:         AssigneeUser,
			EscalateToID:           securityLead,
			NextEscalationPolicyID: &policy1ID, // CYCLE
		}
		_, err = svc.ConfigureEscalationPolicy(ctx, p2)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrCircularEscalationDetected)
	})

	t.Run("escalates to next level on SLA breach", func(t *testing.T) {
		validP2 := &EscalationPolicy{
			OrganizationID:   orgID,
			Name:             "Level 2 to Security Lead",
			TriggerCondition: TriggerSLABreached,
			EscalationLevel:  2,
			EscalateToType:   AssigneeUser,
			EscalateToID:     securityLead,
		}
		_, err := svc.ConfigureEscalationPolicy(ctx, validP2)
		require.NoError(t, err)

		finding := FindingContext{
			OrganizationID:         orgID,
			FindingID:              uuid.New(),
			CurrentAssigneeType:    AssigneeUser,
			CurrentAssigneeID:      devLead,
			CurrentEscalationLevel: 1,
			IsManualOverride:       false,
		}

		res, err := svc.EvaluateEscalation(ctx, finding, TriggerSLABreached)
		require.NoError(t, err)
		assert.Equal(t, securityLead, res.AssignedToID)
		assert.Equal(t, 2, res.EscalationLevel)
		assert.Equal(t, SourceEscalation, res.AssignmentSource)
	})

	t.Run("skips automated escalation when manual override is active", func(t *testing.T) {
		finding := FindingContext{
			OrganizationID:         orgID,
			FindingID:              uuid.New(),
			CurrentAssigneeType:    AssigneeUser,
			CurrentAssigneeID:      devLead,
			CurrentEscalationLevel: 1,
			IsManualOverride:       true, // Locked by manual assignment
		}

		_, err := svc.EvaluateEscalation(ctx, finding, TriggerSLABreached)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "manual override")
	})
}

func TestAssignmentEscalation_ManualOverrideAndHistory(t *testing.T) {
	ctx := context.Background()
	validator := NewMemoryEntityValidator()
	svc := NewAssignmentEscalationService(validator)

	orgID := uuid.New()
	overrideUser := "special-investigator"
	validator.RegisterEntity(orgID, AssigneeUser, overrideUser)

	findingID := uuid.New()
	finding := FindingContext{
		OrganizationID: orgID,
		FindingID:      findingID,
	}

	t.Run("manual override records audit and execution", func(t *testing.T) {
		res, err := svc.ManualOverride(ctx, finding, "auditor-dan", AssigneeUser, overrideUser, "Executive escalated priority")
		require.NoError(t, err)
		assert.Equal(t, overrideUser, res.AssignedToID)
		assert.Equal(t, SourceManualOverride, res.AssignmentSource)
		assert.Equal(t, "auditor-dan", res.ActorID)

		history := svc.GetExecutionHistory(findingID)
		require.Len(t, history, 1)
		assert.Equal(t, "Executive escalated priority", history[0].Reason)
	})

	t.Run("rejects manual override without actor", func(t *testing.T) {
		_, err := svc.ManualOverride(ctx, finding, "", AssigneeUser, overrideUser, "Missing actor")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManualOverrideForbidden)
	})
}
