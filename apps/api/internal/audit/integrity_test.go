package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrityEngine_ValidChainAndCheckpoint(t *testing.T) {
	engine := NewIntegrityEngine("test-hmac-secret-key-super-secure")
	tenantID := uuid.New()
	baseTime := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

	var chain []ChainedEvent
	var last *ChainedEvent

	// Generate 5 valid chained events
	for i := 0; i < 5; i++ {
		e := ChainedEvent{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Action:        "user.login",
			EntityType:    "user",
			Payload:       json.RawMessage(`{"ip": "1.2.3.4"}`),
			CorrelationID: "corr-1",
			CreatedAt:     baseTime.Add(time.Duration(i) * time.Minute),
		}
		chained := engine.AppendChainedEvent(last, e)
		chain = append(chain, chained)
		last = &chain[len(chain)-1]
	}

	assert.Equal(t, GenesisHash, chain[0].PreviousHash)
	assert.Equal(t, int64(1), chain[0].SequenceNum)
	assert.Equal(t, chain[0].CurrentHash, chain[1].PreviousHash)
	assert.Equal(t, int64(5), chain[4].SequenceNum)

	// Create signed checkpoint
	cp, err := engine.CreateCheckpoint(context.Background(), tenantID, 1, chain)
	require.NoError(t, err)
	assert.Equal(t, 5, cp.RecordCount)
	assert.Equal(t, chain[0].CurrentHash, cp.StartHash)
	assert.Equal(t, chain[4].CurrentHash, cp.EndHash)
	assert.NotEmpty(t, cp.Signature)
	assert.True(t, engine.VerifyCheckpointSignature(cp))

	// Verify intact chain against checkpoint
	res, err := engine.VerifyChain(context.Background(), chain, cp)
	require.NoError(t, err)
	assert.True(t, res.Valid)
	assert.Equal(t, 5, res.CheckedCount)
	assert.Empty(t, res.Alerts)
}

func TestIntegrityEngine_DetectTamperedRecordContent(t *testing.T) {
	engine := NewIntegrityEngine("test-secret")
	tenantID := uuid.New()
	baseTime := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

	var chain []ChainedEvent
	var last *ChainedEvent

	for i := 0; i < 3; i++ {
		e := ChainedEvent{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Action:        "finding.status_change",
			EntityType:    "finding",
			Payload:       json.RawMessage(`{"old": "OPEN", "new": "RESOLVED"}`),
			CorrelationID: "corr-tamper",
			CreatedAt:     baseTime.Add(time.Duration(i) * time.Minute),
		}
		chained := engine.AppendChainedEvent(last, e)
		chain = append(chain, chained)
		last = &chain[len(chain)-1]
	}

	cp, err := engine.CreateCheckpoint(context.Background(), tenantID, 1, chain)
	require.NoError(t, err)

	// In-place tampering of record #1: attacker modifies payload
	chain[1].Payload = json.RawMessage(`{"old": "OPEN", "new": "SUPPRESSED"}`)

	res, err := engine.VerifyChain(context.Background(), chain, cp)
	assert.ErrorIs(t, err, ErrHashMismatch)
	assert.False(t, res.Valid)
	require.Len(t, res.Alerts, 1)
	assert.Equal(t, FailureHashMismatch, res.Alerts[0].FailureType)
	assert.Equal(t, int64(2), res.Alerts[0].SequenceNum)
}

func TestIntegrityEngine_DetectDeletedRecord(t *testing.T) {
	engine := NewIntegrityEngine("test-secret")
	tenantID := uuid.New()
	baseTime := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

	var chain []ChainedEvent
	var last *ChainedEvent

	for i := 0; i < 4; i++ {
		e := ChainedEvent{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Action:        "report.downloaded",
			EntityType:    "report",
			Payload:       json.RawMessage(`{}`),
			CorrelationID: "corr-del",
			CreatedAt:     baseTime.Add(time.Duration(i) * time.Minute),
		}
		chained := engine.AppendChainedEvent(last, e)
		chain = append(chain, chained)
		last = &chain[len(chain)-1]
	}

	cp, err := engine.CreateCheckpoint(context.Background(), tenantID, 1, chain)
	require.NoError(t, err)

	// Attacker deletes record at index 2 (sequence 3)
	tamperedChain := []ChainedEvent{chain[0], chain[1], chain[3]}

	res, err := engine.VerifyChain(context.Background(), tamperedChain, cp)
	assert.ErrorIs(t, err, ErrSequenceBreak)
	assert.False(t, res.Valid)
	require.Len(t, res.Alerts, 1)
	assert.Equal(t, FailureChainBroken, res.Alerts[0].FailureType)
}

func TestIntegrityEngine_DetectTamperedCheckpointSignature(t *testing.T) {
	engine := NewIntegrityEngine("test-secret")
	tenantID := uuid.New()
	baseTime := time.Now().UTC()

	evt := engine.AppendChainedEvent(nil, ChainedEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Action:    "test",
		Payload:   json.RawMessage(`{}`),
		CreatedAt: baseTime,
	})

	cp, err := engine.CreateCheckpoint(context.Background(), tenantID, 1, []ChainedEvent{evt})
	require.NoError(t, err)

	// Forged signature
	cp.Signature = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	res, err := engine.VerifyChain(context.Background(), []ChainedEvent{evt}, cp)
	assert.ErrorIs(t, err, ErrInvalidSignature)
	assert.False(t, res.Valid)
	assert.Equal(t, FailureSignatureInvalid, res.Alerts[0].FailureType)
}

func TestComputeMerkleRoot(t *testing.T) {
	assert.Equal(t, GenesisHash, ComputeMerkleRoot(nil))

	single := "abcdef"
	assert.Equal(t, single, ComputeMerkleRoot([]string{single}))

	// Even count
	rootEven := ComputeMerkleRoot([]string{"h1", "h2", "h3", "h4"})
	assert.NotEmpty(t, rootEven)
	assert.Len(t, rootEven, 64)

	// Odd count
	rootOdd := ComputeMerkleRoot([]string{"h1", "h2", "h3"})
	assert.NotEmpty(t, rootOdd)
	assert.Len(t, rootOdd, 64)
}
