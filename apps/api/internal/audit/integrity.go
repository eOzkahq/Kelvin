package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

	FailureHashMismatch     = "HASH_MISMATCH"
	FailureChainBroken      = "CHAIN_BROKEN"
	FailureMerkleMismatch   = "MERKLE_MISMATCH"
	FailureSignatureInvalid = "SIGNATURE_INVALID"

	CheckpointStatusValid    = "VALID"
	CheckpointStatusTampered = "TAMPERED"
	CheckpointStatusPending  = "PENDING"
)

var (
	ErrEmptyEventList       = errors.New("audit integrity: cannot checkpoint an empty list of events")
	ErrSequenceBreak        = errors.New("audit integrity: sequence discontinuity detected in event chain")
	ErrHashMismatch         = errors.New("audit integrity: cryptographic hash mismatch detected")
	ErrInvalidSignature     = errors.New("audit integrity: checkpoint signature is invalid")
	ErrMerkleRootMismatch   = errors.New("audit integrity: merkle root verification failed")
)

// ChainedEvent is an audit record augmented with cryptographic link metadata.
type ChainedEvent struct {
	ID            uuid.UUID       `json:"id"`
	TenantID      uuid.UUID       `json:"tenant_id"`
	SequenceNum   int64           `json:"sequence_num"`
	PreviousHash  string          `json:"previous_hash"`
	CurrentHash   string          `json:"current_hash"`
	Action        string          `json:"action"`
	EntityType    string          `json:"entity_type"`
	EntityID      *uuid.UUID      `json:"entity_id,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	CorrelationID string          `json:"correlation_id"`
	CreatedAt     time.Time       `json:"created_at"`
}

// AuditCheckpoint represents a signed cryptographic snapshot over an audit sequence window.
type AuditCheckpoint struct {
	ID               uuid.UUID `json:"id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	CheckpointSeq    int64     `json:"checkpoint_seq"`
	StartSequenceNum int64     `json:"start_sequence_num"`
	EndSequenceNum   int64     `json:"end_sequence_num"`
	RecordCount      int       `json:"record_count"`
	StartHash        string    `json:"start_hash"`
	EndHash          string    `json:"end_hash"`
	MerkleRoot       string    `json:"merkle_root"`
	Signature        string    `json:"signature"`
	Status           string    `json:"status"` // VALID, TAMPERED, PENDING
	CreatedAt        time.Time `json:"created_at"`
}

// IntegrityAlert documents a discovered audit corruption, omission, or alteration event.
type IntegrityAlert struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	CheckpointID *uuid.UUID `json:"checkpoint_id,omitempty"`
	FailureType  string     `json:"failure_type"`
	RecordID     *uuid.UUID `json:"record_id,omitempty"`
	SequenceNum  int64      `json:"sequence_num"`
	ExpectedHash string     `json:"expected_hash"`
	ComputedHash string     `json:"computed_hash"`
	Details      string     `json:"details"`
	Status       string     `json:"status"` // OPEN, INVESTIGATING, RESOLVED
	DetectedAt   time.Time  `json:"detected_at"`
}

// VerificationResult summarizes the cryptographic audit integrity check outcome.
type VerificationResult struct {
	Valid        bool              `json:"valid"`
	CheckedCount int               `json:"checked_count"`
	Alerts       []*IntegrityAlert `json:"alerts"`
	Message      string            `json:"message"`
}

// ComputeEventHash computes SHA-256(prev_hash || id || action || entity_type || entity_id || payload || correlation_id || created_at).
func ComputeEventHash(prevHash string, evt ChainedEvent) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte(evt.ID.String()))
	h.Write([]byte(evt.Action))
	h.Write([]byte(evt.EntityType))
	if evt.EntityID != nil {
		h.Write([]byte(evt.EntityID.String()))
	}
	h.Write(evt.Payload)
	h.Write([]byte(evt.CorrelationID))
	h.Write([]byte(evt.CreatedAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeMerkleRoot calculates the binary Merkle root hash over a list of event hashes.
func ComputeMerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		return GenesisHash
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	currentLevel := make([]string, len(hashes))
	copy(currentLevel, hashes)

	for len(currentLevel) > 1 {
		var nextLevel []string
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				combined := currentLevel[i] + currentLevel[i+1]
				h := sha256.Sum256([]byte(combined))
				nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
			} else {
				// Odd count: duplicate last node
				combined := currentLevel[i] + currentLevel[i]
				h := sha256.Sum256([]byte(combined))
				nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
			}
		}
		currentLevel = nextLevel
	}

	return currentLevel[0]
}

// IntegrityEngine provides cryptographic hashing, checkpoint generation, and verification.
type IntegrityEngine struct {
	signingKey []byte
}

func NewIntegrityEngine(signingKey string) *IntegrityEngine {
	if signingKey == "" {
		signingKey = "kelvin-audit-integrity-default-hmac-key-256bit"
	}
	return &IntegrityEngine{
		signingKey: []byte(signingKey),
	}
}

// SignCheckpoint computes HMAC-SHA256 signature for checkpoint metadata.
func (e *IntegrityEngine) SignCheckpoint(cp *AuditCheckpoint) string {
	mac := hmac.New(sha256.New, e.signingKey)
	mac.Write([]byte(cp.TenantID.String()))
	mac.Write([]byte(fmt.Sprintf("%d", cp.CheckpointSeq)))
	mac.Write([]byte(fmt.Sprintf("%d", cp.StartSequenceNum)))
	mac.Write([]byte(fmt.Sprintf("%d", cp.EndSequenceNum)))
	mac.Write([]byte(fmt.Sprintf("%d", cp.RecordCount)))
	mac.Write([]byte(cp.StartHash))
	mac.Write([]byte(cp.EndHash))
	mac.Write([]byte(cp.MerkleRoot))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyCheckpointSignature checks HMAC-SHA256 signature validity in constant time.
func (e *IntegrityEngine) VerifyCheckpointSignature(cp *AuditCheckpoint) bool {
	expectedSig := e.SignCheckpoint(cp)
	return hmac.Equal([]byte(expectedSig), []byte(cp.Signature))
}

// AppendChainedEvent adds an event to the chain, assigning sequential number and cryptographic hash.
func (e *IntegrityEngine) AppendChainedEvent(lastEvent *ChainedEvent, newEvt ChainedEvent) ChainedEvent {
	prevHash := GenesisHash
	seq := int64(1)

	if lastEvent != nil {
		prevHash = lastEvent.CurrentHash
		seq = lastEvent.SequenceNum + 1
	}

	newEvt.SequenceNum = seq
	newEvt.PreviousHash = prevHash
	newEvt.CurrentHash = ComputeEventHash(prevHash, newEvt)
	return newEvt
}

// CreateCheckpoint constructs and signs an audit checkpoint snapshot over an event sequence.
func (e *IntegrityEngine) CreateCheckpoint(
	ctx context.Context,
	tenantID uuid.UUID,
	checkpointSeq int64,
	events []ChainedEvent,
) (*AuditCheckpoint, error) {
	if len(events) == 0 {
		return nil, ErrEmptyEventList
	}

	startSeq := events[0].SequenceNum
	endSeq := events[len(events)-1].SequenceNum
	startHash := events[0].CurrentHash
	endHash := events[len(events)-1].CurrentHash

	hashes := make([]string, len(events))
	for i, evt := range events {
		hashes[i] = evt.CurrentHash
	}

	merkleRoot := ComputeMerkleRoot(hashes)

	cp := &AuditCheckpoint{
		ID:               uuid.New(),
		TenantID:         tenantID,
		CheckpointSeq:    checkpointSeq,
		StartSequenceNum: startSeq,
		EndSequenceNum:   endSeq,
		RecordCount:      len(events),
		StartHash:        startHash,
		EndHash:          endHash,
		MerkleRoot:       merkleRoot,
		Status:           CheckpointStatusValid,
		CreatedAt:        time.Now().UTC(),
	}

	cp.Signature = e.SignCheckpoint(cp)
	return cp, nil
}

// VerifyChain verifies cryptographic chain integrity, detecting modifications, deletions, and reordering.
func (e *IntegrityEngine) VerifyChain(
	ctx context.Context,
	events []ChainedEvent,
	checkpoint *AuditCheckpoint,
) (*VerificationResult, error) {
	result := &VerificationResult{
		Valid:        true,
		CheckedCount: len(events),
		Alerts:       make([]*IntegrityAlert, 0),
		Message:      "Audit integrity certified. No tampering or alteration detected.",
	}

	// 1. Verify Checkpoint Signature
	if checkpoint != nil {
		if !e.VerifyCheckpointSignature(checkpoint) {
			alert := &IntegrityAlert{
				ID:           uuid.New(),
				TenantID:     checkpoint.TenantID,
				CheckpointID: &checkpoint.ID,
				FailureType:  FailureSignatureInvalid,
				Details:      "Checkpoint signature verification failed; checkpoint may be forged or tampered",
				Status:       "OPEN",
				DetectedAt:   time.Now().UTC(),
			}
			result.Valid = false
			result.Alerts = append(result.Alerts, alert)
			result.Message = "CRITICAL AUDIT TAMPER ALERT: Invalid checkpoint signature"
			return result, ErrInvalidSignature
		}
	}

	if len(events) == 0 {
		return result, nil
	}

	var hashes []string

	for i := 0; i < len(events); i++ {
		evt := events[i]
		hashes = append(hashes, evt.CurrentHash)

		// 2. Check Sequence Continuity
		if i > 0 {
			expectedSeq := events[i-1].SequenceNum + 1
			if evt.SequenceNum != expectedSeq {
				alert := &IntegrityAlert{
					ID:           uuid.New(),
					TenantID:     evt.TenantID,
					FailureType:  FailureChainBroken,
					RecordID:     &evt.ID,
					SequenceNum:  evt.SequenceNum,
					Details:      fmt.Sprintf("Sequence break: expected seq %d but found %d (record deletion/omission detected)", expectedSeq, evt.SequenceNum),
					Status:       "OPEN",
					DetectedAt:   time.Now().UTC(),
				}
				result.Valid = false
				result.Alerts = append(result.Alerts, alert)
				result.Message = "CRITICAL AUDIT TAMPER ALERT: Audit record sequence broken"
				return result, ErrSequenceBreak
			}

			// 3. Check Previous Hash Link Continuity
			if evt.PreviousHash != events[i-1].CurrentHash {
				alert := &IntegrityAlert{
					ID:           uuid.New(),
					TenantID:     evt.TenantID,
					FailureType:  FailureChainBroken,
					RecordID:     &evt.ID,
					SequenceNum:  evt.SequenceNum,
					ExpectedHash: events[i-1].CurrentHash,
					ComputedHash: evt.PreviousHash,
					Details:      fmt.Sprintf("Hash link break at sequence %d: previous_hash does not match predecessor current_hash", evt.SequenceNum),
					Status:       "OPEN",
					DetectedAt:   time.Now().UTC(),
				}
				result.Valid = false
				result.Alerts = append(result.Alerts, alert)
				result.Message = "CRITICAL AUDIT TAMPER ALERT: Chain linkage broken"
				return result, ErrSequenceBreak
			}
		}

		// 4. Verify Record Cryptographic Hash (Detect In-Place Modification)
		computedHash := ComputeEventHash(evt.PreviousHash, evt)
		if computedHash != evt.CurrentHash {
			alert := &IntegrityAlert{
				ID:           uuid.New(),
				TenantID:     evt.TenantID,
				FailureType:  FailureHashMismatch,
				RecordID:     &evt.ID,
				SequenceNum:  evt.SequenceNum,
				ExpectedHash: evt.CurrentHash,
				ComputedHash: computedHash,
				Details:      fmt.Sprintf("Cryptographic hash mismatch at sequence %d: record contents were altered", evt.SequenceNum),
				Status:       "OPEN",
				DetectedAt:   time.Now().UTC(),
			}
			result.Valid = false
			result.Alerts = append(result.Alerts, alert)
			result.Message = "CRITICAL AUDIT TAMPER ALERT: Record modification detected"
			return result, ErrHashMismatch
		}
	}

	// 5. Verify Merkle Root if Checkpoint provided
	if checkpoint != nil {
		computedRoot := ComputeMerkleRoot(hashes)
		if computedRoot != checkpoint.MerkleRoot {
			alert := &IntegrityAlert{
				ID:           uuid.New(),
				TenantID:     checkpoint.TenantID,
				CheckpointID: &checkpoint.ID,
				FailureType:  FailureMerkleMismatch,
				ExpectedHash: checkpoint.MerkleRoot,
				ComputedHash: computedRoot,
				Details:      "Merkle root mismatch against signed checkpoint snapshot",
				Status:       "OPEN",
				DetectedAt:   time.Now().UTC(),
			}
			result.Valid = false
			result.Alerts = append(result.Alerts, alert)
			result.Message = "CRITICAL AUDIT TAMPER ALERT: Checkpoint Merkle root mismatch"
			return result, ErrMerkleRootMismatch
		}
	}

	return result, nil
}
