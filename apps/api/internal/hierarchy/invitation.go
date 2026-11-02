package hierarchy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
)

// GenerateInvitationToken generates a 256-bit cryptographically secure random token
// and returns both the raw token (to be sent to the recipient) and its SHA-256 hash (to be stored).
func GenerateInvitationToken() (string, string, error) {
	b := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	rawToken := hex.EncodeToString(b)
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])
	return rawToken, tokenHash, nil
}

// HashInvitationToken computes the SHA-256 digest of a raw token.
func HashInvitationToken(rawToken string) string {
	if rawToken == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}

// InvitationRepository defines storage for organization invitations.
type InvitationRepository interface {
	SaveInvitation(invite *OrganizationInvitation) error
	GetInvitation(id uuid.UUID) (*OrganizationInvitation, error)
	GetInvitationByTokenHash(tokenHash string) (*OrganizationInvitation, error)
	UpdateInvitation(invite *OrganizationInvitation) error
	ListInvitations(orgID uuid.UUID) ([]*OrganizationInvitation, error)
}

var (
	ErrInvitationReplay = errors.New("invitation token has already been consumed")
)
