package identity

import (
	"fmt"
	"unicode"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

const (
	// minPassphraseLength defines the minimum number of characters required for a passphrase.
	minPassphraseLength = 12
)

var (
	// ErrWeakPassphrase is returned when the passphrase fails the strength policy.
	ErrWeakPassphrase = fmt.Errorf(
		"passphrase is too weak (must be at least %d characters and include upper, lower, "+
			"number, and symbol)",
		minPassphraseLength,
	)
)

// Service manages identity key creation and access using a backing store.
//
// The identity contains:
//   - X25519 key pair for Diffie-Hellman (X3DH and Double Ratchet).
//   - Ed25519 key pair for signing (for example, signing the Signed Pre-Key).
type Service struct {
	store domain.IdentityStore
}

// New returns an identity service backed by the given store.
func New(s domain.IdentityStore) *Service { return &Service{store: s} }

// GenerateIdentity creates a new identity, saves it encrypted with the passphrase,
// and returns the identity plus a short fingerprint of the X25519 public key.
func (s *Service) GenerateIdentity(
	passphrase string,
) (domain.Identity, domain.Fingerprint, error) {
	if !isSecurePassphrase(passphrase) {
		return domain.Identity{}, "", ErrWeakPassphrase
	}

	// Generate Diffie-Hellman keypair for X3DH.
	identityDiffieHellmanPrivateKey, identityDiffieHellmanPublicKey, err := crypto.GenerateX25519()
	if err != nil {
		return domain.Identity{}, "", err
	}
	// Generate signing keypair.
	identitySigningPrivateKey, identitySigningPublicKey, err := crypto.GenerateEd25519()
	if err != nil {
		return domain.Identity{}, "", err
	}

	id := domain.Identity{
		XPub:   identityDiffieHellmanPublicKey,
		XPriv:  identityDiffieHellmanPrivateKey,
		EdPub:  identitySigningPublicKey,
		EdPriv: identitySigningPrivateKey,
	}
	if err := s.store.SaveIdentity(passphrase, id); err != nil {
		return domain.Identity{}, "", err
	}
	return id, domain.Fingerprint(crypto.Fingerprint(id.XPub.Slice())), nil
}

// LoadIdentity decrypts and returns the local identity.
func (s *Service) LoadIdentity(passphrase string) (domain.Identity, error) {
	return s.store.LoadIdentity(passphrase)
}

// FingerprintIdentity returns a short fingerprint of the local X25519 public key.
func (s *Service) FingerprintIdentity(passphrase string) (domain.Fingerprint, error) {
	id, err := s.store.LoadIdentity(passphrase)
	if err != nil {
		return "", err
	}
	return domain.Fingerprint(crypto.Fingerprint(id.XPub.Slice())), nil
}

// isSecurePassphrase enforces a basic strength policy.
func isSecurePassphrase(passphrase string) bool {
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	if len(passphrase) < minPassphraseLength {
		return false
	}
	for _, r := range passphrase {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSymbol
}

// Compile-time assertion that Service implements domain.IdentityService.
var _ domain.IdentityService = (*Service)(nil)
