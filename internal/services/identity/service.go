package identity

import (
	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

// Service manages identity key creation and access using a backing store.
type Service struct {
	store domain.IdentityStore
}

// New returns an identity service backed by the given store.
func New(s domain.IdentityStore) *Service { return &Service{store: s} }

// Generate creates a new identity, saves it encrypted with passphrase, and returns the identity
// plus a short fingerprint of the X25519 public key.
func (s *Service) Generate(passphrase string) (domain.Identity, string, error) {
	xpriv, xpub, err := crypto.GenerateX25519()
	if err != nil {
		return domain.Identity{}, "", err
	}
	edpriv, edpub, err := crypto.GenerateEd25519()
	if err != nil {
		return domain.Identity{}, "", err
	}
	id := domain.Identity{XPub: xpub, XPriv: xpriv, EdPub: edpub, EdPriv: edpriv}
	if err := s.store.SaveIdentity(passphrase, id); err != nil {
		return domain.Identity{}, "", err
	}
	return id, crypto.Fingerprint(id.XPub.Slice()), nil
}

// LoadIdentity decrypts and returns the local identity.
func (s *Service) LoadIdentity(passphrase string) (domain.Identity, error) {
	return s.store.LoadIdentity(passphrase)
}

// Fingerprint returns a short fingerprint of the local X25519 public key.
func (s *Service) Fingerprint(passphrase string) (string, error) {
	id, err := s.store.LoadIdentity(passphrase)
	if err != nil {
		return "", err
	}
	return crypto.Fingerprint(id.XPub.Slice()), nil
}
