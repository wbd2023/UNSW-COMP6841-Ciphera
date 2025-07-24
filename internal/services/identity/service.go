package identity

import (
	"ciphera/internal/crypto"
	"ciphera/internal/domain"
	"ciphera/internal/store"
)

type Service struct {
	store store.IdentityStore
}

func New(s store.IdentityStore) *Service {
	return &Service{store: s}
}

var _ domain.IdentityService = (*Service)(nil)

func (s *Service) Generate(passphrase string) (domain.Identity, string, error) {
	raw, err := crypto.NewX25519Identity()
	if err != nil {
		return domain.Identity{}, "", err
	}
	id := domain.Identity{Private: raw.Private, Public: raw.Public}
	if err := s.store.SaveIdentity(id, passphrase); err != nil {
		return domain.Identity{}, "", err
	}
	fp := crypto.Fingerprint(id.Public[:])
	return id, fp, nil
}

func (s *Service) Fingerprint(passphrase string) (string, error) {
	id, err := s.store.LoadIdentity(passphrase)
	if err != nil {
		return "", err
	}
	return crypto.Fingerprint(id.Public[:]), nil
}
