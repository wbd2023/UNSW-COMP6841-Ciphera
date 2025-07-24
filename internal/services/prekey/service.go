package prekey

import (
	"crypto/ed25519"
	"crypto/rand"

	"golang.org/x/crypto/curve25519"

	"ciphera/internal/domain"
	"ciphera/internal/store"
)

type Service struct {
	ids     domain.IdentityService
	idStore store.IdentityStore
	pkStore store.PrekeyStore
}

func New(ids domain.IdentityService, idStore store.IdentityStore, pkStore store.PrekeyStore) *Service {
	return &Service{
		ids:     ids,
		idStore: idStore,
		pkStore: pkStore,
	}
}

var _ domain.PrekeyService = (*Service)(nil)

func (s *Service) GenerateAndStore(passphrase string, nOneTime uint16) (domain.SignedPreKey, []domain.OneTimePreKey, error) {
	// load identity to sign the SPK
	id, err := s.idStore.LoadIdentity(passphrase)
	if err != nil {
		return domain.SignedPreKey{}, nil, err
	}

	// signed prekey
	var spkPriv [32]byte
	if _, err := rand.Read(spkPriv[:]); err != nil {
		return domain.SignedPreKey{}, nil, err
	}
	spkPriv[0] &= 248
	spkPriv[31] &= 127
	spkPriv[31] |= 64

	var spkPub [32]byte
	curve25519.ScalarBaseMult(&spkPub, &spkPriv)

	sig := ed25519.Sign(ed25519.PrivateKey(id.EdPriv.Slice()), spkPub[:])

	spk := domain.SignedPreKey{
		ID:  1,
		Key: domain.MustX25519Public(spkPub[:]),
		Sig: sig,
	}

	// one-time prekeys
	otks := make([]domain.OneTimePreKey, 0, nOneTime)
	for i := uint16(0); i < nOneTime; i++ {
		var priv [32]byte
		if _, err := rand.Read(priv[:]); err != nil {
			return domain.SignedPreKey{}, nil, err
		}
		priv[0] &= 248
		priv[31] &= 127
		priv[31] |= 64
		var pub [32]byte
		curve25519.ScalarBaseMult(&pub, &priv)

		otks = append(otks, domain.OneTimePreKey{
			ID:  uint32(i + 1),
			Key: domain.MustX25519Public(pub[:]),
		})
	}

	if err := s.pkStore.SavePrekeys(spk, otks); err != nil {
		return domain.SignedPreKey{}, nil, err
	}
	return spk, otks, nil
}

func (s *Service) LoadBundle(passphrase, username string) (domain.PrekeyBundle, error) {
	id, err := s.idStore.LoadIdentity(passphrase)
	if err != nil {
		return domain.PrekeyBundle{}, err
	}
	spk, otks, err := s.pkStore.LoadPrekeys()
	if err != nil {
		return domain.PrekeyBundle{}, err
	}
	return domain.PrekeyBundle{
		Username:      username,
		IdentityXPub:  id.XPub,
		IdentityEdPub: id.EdPub,
		SignedPreKey:  spk,
		OneTimeKeys:   otks,
	}, nil
}
