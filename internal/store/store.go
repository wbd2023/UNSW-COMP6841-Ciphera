package store

import "ciphera/internal/domain"

type IdentityStore interface {
	SaveIdentity(id domain.Identity, passphrase string) error
	LoadIdentity(passphrase string) (domain.Identity, error)
}

type PrekeyStore interface {
	SavePrekeys(spk domain.SignedPreKey, otks []domain.OneTimePreKey) error
	LoadPrekeys() (domain.SignedPreKey, []domain.OneTimePreKey, error)
}
