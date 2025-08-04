package app

import "ciphera/internal/domain"

// IdentityAPI is the minimal surface the CLI needs for identity tasks.
type IdentityAPI interface {
	Generate(passphrase string) (domain.Identity, string, error)
	LoadIdentity(passphrase string) (domain.Identity, error)
	Fingerprint(passphrase string) (string, error)
}

// PrekeyAPI is the minimal surface the CLI needs for prekey tasks.
type PrekeyAPI interface {
	GenerateAndStore(passphrase string, n int) (domain.X25519Public, []domain.X25519Public, error)
	LoadBundle(passphrase, username string) (domain.PrekeyBundle, error)
}

// App gathers the services the CLI uses.
type App struct {
	IDs      IdentityAPI
	Prekeys  PrekeyAPI
	Relay    domain.RelayClient
	Sessions domain.SessionService
	Messages domain.MessageService
}
