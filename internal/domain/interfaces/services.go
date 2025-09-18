package interfaces

import (
	"context"

	domaintypes "ciphera/internal/domain/types"
)

// IdentityService creates, retrieves, and inspects your identity keys.
type IdentityService interface {
	GenerateIdentity(passphrase string) (
		domaintypes.Identity,
		domaintypes.Fingerprint,
		error,
	)
	LoadIdentity(passphrase string) (domaintypes.Identity, error)
	FingerprintIdentity(passphrase string) (domaintypes.Fingerprint, error)
}

// PreKeyService generates and assembles your pre-key bundles.
type PreKeyService interface {
	GenerateAndStorePreKeys(passphrase string, count int) (
		domaintypes.X25519Public,
		[]domaintypes.X25519Public,
		error,
	)
	LoadPreKeyBundle(
		passphrase string,
		username domaintypes.Username,
		serverURL string,
	) (
		domaintypes.PreKeyBundle,
		error,
	)
}

// SessionService establishes or retrieves an X3DH session.
type SessionService interface {
	InitiateSession(
		ctx context.Context,
		passphrase string,
		peer domaintypes.Username,
	) (domaintypes.Session, error)
	GetSession(peer domaintypes.Username) (domaintypes.Session, bool, error)
}

// MessageService encrypts, sends, fetches and decrypts messages.
type MessageService interface {
	SendMessage(
		ctx context.Context,
		passphrase string,
		from domaintypes.Username,
		to domaintypes.Username,
		plaintext []byte,
	) error
	ReceiveMessage(
		ctx context.Context,
		passphrase string,
		me domaintypes.Username,
		limit int,
	) ([]domaintypes.DecryptedMessage, error)
}
