package prekey

import (
	"errors"
	"fmt"
	"time"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

// Service manages pre-key pairs and builds the public bundle.
//
// In this protocol, a client advertises a Signed Pre-Key and a batch of
// One-Time Pre-Keys. Peers use these to complete X3DH and start a
// Double Ratchet conversation.
type Service struct {
	idStore     domain.IdentityStore
	prekeyStore domain.PreKeyStore
	bundleStore domain.PreKeyBundleStore
}

var (
	// ErrNoSignedPreKey indicates there is no signed pre-key available to build a bundle.
	ErrNoSignedPreKey = errors.New("no signed prekey available")
)

// New constructs a prekey service wired to the given stores.
func New(
	idStore domain.IdentityStore,
	prekeyStore domain.PreKeyStore,
	bundleStore domain.PreKeyBundleStore,
) *Service {
	return &Service{
		idStore:     idStore,
		prekeyStore: prekeyStore,
		bundleStore: bundleStore,
	}
}

// GenerateAndStorePreKeys creates a new Signed Pre-Key and count One-Time Pre-Keys,
// persists them, and marks the new Signed Pre-Key as current.
//
// It returns the public SPK and the list of public OPKs for convenience so
// callers can surface or log what was generated without reloading from storage.
func (s *Service) GenerateAndStorePreKeys(
	passphrase string,
	count int,
) (
	domain.X25519Public,
	[]domain.X25519Public,
	error,
) {
	// Load our identity; needed to sign the Signed Pre-Key with Ed25519.
	id, err := s.idStore.LoadIdentity(passphrase)
	if err != nil {
		return domain.X25519Public{}, nil, err
	}

	// Signed Pre-Key: generate, sign with identity signing key, save, mark current.
	signedPreKeyPrivateKey, signedPreKeyPublicKey, err := crypto.GenerateX25519()
	if err != nil {
		return domain.X25519Public{}, nil, err
	}
	signedPreKeyIdentifier := domain.SignedPreKeyID(fmt.Sprintf("spk-%d", time.Now().Unix()))
	signedPreKeySignature := crypto.SignEd25519(id.EdPriv, signedPreKeyPublicKey[:])
	if err := s.prekeyStore.SaveSignedPreKey(
		signedPreKeyIdentifier,
		signedPreKeyPrivateKey,
		signedPreKeyPublicKey,
		signedPreKeySignature,
	); err != nil {
		return domain.X25519Public{}, nil, err
	}
	if err := s.prekeyStore.SetCurrentSignedPreKeyID(signedPreKeyIdentifier); err != nil {
		return domain.X25519Public{}, nil, err
	}

	// One-Time Pre-Keys: generate count pairs and persist them in a batch.
	oneTimePreKeyPairs := make([]domain.OneTimePreKeyPair, 0, count)
	oneTimePreKeyPublicKeys := make([]domain.X25519Public, 0, count)
	for index := 0; index < count; index++ {
		oneTimePreKeyPrivateKey, oneTimePreKeyPublicKey, err := crypto.GenerateX25519()
		if err != nil {
			return domain.X25519Public{}, nil, err
		}
		oneTimePreKeyIdentifier := domain.OneTimePreKeyID(
			fmt.Sprintf("opk-%d-%d", time.Now().Unix(), index),
		)
		oneTimePreKeyPairs = append(
			oneTimePreKeyPairs,
			domain.OneTimePreKeyPair{
				ID:   oneTimePreKeyIdentifier,
				Priv: oneTimePreKeyPrivateKey,
				Pub:  oneTimePreKeyPublicKey,
			},
		)
		oneTimePreKeyPublicKeys = append(oneTimePreKeyPublicKeys, oneTimePreKeyPublicKey)
	}
	if err := s.prekeyStore.SaveOneTimePreKeys(oneTimePreKeyPairs); err != nil {
		return domain.X25519Public{}, nil, err
	}

	return signedPreKeyPublicKey, oneTimePreKeyPublicKeys, nil
}

// LoadPreKeyBundle assembles the public bundle from the current SPK and the
// current set of OPKs, caches it in the bundle store, and returns it.
//
// The bundle includes:
//   - Identity keys (X25519 and Ed25519).
//   - Current SPK and its signature over the SPK.
//   - Zero or more OPK publics.
func (s *Service) LoadPreKeyBundle(
	passphrase string,
	username domain.Username,
) (domain.PreKeyBundle, error) {
	id, err := s.idStore.LoadIdentity(passphrase)
	if err != nil {
		return domain.PreKeyBundle{}, err
	}

	signedPreKeyIdentifier, ok, err := s.prekeyStore.CurrentSignedPreKeyID()
	if err != nil {
		return domain.PreKeyBundle{}, err
	}
	if !ok {
		return domain.PreKeyBundle{}, ErrNoSignedPreKey
	}

	_, signedPreKeyPublicKey, signedPreKeySignature, found, err := s.prekeyStore.LoadSignedPreKey(
		signedPreKeyIdentifier,
	)
	if err != nil {
		return domain.PreKeyBundle{}, err
	}
	if !found {
		return domain.PreKeyBundle{}, ErrNoSignedPreKey
	}

	oneTimePreKeys, err := s.prekeyStore.ListOneTimePreKeyPublics()
	if err != nil {
		return domain.PreKeyBundle{}, err
	}

	bundle := domain.PreKeyBundle{
		Username:              username,
		IdentityKey:           id.XPub,
		SigningKey:            id.EdPub,
		SignedPreKeyID:        signedPreKeyIdentifier,
		SignedPreKey:          signedPreKeyPublicKey,
		SignedPreKeySignature: signedPreKeySignature,
		OneTimePreKeys:        oneTimePreKeys,
	}
	if err := s.bundleStore.SavePreKeyBundle(bundle); err != nil {
		return domain.PreKeyBundle{}, err
	}
	return bundle, nil
}

// Compile-time assertion that Service implements domain.PrekeyService.
var _ domain.PreKeyService = (*Service)(nil)
