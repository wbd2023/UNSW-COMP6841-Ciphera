package prekey

import (
	"errors"
	"fmt"
	"time"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

// Service manages prekey pairs and builds the public bundle.
//
// In this protocol, a client advertises a signed prekey (SPK) and a batch of
// one-time prekeys (OPKs). Peers use these to complete X3DH and start a
// Double Ratchet conversation.
type Service struct {
	idStore     domain.IdentityStore
	prekeyStore domain.PrekeyStore
	bundleStore domain.PrekeyBundleStore
}

var (
	// ErrNoSignedPrekey indicates there is no signed prekey available to build a bundle.
	ErrNoSignedPrekey = errors.New("no signed prekey available")
)

// New constructs a prekey service wired to the given stores.
func New(
	idStore domain.IdentityStore,
	prekeyStore domain.PrekeyStore,
	bundleStore domain.PrekeyBundleStore,
) *Service {
	return &Service{
		idStore:     idStore,
		prekeyStore: prekeyStore,
		bundleStore: bundleStore,
	}
}

// GenerateAndStorePrekeys creates a new signed prekey and n one-time prekeys,
// persists them, and marks the new signed prekey as current.
//
// It returns the public SPK and the list of public OPKs for convenience so
// callers can surface or log what was generated without reloading from storage.
func (s *Service) GenerateAndStorePrekeys(
	passphrase string,
	n int,
) (
	domain.X25519Public,
	[]domain.X25519Public,
	error,
) {
	// Load our identity; needed to sign the SPK with Ed25519.
	id, err := s.idStore.LoadIdentity(passphrase)
	if err != nil {
		return domain.X25519Public{}, nil, err
	}

	// Signed prekey: generate, sign with identity signing key, save, mark current.
	spkPriv, spkPub, err := crypto.GenerateX25519()
	if err != nil {
		return domain.X25519Public{}, nil, err
	}
	spkID := fmt.Sprintf("spk-%d", time.Now().Unix())
	sig := crypto.SignEd25519(id.EdPriv, spkPub[:])
	if err := s.prekeyStore.SaveSignedPrekey(spkID, spkPriv, spkPub, sig); err != nil {
		return domain.X25519Public{}, nil, err
	}
	if err := s.prekeyStore.SetCurrentSignedPrekeyID(spkID); err != nil {
		return domain.X25519Public{}, nil, err
	}

	// One-time prekeys: generate n pairs and persist them in a batch.
	pairs := make([]domain.OneTimePair, 0, n)
	publics := make([]domain.X25519Public, 0, n)
	for i := range n {
		priv, pub, err := crypto.GenerateX25519()
		if err != nil {
			return domain.X25519Public{}, nil, err
		}
		id := fmt.Sprintf("opk-%d-%d", time.Now().Unix(), i)
		pairs = append(pairs, domain.OneTimePair{ID: id, Priv: priv, Pub: pub})
		publics = append(publics, pub)
	}
	if err := s.prekeyStore.SaveOneTimePrekeys(pairs); err != nil {
		return domain.X25519Public{}, nil, err
	}

	return spkPub, publics, nil
}

// LoadPrekeyBundle assembles the public bundle from the current SPK and the
// current set of OPKs, caches it in the bundle store, and returns it.
//
// The bundle includes:
//   - Identity keys (X25519 and Ed25519).
//   - Current SPK and its signature over the SPK.
//   - Zero or more OPK publics.
func (s *Service) LoadPrekeyBundle(
	passphrase string,
	username string,
) (domain.PrekeyBundle, error) {
	id, err := s.idStore.LoadIdentity(passphrase)
	if err != nil {
		return domain.PrekeyBundle{}, err
	}

	spkID, ok, err := s.prekeyStore.CurrentSignedPrekeyID()
	if err != nil {
		return domain.PrekeyBundle{}, err
	}
	if !ok {
		return domain.PrekeyBundle{}, ErrNoSignedPrekey
	}

	_, spkPub, sig, found, err := s.prekeyStore.LoadSignedPrekey(spkID)
	if err != nil {
		return domain.PrekeyBundle{}, err
	}
	if !found {
		return domain.PrekeyBundle{}, ErrNoSignedPrekey
	}

	oneTime, err := s.prekeyStore.ListOneTimePrekeyPublics()
	if err != nil {
		return domain.PrekeyBundle{}, err
	}

	bundle := domain.PrekeyBundle{
		Username:        username,
		IdentityKey:     id.XPub,
		SignKey:         id.EdPub,
		SPKID:           spkID,
		SignedPrekey:    spkPub,
		SignedPrekeySig: sig,
		OneTime:         oneTime,
	}
	if err := s.bundleStore.SavePrekeyBundle(bundle); err != nil {
		return domain.PrekeyBundle{}, err
	}
	return bundle, nil
}

// Compile-time assertion that Service implements domain.PrekeyService.
var _ domain.PrekeyService = (*Service)(nil)
