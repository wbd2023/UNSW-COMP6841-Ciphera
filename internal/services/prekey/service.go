package prekey

import (
	"fmt"
	"time"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

// Service manages prekey pairs and builds the public bundle.
type Service struct {
	ids domain.IdentityStore
	ps  domain.PrekeyStore
	bs  domain.PrekeyBundleStore
}

func New(ids domain.IdentityStore, ps domain.PrekeyStore, bs domain.PrekeyBundleStore) *Service {
	return &Service{ids: ids, ps: ps, bs: bs}
}

// GenerateAndStorePrekeys creates a signed-prekey and n one-time prekeys.
//
// It also marks the new signed-prekey as current.
func (s *Service) GenerateAndStorePrekeys(
	passphrase string,
	n int,
) (
	domain.X25519Public,
	[]domain.X25519Public,
	error,
) {
	id, err := s.ids.LoadIdentity(passphrase)
	if err != nil {
		return domain.X25519Public{}, nil, err
	}

	// Signed prekey
	spkPriv, spkPub, err := crypto.GenerateX25519()
	if err != nil {
		return domain.X25519Public{}, nil, err
	}
	spkID := fmt.Sprintf("spk-%d", time.Now().Unix())
	sig := crypto.SignEd25519(id.EdPriv, spkPub[:])
	if err := s.ps.SaveSignedPrekey(spkID, spkPriv, spkPub, sig); err != nil {
		return domain.X25519Public{}, nil, err
	}
	if err := s.ps.SetCurrentSignedPrekeyID(spkID); err != nil {
		return domain.X25519Public{}, nil, err
	}

	// One-time prekeys
	pairs := make([]domain.OneTimePair, 0, n)
	publics := make([]domain.X25519Public, 0, n)
	for i := 0; i < n; i++ {
		priv, pub, err := crypto.GenerateX25519()
		if err != nil {
			return domain.X25519Public{}, nil, err
		}
		id := fmt.Sprintf("opk-%d-%d", time.Now().Unix(), i)
		pairs = append(pairs, domain.OneTimePair{ID: id, Priv: priv, Pub: pub})
		publics = append(publics, pub)
	}
	if err := s.ps.SaveOneTimePrekeys(pairs); err != nil {
		return domain.X25519Public{}, nil, err
	}
	return spkPub, publics, nil
}

// LoadPrekeyBundle builds the public bundle from the current signed-prekey and OPK list, caches it,
// and returns it.
func (s *Service) LoadPrekeyBundle(passphrase, username string) (domain.PrekeyBundle, error) {
	id, err := s.ids.LoadIdentity(passphrase)
	if err != nil {
		return domain.PrekeyBundle{}, err
	}

	spkID, ok, err := s.ps.CurrentSignedPrekeyID()
	if err != nil {
		return domain.PrekeyBundle{}, err
	}
	if !ok {
		return domain.PrekeyBundle{}, errNoSignedPrekey
	}
	_, spkPub, sig, found, err := s.ps.LoadSignedPrekey(spkID)
	if err != nil {
		return domain.PrekeyBundle{}, err
	}
	if !found {
		return domain.PrekeyBundle{}, errNoSignedPrekey
	}

	oneTime, err := s.ps.ListOneTimePrekeyPublics()
	if err != nil {
		return domain.PrekeyBundle{}, err
	}

	b := domain.PrekeyBundle{
		Username:        username,
		IdentityKey:     id.XPub,
		SignKey:         id.EdPub,
		SPKID:           spkID,
		SignedPrekey:    spkPub,
		SignedPrekeySig: sig,
		OneTime:         oneTime,
	}
	if err := s.bs.SavePrekeyBundle(b); err != nil {
		return domain.PrekeyBundle{}, err
	}
	return b, nil
}

var errNoSignedPrekey = errString("no signed prekey available")

type errString string

func (e errString) Error() string { return string(e) }
