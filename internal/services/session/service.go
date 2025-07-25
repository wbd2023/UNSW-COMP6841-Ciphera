package session

import (
	"crypto/rand"

	"ciphera/internal/domain"
	"ciphera/internal/protocol/x3dh"
	"ciphera/internal/store"
)

type Service struct {
	ids     domain.IdentityService
	idStore store.IdentityStore
	relay   domain.RelayClient
	store   domain.SessionStore
}

func New(ids domain.IdentityService, idStore store.IdentityStore, relay domain.RelayClient, sessStore domain.SessionStore) *Service {
	return &Service{
		ids:     ids,
		idStore: idStore,
		relay:   relay,
		store:   sessStore,
	}
}

var _ domain.SessionService = (*Service)(nil)

// StartInitiator creates a new session as the initiator using X3DH.
func (s *Service) StartInitiator(passphrase, peerUsername string) (domain.Session, error) {
	ourID, err := s.idStore.LoadIdentity(passphrase)
	if err != nil {
		return domain.Session{}, err
	}

	bundle, err := s.relay.FetchPrekey(peerUsername)
	if err != nil {
		return domain.Session{}, err
	}

	if !x3dh.VerifySPK(bundle.IdentityEdPub, bundle.SignedPreKey.Key, bundle.SignedPreKey.Sig) {
		return domain.Session{}, ErrBadSPKSignature
	}

	var ephRaw [32]byte
	if _, err := rand.Read(ephRaw[:]); err != nil {
		return domain.Session{}, err
	}
	ephRaw[0] &= 248
	ephRaw[31] &= 127
	ephRaw[31] |= 64

	var ephPriv domain.X25519Private
	copy(ephPriv[:], ephRaw[:])

	var opk *domain.X25519Public
	if len(bundle.OneTimeKeys) > 0 {
		opk = &bundle.OneTimeKeys[0].Key
	}

	root, err := x3dh.InitiatorRootKey(
		ourID.XPriv,
		ephPriv,
		bundle.IdentityXPub,
		bundle.SignedPreKey.Key,
		opk,
	)
	if err != nil {
		return domain.Session{}, err
	}

	sess := domain.Session{
		Peer:           peerUsername,
		RootKey:        root,
		OurIdentity:    ourID.XPub,
		PeerIdentity:   bundle.IdentityXPub,
		PeerEd25519:    bundle.IdentityEdPub,
		PeerSPK:        bundle.SignedPreKey.Key,
		UsedOneTimeKey: opk != nil,
	}
	if err := s.store.SaveSession(sess); err != nil {
		return domain.Session{}, err
	}
	return sess, nil
}

func (s *Service) Get(peer string) (domain.Session, bool, error) {
	return s.store.LoadSession(peer)
}

var ErrBadSPKSignature = errBadSPKSignature{}

type errBadSPKSignature struct{}

func (errBadSPKSignature) Error() string { return "bad signed prekey signature" }
