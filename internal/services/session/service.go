package session

import (
	"time"

	"ciphera/internal/domain"
	"ciphera/internal/protocol/x3dh"
)

// Service performs X3DH initiation and persists sessions.
type Service struct {
	ids   domain.IdentityStore
	pks   domain.PrekeyBundleStore
	relay domain.RelayClient
	store domain.SessionStore
}

// New constructs a Session Service with the given stores and relay client.
func New(
	ids domain.IdentityStore,
	pks domain.PrekeyBundleStore,
	relay domain.RelayClient,
	store domain.SessionStore,
) *Service {
	return &Service{ids: ids, pks: pks, relay: relay, store: store}
}

// Initiate runs X3DH against the peer's bundle and stores the resulting session.
func (s *Service) Initiate(passphrase, peer string) (domain.Session, error) {
	id, err := s.ids.LoadIdentity(passphrase)
	if err != nil {
		return domain.Session{}, err
	}

	bundle, err := s.relay.FetchPrekeyBundle(peer)
	if err != nil {
		return domain.Session{}, err
	}

	rk, spkID, opkID, ephPub, err := x3dh.InitiatorRoot(id, bundle)
	if err != nil {
		return domain.Session{}, err
	}

	sess := domain.Session{
		Peer:        peer,
		RootKey:     rk,
		PeerSPK:     bundle.SignedPrekey,
		PeerIK:      bundle.IdentityKey,
		CreatedUTC:  time.Now().Unix(),
		SPKID:       spkID,
		OPKID:       opkID,
		InitiatorEK: ephPub,
	}

	if err := s.store.SaveSession(peer, sess); err != nil {
		return domain.Session{}, err
	}
	return sess, nil
}

// Get retrieves a stored session for the given peer.
func (s *Service) Get(peer string) (domain.Session, bool, error) {
	return s.store.LoadSession(peer)
}

var _ domain.SessionService = (*Service)(nil)
