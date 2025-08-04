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

func New(ids domain.IdentityStore, pks domain.PrekeyBundleStore, relay domain.RelayClient, store domain.SessionStore) *Service {
	return &Service{ids: ids, pks: pks, relay: relay, store: store}
}

// StartInitiator runs X3DH against the peer's bundle and stores a session.
// Also records initiator's ephemeral and SPK/OPK IDs for a matching PrekeyMessage in first message.
func (s *Service) StartInitiator(passphrase, peer string) (domain.Session, error) {
	id, err := s.ids.LoadIdentity(passphrase)
	if err != nil {
		return domain.Session{}, err
	}
	bundle, err := s.relay.FetchPrekey(peer)
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
	if err := s.store.Save(sess); err != nil {
		return domain.Session{}, err
	}
	return sess, nil
}

func (s *Service) Get(peer string) (domain.Session, bool, error) {
	return s.store.Get(peer)
}

var _ domain.SessionService = (*Service)(nil)
