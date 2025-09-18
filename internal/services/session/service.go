package session

import (
	"context"
	"time"

	"ciphera/internal/domain"
	"ciphera/internal/protocol/x3dh"
)

// Service performs X3DH initiation and persists sessions.
//
// A session represents the shared root key and associated metadata needed
// for establishing a Double Ratchet conversation with a peer.
// This service handles:
//   - Retrieving our own identity keys.
//   - Fetching the peer's prekey bundle from the relay.
//   - Running the X3DH key agreement as the initiator.
//   - Persisting the resulting session for later message encryption.
type Service struct {
	idStore      domain.IdentityStore
	prekeyStore  domain.PreKeyBundleStore
	sessionStore domain.SessionStore
	relayClient  domain.RelayClient
}

// New constructs a Session Service with the given stores and relay client.
func New(
	idStore domain.IdentityStore,
	prekeyStore domain.PreKeyBundleStore,
	sessionStore domain.SessionStore,
	relayClient domain.RelayClient,
) *Service {
	return &Service{
		idStore:      idStore,
		prekeyStore:  prekeyStore,
		sessionStore: sessionStore,
		relayClient:  relayClient,
	}
}

// Initiate runs X3DH against the peer's prekey bundle and stores the resulting session.
//
// Steps:
//  1. Load our own identity key pair from the identity store.
//  2. Fetch the peer's pre-key bundle from the relay (contains identity key,
//     Signed Pre-Key, and optionally a One-Time Pre-Key).
//  3. Run X3DH as the initiator to derive the root key and record which pre-keys
//     were used.
//  4. Create a Session record and persist it to the session store for future
//     message exchanges.
func (s *Service) InitiateSession(
	ctx context.Context,
	passphrase string,
	peer domain.Username,
) (domain.Session, error) {
	// Load our identity from secure storage.
	id, err := s.idStore.LoadIdentity(passphrase)
	if err != nil {
		return domain.Session{}, err
	}

	// Get the peer's current prekey bundle from the relay.
	bundle, err := s.relayClient.FetchPreKeyBundle(ctx, peer)
	if err != nil {
		return domain.Session{}, err
	}

	// Perform X3DH as the initiator to derive the shared root key and identify
	// which SPK/OPK were used.
	rootKey,
		signedPreKeyIdentifier,
		oneTimePreKeyIdentifier,
		initiatorEphemeralPublicKey,
		err := x3dh.InitiatorRoot(id, bundle)
	if err != nil {
		return domain.Session{}, err
	}

	// Build the session record.
	session := domain.Session{
		PeerUsername:          peer,
		RootKey:               rootKey,
		PeerSignedPreKey:      bundle.SignedPreKey,
		PeerIdentityKey:       bundle.IdentityKey,
		CreatedUTC:            time.Now().Unix(),
		SignedPreKeyID:        signedPreKeyIdentifier,
		OneTimePreKeyID:       oneTimePreKeyIdentifier,
		InitiatorEphemeralKey: initiatorEphemeralPublicKey,
	}

	// Persist the session for later retrieval.
	if err := s.sessionStore.SaveSession(peer, session); err != nil {
		return domain.Session{}, err
	}
	return session, nil
}

// Get retrieves a stored session for the given peer from the session store.
func (s *Service) GetSession(peer domain.Username) (domain.Session, bool, error) {
	return s.sessionStore.LoadSession(peer)
}

// Compile-time assertion that Service implements domain.SessionService.
var _ domain.SessionService = (*Service)(nil)
