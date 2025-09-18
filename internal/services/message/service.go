package message

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ciphera/internal/domain"
	"ciphera/internal/protocol/ratchet"
	"ciphera/internal/protocol/x3dh"
)

// Service sends and receives messages over the relay using Double Ratchet.
//
// High-level flow:
//   - Send: if no conversation exists, include a PrekeyMessage so the receiver can
//     bootstrap a session, then encrypt with Double Ratchet and post via the relay.
//   - Receive: fetch envelopes, bootstrap a session if needed using the sender's
//     PrekeyMessage, decrypt in order, persist ratchet state, then ack processed
//     messages.
type Service struct {
	idStore        domain.IdentityStore
	prekeyStore    domain.PreKeyStore
	ratchetStore   domain.RatchetStore
	sessionService domain.SessionService
	relayClient    domain.RelayClient
}

var (
	// ErrNoSession indicates there is no stored session with the peer.
	ErrNoSession = errors.New("no session with peer; run Initiate first")
)

// New constructs a Message Service with the given stores and relay client.
func New(
	idStore domain.IdentityStore,
	prekeyStore domain.PreKeyStore,
	ratchetStore domain.RatchetStore,
	sessionService domain.SessionService,
	relayClient domain.RelayClient,
) *Service {
	return &Service{
		idStore:        idStore,
		prekeyStore:    prekeyStore,
		ratchetStore:   ratchetStore,
		sessionService: sessionService,
		relayClient:    relayClient,
	}
}

// Send encrypts and posts plaintext.
//
// If this is the first message to a peer (no stored conversation), a PrekeyMessage
// is attached so the receiver can establish a Double Ratchet session using X3DH.
// Subsequent messages omit PrekeyMessage and use the existing ratchet state.
func (s *Service) SendMessage(
	ctx context.Context,
	passphrase string,
	fromUsername domain.Username,
	toUsername domain.Username,
	plaintext []byte,
) error {
	session, hasSession, err := s.sessionService.GetSession(toUsername)
	if err != nil {
		return err
	}
	if !hasSession {
		return ErrNoSession
	}

	conversationID := domain.ConversationID(toUsername.String())
	conversation, found, err := s.ratchetStore.LoadConversation(conversationID)
	if err != nil {
		return err
	}

	var preKeyMessage *domain.PreKeyMessage
	if !found {
		// No existing conversation: we are the initiator.
		// Build a fresh Double Ratchet state and include a PrekeyMessage so the
		// receiver can derive the root key (X3DH) and initialise their side.
		//
		// PrekeyMessage fields:
		//   - InitiatorIK: our identity public key so the receiver can authenticate us.
		//   - Ephemeral: our X25519 ephemeral public used during X3DH.
		//   - SignedPreKeyID / OneTimePreKeyID: which pre-keys we target on the receiver.
		identity, err := s.idStore.LoadIdentity(passphrase)
		if err != nil {
			return err
		}
		ratchetState, err := ratchet.InitAsInitiator(
			session.RootKey,
			identity.XPriv,
			identity.XPub,
			session.PeerIdentityKey,
		)
		if err != nil {
			return err
		}
		conversation = domain.Conversation{Peer: conversationID, State: ratchetState}

		preKeyMessage = &domain.PreKeyMessage{
			InitiatorIdentityKey: identity.XPub,
			EphemeralKey:         session.InitiatorEphemeralKey,
			SignedPreKeyID:       session.SignedPreKeyID,
			OneTimePreKeyID:      session.OneTimePreKeyID,
		}
	}

	// Encrypt the payload using the current ratchet state.
	ratchetHeader, ciphertext, err := ratchet.Encrypt(&conversation.State, nil, plaintext)
	if err != nil {
		return err
	}

	// Persist updated ratchet state before sending to avoid message loss if we crash.
	if err := s.ratchetStore.SaveConversation(conversationID, conversation); err != nil {
		return err
	}

	envelope := domain.Envelope{
		From:      fromUsername,
		To:        toUsername,
		Header:    ratchetHeader,
		Cipher:    ciphertext,
		PreKey:    preKeyMessage, // present only for the first message of a conversation
		Timestamp: time.Now().Unix(),
	}
	return s.relayClient.SendMessage(ctx, envelope)
}

// Receive fetches pending messages and decrypts them.
//
// The method processes envelopes in order. For the first message from a peer,
// it expects a PrekeyMessage to bootstrap X3DH and initialise the Double Ratchet.
// If bootstrapping prerequisites are not met, processing stops and remaining
// envelopes are left queued.
//
// We track how many envelopes were processed successfully and ack only that
// count. This avoids acknowledging messages we did not handle (for example,
// if a mid-stream decrypt error occurs).
func (s *Service) ReceiveMessage(
	ctx context.Context,
	passphrase string,
	me domain.Username,
	limit int,
) ([]domain.DecryptedMessage, error) {
	envelopes, err := s.relayClient.FetchMessages(ctx, me, limit)
	if err != nil {
		return nil, err
	}
	decrypted := make([]domain.DecryptedMessage, 0, len(envelopes))
	processed := 0

	for index, envelope := range envelopes {
		conversationID := domain.ConversationID(envelope.From.String())
		conversation, found, err := s.ratchetStore.LoadConversation(conversationID)
		if err != nil {
			return decrypted, err
		}

		if !found {
			// First message from this peer: bootstrap using the PrekeyMessage.
			//
			// Steps:
			//   1) Validate prerequisites (Prekey present and DH header present).
			//   2) Load our identity.
			//   3) Resolve the sender's public from the header.
			//   4) Load our signed prekey by ID; optionally consume a one-time prekey.
			//   5) Derive the root key (X3DH) and initialise Double Ratchet as responder.
			//
			// If prerequisites are missing, break and leave remaining envelopes queued.
			if envelope.PreKey == nil || len(envelope.Header.DiffieHellmanPublicKey) != 32 {
				break // leave the rest queued
			}
			identity, err := s.idStore.LoadIdentity(passphrase)
			if err != nil {
				return decrypted, err
			}
			var senderRatchetPublicKey domain.X25519Public
			copy(senderRatchetPublicKey[:], envelope.Header.DiffieHellmanPublicKey)

			if envelope.PreKey.SignedPreKeyID == "" {
				return decrypted, fmt.Errorf("missing SignedPreKeyID in pre-key message")
			}
			signedPreKeyPrivateKey, _, _, signedPreKeyFound, err := s.prekeyStore.LoadSignedPreKey(
				envelope.PreKey.SignedPreKeyID,
			)
			if err != nil {
				return decrypted, err
			}
			if !signedPreKeyFound {
				return decrypted, fmt.Errorf("signed pre-key %q not found", envelope.PreKey.SignedPreKeyID)
			}

			var oneTimePreKeyPrivateKey *domain.X25519Private
			if envelope.PreKey.OneTimePreKeyID != "" {
				privateKey, _, oneTimePreKeyFound, err := s.prekeyStore.ConsumeOneTimePreKey(
					envelope.PreKey.OneTimePreKeyID,
				)
				if err != nil {
					return decrypted, err
				}
				if oneTimePreKeyFound {
					oneTimePreKeyPrivateKey = &privateKey
				}
			}

			rootKey, err := x3dh.ResponderRoot(
				identity,
				signedPreKeyPrivateKey,
				oneTimePreKeyPrivateKey,
				*envelope.PreKey,
			)
			if err != nil {
				return decrypted, fmt.Errorf("x3dh responder root: %w", err)
			}
			ratchetState, err := ratchet.InitAsResponder(
				rootKey,
				identity.XPriv,
				identity.XPub,
				senderRatchetPublicKey,
			)
			if err != nil {
				return decrypted, err
			}
			conversation = domain.Conversation{Peer: conversationID, State: ratchetState}
		}

		// Decrypt using the ratchet state and associated data.
		plaintext, err := ratchet.Decrypt(
			&conversation.State,
			envelope.AssociatedData,
			envelope.Header,
			envelope.Cipher,
		)
		if err != nil {
			return decrypted, fmt.Errorf("decrypt from %q failed: %w", envelope.From, err)
		}

		// Persist updated ratchet state after successful decrypt to advance chains.
		if err := s.ratchetStore.SaveConversation(conversationID, conversation); err != nil {
			return decrypted, fmt.Errorf("save conversation %q: %w", envelope.From, err)
		}

		decrypted = append(decrypted, domain.DecryptedMessage{
			From:      envelope.From,
			To:        envelope.To,
			Plaintext: plaintext,
			Timestamp: envelope.Timestamp,
		})
		processed = index + 1
	}

	// Ack only what we processed successfully. If zero, do nothing.
	if processed > 0 {
		if err := s.relayClient.AckMessages(ctx, me, processed); err != nil {
			return decrypted, fmt.Errorf("ack %d messages: %w", processed, err)
		}
	}
	return decrypted, nil
}

// Compile-time assertion that Service implements domain.MessageService.
var _ domain.MessageService = (*Service)(nil)
