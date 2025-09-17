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
	prekeyStore    domain.PrekeyStore
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
	prekeyStore domain.PrekeyStore,
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
	fromUsername string,
	toUsername string,
	plaintext []byte,
) error {
	sess, ok, err := s.sessionService.GetSession(toUsername)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoSession
	}

	conv, found, err := s.ratchetStore.LoadConversation(toUsername)
	if err != nil {
		return err
	}

	var prekey *domain.PrekeyMessage
	if !found {
		// No existing conversation: we are the initiator.
		// Build a fresh Double Ratchet state and include a PrekeyMessage so the
		// receiver can derive the root key (X3DH) and initialise their side.
		//
		// PrekeyMessage fields:
		//   - InitiatorIK: our identity public key so the receiver can authenticate us.
		//   - Ephemeral: our X25519 ephemeral public used during X3DH.
		//   - SPKID/OPKID: which signed/one-time prekey we target on the receiver.
		id, err := s.idStore.LoadIdentity(passphrase)
		if err != nil {
			return err
		}
		st, err := ratchet.InitAsInitiator(sess.RootKey, id.XPriv, id.XPub, sess.PeerIK)
		if err != nil {
			return err
		}
		conv = domain.Conversation{Peer: toUsername, State: st}

		prekey = &domain.PrekeyMessage{
			InitiatorIK: id.XPub,
			Ephemeral:   sess.InitiatorEK,
			SPKID:       sess.SPKID,
			OPKID:       sess.OPKID,
		}
	}

	// Encrypt the payload using the current ratchet state.
	header, ct, err := ratchet.Encrypt(&conv.State, nil, plaintext)
	if err != nil {
		return err
	}

	// Persist updated ratchet state before sending to avoid message loss if we crash.
	if err := s.ratchetStore.SaveConversation(toUsername, conv); err != nil {
		return err
	}

	env := domain.Envelope{
		From:      fromUsername,
		To:        toUsername,
		Header:    header,
		Cipher:    ct,
		Prekey:    prekey, // present only for the first message of a conversation
		Timestamp: time.Now().Unix(),
	}
	return s.relayClient.SendMessage(ctx, env)
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
	me string,
	limit int,
) ([]domain.DecryptedMessage, error) {
	envs, err := s.relayClient.FetchMessages(ctx, me, limit)
	if err != nil {
		return nil, err
	}
	out := make([]domain.DecryptedMessage, 0, len(envs))
	processed := 0

	for i, env := range envs {
		conv, found, err := s.ratchetStore.LoadConversation(env.From)
		if err != nil {
			return out, err
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
			if env.Prekey == nil || len(env.Header.DHPub) != 32 {
				break // leave the rest queued
			}
			id, err := s.idStore.LoadIdentity(passphrase)
			if err != nil {
				return out, err
			}
			var senderPub domain.X25519Public
			copy(senderPub[:], env.Header.DHPub)

			if env.Prekey.SPKID == "" {
				return out, fmt.Errorf("missing SPKID in prekey message")
			}
			spkPriv, _, _, okSPK, err := s.prekeyStore.LoadSignedPrekey(env.Prekey.SPKID)
			if err != nil {
				return out, err
			}
			if !okSPK {
				return out, fmt.Errorf("signed prekey %q not found", env.Prekey.SPKID)
			}

			var opkPriv *domain.X25519Private
			if env.Prekey.OPKID != "" {
				p, _, okOPK, err := s.prekeyStore.ConsumeOneTimePrekey(env.Prekey.OPKID)
				if err != nil {
					return out, err
				}
				if okOPK {
					opkPriv = &p
				}
			}

			rk, err := x3dh.ResponderRoot(id, spkPriv, opkPriv, *env.Prekey)
			if err != nil {
				return out, fmt.Errorf("x3dh responder root: %w", err)
			}
			st, err := ratchet.InitAsResponder(rk, id.XPriv, id.XPub, senderPub)
			if err != nil {
				return out, err
			}
			conv = domain.Conversation{Peer: env.From, State: st}
		}

		// Decrypt using the ratchet state and associated data.
		plain, err := ratchet.Decrypt(&conv.State, env.AD, env.Header, env.Cipher)
		if err != nil {
			return out, fmt.Errorf("decrypt from %q failed: %w", env.From, err)
		}

		// Persist updated ratchet state after successful decrypt to advance chains.
		if err := s.ratchetStore.SaveConversation(env.From, conv); err != nil {
			return out, fmt.Errorf("save conversation %q: %w", env.From, err)
		}

		out = append(out, domain.DecryptedMessage{
			From:      env.From,
			To:        env.To,
			Plaintext: plain,
			Timestamp: env.Timestamp,
		})
		processed = i + 1
	}

	// Ack only what we processed successfully. If zero, do nothing.
	if processed > 0 {
		if err := s.relayClient.AckMessages(ctx, me, processed); err != nil {
			return out, fmt.Errorf("ack %d messages: %w", processed, err)
		}
	}
	return out, nil
}

// Compile-time assertion that Service implements domain.MessageService.
var _ domain.MessageService = (*Service)(nil)
