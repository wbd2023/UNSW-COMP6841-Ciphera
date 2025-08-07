package message

import (
	"fmt"
	"time"

	"ciphera/internal/domain"
	"ciphera/internal/protocol/ratchet"
	"ciphera/internal/protocol/x3dh"
)

// Service sends and receives messages over the relay using Double Ratchet.
type Service struct {
	idStore  domain.IdentityStore
	prekeys  domain.PrekeyStore
	sessions domain.SessionService
	rstore   domain.RatchetStore
	relay    domain.RelayClient
}

// New constructs a Message Service with the given stores and relay client.
func New(
	ids domain.IdentityStore,
	ps domain.PrekeyStore,
	sess domain.SessionService,
	rs domain.RatchetStore,
	relay domain.RelayClient,
) *Service {
	return &Service{idStore: ids, prekeys: ps, sessions: sess, rstore: rs, relay: relay}
}

var _ domain.MessageService = (*Service)(nil)

// Send encrypts and posts plaintext.
//
// If no conversation exists, it initialises the initiator ratchet and includes a PrekeyMessage
// matching the stored X3DH initiation so the responder can derive the same root.
func (s *Service) Send(passphrase, fromUsername, toUsername string, plaintext []byte) error {
	sess, ok, err := s.sessions.Get(toUsername)
	if err != nil {
		return err
	}
	if !ok {
		return errNoSession
	}

	conv, found, err := s.rstore.LoadConversation(toUsername)
	if err != nil {
		return err
	}

	var prekey *domain.PrekeyMessage
	if !found {
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

	header, ct, err := ratchet.Encrypt(&conv.State, nil, plaintext)
	if err != nil {
		return err
	}

	if err := s.rstore.SaveConversation(toUsername, conv); err != nil {
		return err
	}

	env := domain.Envelope{
		From:      fromUsername,
		To:        toUsername,
		Header:    header,
		Cipher:    ct,
		Prekey:    prekey,
		Timestamp: time.Now().Unix(),
	}
	return s.relay.SendMessage(env)
}

// Receive fetches pending messages and decrypts them.
//
// On a first inbound from a peer, it derives the responder root via X3DH and then initialises the
// responder ratchet with the sender's header DH pub.
func (s *Service) Receive(passphrase, me string, limit int) ([]domain.DecryptedMessage, error) {
	envs, err := s.relay.FetchMessages(me, limit)
	if err != nil {
		return nil, err
	}
	out := make([]domain.DecryptedMessage, 0, len(envs))
	processed := 0

	for i, env := range envs {
		conv, found, err := s.rstore.LoadConversation(env.From)
		if err != nil {
			return out, err
		}

		if !found {
			// Need to bootstrap via PrekeyMessage
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
			spkPriv, _, _, okSPK, err := s.prekeys.LoadSignedPrekey(env.Prekey.SPKID)
			if err != nil {
				return out, err
			}
			if !okSPK {
				return out, fmt.Errorf("signed prekey %q not found", env.Prekey.SPKID)
			}

			var opkPriv *domain.X25519Private
			if env.Prekey.OPKID != "" {
				p, _, okOPK, err := s.prekeys.ConsumeOneTimePrekey(env.Prekey.OPKID)
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

		plain, err := ratchet.Decrypt(&conv.State, env.AD, env.Header, env.Cipher)
		if err != nil {
			return out, fmt.Errorf("decrypt from %q failed: %w", env.From, err)
		}
		if err := s.rstore.SaveConversation(env.From, conv); err != nil {
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

	if processed > 0 {
		if err := s.relay.AckMessages(me, processed); err != nil {
			return out, fmt.Errorf("ack %d messages: %w", processed, err)
		}
	}
	return out, nil
}

var errNoSession = errString("no session with peer; run Initiate first")

type errString string

func (e errString) Error() string { return string(e) }
