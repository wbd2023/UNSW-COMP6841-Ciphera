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

func New(ids domain.IdentityStore, ps domain.PrekeyStore, sess domain.SessionService, rs domain.RatchetStore, relay domain.RelayClient) *Service {
	return &Service{idStore: ids, prekeys: ps, sessions: sess, rstore: rs, relay: relay}
}

var _ domain.MessageService = (*Service)(nil)

// Send encrypts and posts plaintext.
// If no conversation exists, it initialises the initiator ratchet and includes a PrekeyMessage that
// matches the stored X3DH initiation (EK/IDs) so the responder can derive the same root.
func (s *Service) Send(passphrase, fromUsername, toUsername string, plaintext []byte) error {
	sess, ok, err := s.sessions.Get(toUsername)
	if err != nil {
		return err
	}
	if !ok {
		return errNoSession
	}

	conv, ok, err := s.rstore.Load(toUsername)
	if err != nil {
		return err
	}
	var prekey *domain.PrekeyMessage

	if !ok {
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
			Ephemeral:   sess.InitiatorEK, // the EK used in X3DH
			SPKID:       sess.SPKID,
			OPKID:       sess.OPKID,
		}
	}

	header, ct, err := ratchet.Encrypt(&conv.State, nil, plaintext)
	if err != nil {
		return err
	}
	if err := s.rstore.Save(conv); err != nil {
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

// Recv fetches pending messages and decrypts them.
// On a first inbound from a peer, it derives the responder root via X3DH (using SPK/optional OPK
// privs) and then initialises the responder ratchet with the sender's header DH pub.
func (s *Service) Recv(passphrase, me string, limit int) ([]domain.DecryptedMessage, error) {
	envs, err := s.relay.FetchMessages(me, limit)
	if err != nil {
		return nil, err
	}
	out := make([]domain.DecryptedMessage, 0, len(envs))
	processedPrefix := 0

	for i, env := range envs {
		conv, ok, err := s.rstore.Load(env.From)
		if err != nil {
			return out, err
		}

		if !ok {
			if env.Prekey == nil || len(env.Header.DHPub) != 32 {
				// Not enough context to bootstrap; leave queued.
				break
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
			spkPriv, _, _, okSPK, err := s.prekeys.LoadSignedPrekeyPair(env.Prekey.SPKID)
			if err != nil {
				return out, err
			}
			if !okSPK {
				return out, fmt.Errorf("signed prekey %q not found", env.Prekey.SPKID)
			}

			var opkPriv *domain.X25519Private
			if env.Prekey.OPKID != "" {
				if p, _, okOPK, err := s.prekeys.ConsumeOneTimePair(env.Prekey.OPKID); err != nil {
					return out, err
				} else if okOPK {
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
		if err := s.rstore.Save(conv); err != nil {
			return out, fmt.Errorf("save conversation %q: %w", env.From, err)
		}

		out = append(out, domain.DecryptedMessage{
			From:      env.From,
			To:        env.To,
			Plaintext: plain,
			Timestamp: env.Timestamp,
		})
		processedPrefix = i + 1
	}

	if processedPrefix > 0 {
		if err := s.relay.AckMessages(me, processedPrefix); err != nil {
			return out, fmt.Errorf("ack %d messages: %w", processedPrefix, err)
		}
	}
	return out, nil
}

var errNoSession = errString("no session with peer, run start-session first")

type errString string

func (e errString) Error() string { return string(e) }
