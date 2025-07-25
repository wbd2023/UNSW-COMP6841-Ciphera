package store

import (
	"encoding/json"
	"os"
	"path/filepath"

	"ciphera/internal/domain"
)

type sessionDisk struct {
	RootKey        []byte
	OurIdentity    []byte
	PeerIdentity   []byte
	PeerEd25519    []byte
	PeerSPK        []byte
	UsedOneTimeKey bool
}

type SessionsFile struct {
	Version  int                    `json:"version"`
	Sessions map[string]sessionDisk `json:"sessions"`
}

type SessionStore struct {
	home string
}

func NewSessionStore(home string) *SessionStore {
	return &SessionStore{home: home}
}

func (s *SessionStore) path() string {
	return filepath.Join(s.home, "sessions.json")
}

func (s *SessionStore) SaveSession(sess domain.Session) error {
	state, err := s.loadAll()
	if err != nil {
		return err
	}
	if state.Sessions == nil {
		state.Sessions = make(map[string]sessionDisk)
	}
	state.Sessions[sess.Peer] = sessionDisk{
		RootKey:        append([]byte(nil), sess.RootKey...),
		OurIdentity:    sess.OurIdentity.Slice(),
		PeerIdentity:   sess.PeerIdentity.Slice(),
		PeerEd25519:    sess.PeerEd25519.Slice(),
		PeerSPK:        sess.PeerSPK.Slice(),
		UsedOneTimeKey: sess.UsedOneTimeKey,
	}
	return s.saveAll(state)
}

func (s *SessionStore) LoadSession(peer string) (domain.Session, bool, error) {
	state, err := s.loadAll()
	if err != nil {
		return domain.Session{}, false, err
	}
	d, ok := state.Sessions[peer]
	if !ok {
		return domain.Session{}, false, nil
	}
	return domain.Session{
		Peer:           peer,
		RootKey:        append([]byte(nil), d.RootKey...),
		OurIdentity:    domain.MustX25519Public(d.OurIdentity),
		PeerIdentity:   domain.MustX25519Public(d.PeerIdentity),
		PeerEd25519:    domain.MustEd25519Public(d.PeerEd25519),
		PeerSPK:        domain.MustX25519Public(d.PeerSPK),
		UsedOneTimeKey: d.UsedOneTimeKey,
	}, true, nil
}

func (s *SessionStore) loadAll() (SessionsFile, error) {
	var out SessionsFile
	b, err := os.ReadFile(s.path())
	if err != nil {
		if os.IsNotExist(err) {
			out.Version = 1
			out.Sessions = make(map[string]sessionDisk)
			return out, nil
		}
		return out, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (s *SessionStore) saveAll(sf SessionsFile) error {
	b, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(), b, 0o600)
}

var _ domain.SessionStore = (*SessionStore)(nil)
