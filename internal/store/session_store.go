package store

import (
	"path/filepath"
	"sync"

	"ciphera/internal/domain"
)

const sessFile = "sessions.json"

type SessionFileStore struct {
	dir string
	mu  sync.Mutex
}

func NewSessionFileStore(dir string) *SessionFileStore { return &SessionFileStore{dir: dir} }

func (s *SessionFileStore) Save(sess domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, sessFile)
	m := make(map[string]domain.Session)
	_ = readJSON(path, &m)
	m[sess.Peer] = sess
	return writeJSON(path, m, 0o600)
}

func (s *SessionFileStore) Get(peer string) (domain.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, sessFile)
	m := make(map[string]domain.Session)
	if err := readJSON(path, &m); err != nil {
		return domain.Session{}, false, err
	}
	v, ok := m[peer]
	return v, ok, nil
}

var _ domain.SessionStore = (*SessionFileStore)(nil)
