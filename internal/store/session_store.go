package store

import (
	"path/filepath"
	"sync"

	"ciphera/internal/domain"
)

const sessionsFilename = "sessions.json"

// SessionFileStore persists established X3DH sessions to disk.
type SessionFileStore struct {
	dir string
	mu  sync.Mutex
}

// NewSessionFileStore returns a SessionFileStore rooted at dir.
func NewSessionFileStore(dir string) *SessionFileStore {
	return &SessionFileStore{dir: dir}
}

// SaveSession writes a session record for peer.
func (s *SessionFileStore) SaveSession(peer string, sess domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, sessionsFilename)
	m := map[string]domain.Session{}
	_ = readJSON(path, &m)
	m[peer] = sess
	return writeJSON(path, m, 0o600)
}

// LoadSession retrieves a stored session for peer.
func (s *SessionFileStore) LoadSession(peer string) (domain.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, sessionsFilename)
	m := map[string]domain.Session{}
	if err := readJSON(path, &m); err != nil {
		return domain.Session{}, false, err
	}
	sess, ok := m[peer]
	return sess, ok, nil
}

// Compile-time assertion that SessionFileStore implements domain.SessionStore.
var _ domain.SessionStore = (*SessionFileStore)(nil)
