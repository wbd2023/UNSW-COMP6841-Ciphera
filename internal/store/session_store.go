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
func (s *SessionFileStore) SaveSession(peer domain.Username, session domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, sessionsFilename)
	sessions := map[domain.Username]domain.Session{}
	_ = readJSON(path, &sessions)
	sessions[peer] = session
	return writeJSON(path, sessions, 0o600)
}

// LoadSession retrieves a stored session for peer.
func (s *SessionFileStore) LoadSession(peer domain.Username) (domain.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, sessionsFilename)
	sessions := map[domain.Username]domain.Session{}
	if err := readJSON(path, &sessions); err != nil {
		return domain.Session{}, false, err
	}
	session, ok := sessions[peer]
	return session, ok, nil
}

// Compile-time assertion that SessionFileStore implements domain.SessionStore.
var _ domain.SessionStore = (*SessionFileStore)(nil)
