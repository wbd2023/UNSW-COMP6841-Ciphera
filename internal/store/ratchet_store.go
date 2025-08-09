package store

import (
	"path/filepath"
	"sync"

	"ciphera/internal/domain"
)

const convFilename = "conversations.json"

// RatchetFileStore persists per-peer Double-Ratchet state to disk.
type RatchetFileStore struct {
	dir string
	mu  sync.Mutex
}

// NewRatchetFileStore returns a RatchetFileStore rooted at dir.
func NewRatchetFileStore(dir string) *RatchetFileStore {
	return &RatchetFileStore{dir: dir}
}

// SaveConversation writes the Conversation for peer.
func (s *RatchetFileStore) SaveConversation(peer string, conv domain.Conversation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, convFilename)
	m := map[string]domain.Conversation{}
	_ = readJSON(path, &m)
	m[peer] = conv
	return writeJSON(path, m, 0o600)
}

// LoadConversation retrieves the Conversation for peer.
func (s *RatchetFileStore) LoadConversation(peer string) (domain.Conversation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, convFilename)
	m := map[string]domain.Conversation{}
	if err := readJSON(path, &m); err != nil {
		return domain.Conversation{}, false, err
	}
	c, ok := m[peer]
	return c, ok, nil
}

// Compile-time assertion that RatchetFileStore implements domain.RatchetStore.
var _ domain.RatchetStore = (*RatchetFileStore)(nil)
