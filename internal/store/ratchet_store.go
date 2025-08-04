package store

import (
	"path/filepath"
	"sync"

	"ciphera/internal/domain"
)

const convFile = "conversations.json"

type RatchetFileStore struct {
	dir string
	mu  sync.Mutex
}

func NewRatchetFileStore(dir string) *RatchetFileStore { return &RatchetFileStore{dir: dir} }

func (s *RatchetFileStore) Save(conv domain.Conversation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, convFile)
	m := make(map[string]domain.Conversation)
	_ = readJSON(path, &m)
	m[conv.Peer] = conv
	return writeJSON(path, m, 0o600)
}

func (s *RatchetFileStore) Load(peer string) (domain.Conversation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, convFile)
	m := make(map[string]domain.Conversation)
	if err := readJSON(path, &m); err != nil {
		return domain.Conversation{}, false, err
	}
	c, ok := m[peer]
	return c, ok, nil
}

var _ domain.RatchetStore = (*RatchetFileStore)(nil)
