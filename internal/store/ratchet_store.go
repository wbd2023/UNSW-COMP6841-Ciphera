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
func (s *RatchetFileStore) SaveConversation(
	peer domain.ConversationID,
	conversation domain.Conversation,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, convFilename)
	conversations := make(map[domain.ConversationID]domain.Conversation)
	_ = readJSON(path, &conversations)
	conversations[peer] = conversation
	return writeJSON(path, conversations, 0o600)
}

// LoadConversation retrieves the Conversation for peer.
func (s *RatchetFileStore) LoadConversation(
	peer domain.ConversationID,
) (domain.Conversation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, convFilename)
	conversations := make(map[domain.ConversationID]domain.Conversation)
	if err := readJSON(path, &conversations); err != nil {
		return domain.Conversation{}, false, err
	}
	conversation, ok := conversations[peer]
	return conversation, ok, nil
}

// Compile-time assertion that RatchetFileStore implements domain.RatchetStore.
var _ domain.RatchetStore = (*RatchetFileStore)(nil)
