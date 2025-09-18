package store

import (
	"fmt"
	"path/filepath"
	"sync"

	"ciphera/internal/domain"
)

const accountsFile = "accounts.json"

// AccountFileStore persists per-relay account profiles to disk.
type AccountFileStore struct {
	dir string
	mu  sync.Mutex
}

// NewAccountFileStore returns an AccountFileStore rooted at dir.
func NewAccountFileStore(dir string) *AccountFileStore {
	return &AccountFileStore{dir: dir}
}

// SaveAccountProfile stores or updates the given profile.
func (s *AccountFileStore) SaveAccountProfile(profile domain.AccountProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, accountsFile)
	profiles := make(map[string]domain.AccountProfile)
	_ = readJSON(path, &profiles)
	profiles[accountKey(profile.ServerURL, profile.Username)] = profile
	return writeJSON(path, profiles, 0o600)
}

// LoadAccountProfile retrieves a profile for (serverURL, username).
func (s *AccountFileStore) LoadAccountProfile(
	serverURL string,
	username domain.Username,
) (domain.AccountProfile, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, accountsFile)
	profiles := make(map[string]domain.AccountProfile)
	if err := readJSON(path, &profiles); err != nil {
		return domain.AccountProfile{}, false, err
	}
	profile, ok := profiles[accountKey(serverURL, username)]
	return profile, ok, nil
}

func accountKey(serverURL string, username domain.Username) string {
	return fmt.Sprintf("%s|%s", serverURL, username.String())
}

// Compile-time assertion that AccountFileStore implements domain.AccountStore.
var _ domain.AccountStore = (*AccountFileStore)(nil)
