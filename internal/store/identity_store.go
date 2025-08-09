package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"ciphera/internal/domain"
)

const idFilename = "identity.json.enc"

// IdentityFileStore persists the local identity to disk.
type IdentityFileStore struct {
	dir string
	mu  sync.Mutex
}

// NewIdentityFileStore returns an IdentityFileStore rooted at dir.
func NewIdentityFileStore(dir string) *IdentityFileStore {
	return &IdentityFileStore{dir: dir}
}

// SaveIdentity writes the encrypted identity to disk.
func (s *IdentityFileStore) SaveIdentity(passphrase string, id domain.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := json.Marshal(id)
	if err != nil {
		return err
	}
	N, r, p := scryptParamsDefault()
	ct, err := encrypt(passphrase, raw, N, r, p)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, idFilename)
	return os.WriteFile(path, ct, 0o600)
}

// LoadIdentity reads and decrypts the identity.
func (s *IdentityFileStore) LoadIdentity(passphrase string) (domain.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, idFilename)

	b, err := os.ReadFile(path)
	if err != nil {
		return domain.Identity{}, err
	}
	pt, err := decrypt(passphrase, b)
	if err != nil {
		return domain.Identity{}, err
	}
	var id domain.Identity
	if err := json.Unmarshal(pt, &id); err != nil {
		return domain.Identity{}, err
	}
	return id, nil
}

// Compile-time assertion that IdentityFileStore implements domain.IdentityStore.
var _ domain.IdentityStore = (*IdentityFileStore)(nil)
