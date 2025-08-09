package store

import (
	"path/filepath"
	"sync"

	"ciphera/internal/domain"
)

const bundleFile = "bundle.json"

// BundleFileStore caches the last prekey bundle you registered.
type BundleFileStore struct {
	dir string
	mu  sync.Mutex
}

// NewBundleFileStore returns a BundleFileStore rooted at dir.
func NewBundleFileStore(dir string) *BundleFileStore {
	return &BundleFileStore{dir: dir}
}

// SavePrekeyBundle writes the bundle to disk.
func (s *BundleFileStore) SavePrekeyBundle(b domain.PrekeyBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, bundleFile)
	return writeJSON(path, b, 0o600)
}

// LoadPrekeyBundle returns the cached bundle and whether it was present.
//
// Parameter username is accepted for interface compatibility but not used for the local cache.
func (s *BundleFileStore) LoadPrekeyBundle(username string) (domain.PrekeyBundle, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, bundleFile)

	var b domain.PrekeyBundle
	if err := readJSON(path, &b); err != nil {
		return domain.PrekeyBundle{}, false, err
	}
	if b.Username == "" {
		return domain.PrekeyBundle{}, false, nil
	}
	return b, true, nil
}

// Compile-time assertion that BundleFileStore implements domain.PrekeyBundleStore.
var _ domain.PrekeyBundleStore = (*BundleFileStore)(nil)
