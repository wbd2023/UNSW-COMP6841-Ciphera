package store

import (
	"path/filepath"
	"sync"

	"ciphera/internal/domain"
)

const bundleFile = "bundle.json"

// BundleFileStore caches the last pre-key bundle you registered.
type BundleFileStore struct {
	dir string
	mu  sync.Mutex
}

// NewBundleFileStore returns a BundleFileStore rooted at dir.
func NewBundleFileStore(dir string) *BundleFileStore {
	return &BundleFileStore{dir: dir}
}

// SavePreKeyBundle writes the bundle to disk.
func (s *BundleFileStore) SavePreKeyBundle(bundle domain.PreKeyBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, bundleFile)
	return writeJSON(path, bundle, 0o600)
}

// LoadPrekeyBundle returns the cached bundle and whether it was present.
//
// Parameter username is accepted for interface compatibility but not used for the local cache.
func (s *BundleFileStore) LoadPreKeyBundle(
	username domain.Username,
) (domain.PreKeyBundle, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, bundleFile)

	var bundle domain.PreKeyBundle
	if err := readJSON(path, &bundle); err != nil {
		return domain.PreKeyBundle{}, false, err
	}
	if bundle.Username == "" {
		return domain.PreKeyBundle{}, false, nil
	}
	return bundle, true, nil
}

// Compile-time assertion that BundleFileStore implements domain.PreKeyBundleStore.
var _ domain.PreKeyBundleStore = (*BundleFileStore)(nil)
