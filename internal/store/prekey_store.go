package store

import (
	"path/filepath"
	"sync"

	"ciphera/internal/domain"
)

const (
	spkPairsFile   = "spk_pairs.json"
	opkPairsFile   = "opk_pairs.json"
	prekeyMetaFile = "prekey_meta.json"
)

// PrekeyFileStore persists Signed Pre-Key and One-Time Pre-Key state to disk.
type PrekeyFileStore struct {
	dir string
	mu  sync.Mutex
}

// NewPrekeyFileStore returns a PrekeyFileStore rooted at dir.
func NewPrekeyFileStore(dir string) *PrekeyFileStore {
	return &PrekeyFileStore{dir: dir}
}

// Internal record types.
type spkPair struct {
	Priv [32]byte `json:"priv"`
	Pub  [32]byte `json:"pub"`
	Sig  []byte   `json:"sig"`
}

type opkPair struct {
	Priv [32]byte `json:"priv"`
	Pub  [32]byte `json:"pub"`
}

type prekeyMeta struct {
	CurrentSignedPreKeyID domain.SignedPreKeyID `json:"current_signed_pre_key_id"`
}

// SaveSignedPreKey stores a signed pre-key by id.
func (s *PrekeyFileStore) SaveSignedPreKey(
	id domain.SignedPreKeyID,
	priv domain.X25519Private,
	pub domain.X25519Public,
	sig []byte,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, spkPairsFile)
	m := map[domain.SignedPreKeyID]spkPair{}
	_ = readJSON(path, &m)
	m[id] = spkPair{Priv: priv, Pub: pub, Sig: sig}
	return writeJSON(path, m, 0o600)
}

// LoadSignedPreKey retrieves a signed pre-key by id.
func (s *PrekeyFileStore) LoadSignedPreKey(
	id domain.SignedPreKeyID,
) (
	priv domain.X25519Private,
	pub domain.X25519Public,
	sig []byte,
	ok bool,
	err error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, spkPairsFile)
	m := map[domain.SignedPreKeyID]spkPair{}
	if err = readJSON(path, &m); err != nil {
		return priv, pub, nil, false, err
	}
	p, ok := m[id]
	if !ok {
		return priv, pub, nil, false, nil
	}
	return p.Priv, p.Pub, p.Sig, true, nil
}

// SaveOneTimePreKeys merges the provided one-time pre-key pairs into the store.
func (s *PrekeyFileStore) SaveOneTimePreKeys(pairs []domain.OneTimePreKeyPair) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, opkPairsFile)
	m := map[domain.OneTimePreKeyID]opkPair{}
	_ = readJSON(path, &m)
	for _, p := range pairs {
		m[p.ID] = opkPair{Priv: p.Priv, Pub: p.Pub}
	}
	return writeJSON(path, m, 0o600)
}

// ConsumeOneTimePreKey removes and returns a single one-time pre-key by id.
func (s *PrekeyFileStore) ConsumeOneTimePreKey(
	id domain.OneTimePreKeyID,
) (
	priv domain.X25519Private,
	pub domain.X25519Public,
	ok bool,
	err error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, opkPairsFile)
	m := map[domain.OneTimePreKeyID]opkPair{}
	if err = readJSON(path, &m); err != nil {
		return priv, pub, false, err
	}
	p, ok := m[id]
	if !ok {
		return priv, pub, false, nil
	}
	delete(m, id)
	if err = writeJSON(path, m, 0o600); err != nil {
		return priv, pub, false, err
	}
	return p.Priv, p.Pub, true, nil
}

// ListOneTimePreKeyPublics exposes only the public halves for bundling.
func (s *PrekeyFileStore) ListOneTimePreKeyPublics() ([]domain.OneTimePreKeyPublic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, opkPairsFile)
	m := map[domain.OneTimePreKeyID]opkPair{}
	if err := readJSON(path, &m); err != nil {
		return nil, err
	}

	out := make([]domain.OneTimePreKeyPublic, 0, len(m))
	for id, p := range m {
		out = append(out, domain.OneTimePreKeyPublic{ID: id, Pub: p.Pub})
	}
	return out, nil
}

// SetCurrentSignedPreKeyID records which signed pre-key id is current.
func (s *PrekeyFileStore) SetCurrentSignedPreKeyID(id domain.SignedPreKeyID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, prekeyMetaFile)
	meta := prekeyMeta{CurrentSignedPreKeyID: id}
	return writeJSON(path, meta, 0o600)
}

// CurrentSignedPreKeyID returns the recorded current signed pre-key id.
func (s *PrekeyFileStore) CurrentSignedPreKeyID() (domain.SignedPreKeyID, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, prekeyMetaFile)
	var meta prekeyMeta
	if err := readJSON(path, &meta); err != nil {
		return "", false, err
	}
	if meta.CurrentSignedPreKeyID == "" {
		return "", false, nil
	}
	return meta.CurrentSignedPreKeyID, true, nil
}

// Compile-time assertion that PrekeyFileStore implements domain.PreKeyStore.
var _ domain.PreKeyStore = (*PrekeyFileStore)(nil)
