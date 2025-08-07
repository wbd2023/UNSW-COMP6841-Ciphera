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

// PrekeyFileStore persists SPK and OPK state to disk.
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
	CurrentSPKID string `json:"current_spk_id"`
}

// SaveSignedPrekey stores a signed prekey by id.
func (s *PrekeyFileStore) SaveSignedPrekey(
	id string,
	priv domain.X25519Private,
	pub domain.X25519Public,
	sig []byte,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, spkPairsFile)
	m := map[string]spkPair{}
	_ = readJSON(path, &m)
	m[id] = spkPair{Priv: priv, Pub: pub, Sig: sig}
	return writeJSON(path, m, 0o600)
}

// LoadSignedPrekey retrieves a signed prekey by id.
func (s *PrekeyFileStore) LoadSignedPrekey(
	id string,
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
	m := map[string]spkPair{}
	if err = readJSON(path, &m); err != nil {
		return priv, pub, nil, false, err
	}
	p, ok := m[id]
	if !ok {
		return priv, pub, nil, false, nil
	}
	return p.Priv, p.Pub, p.Sig, true, nil
}

// SaveOneTimePrekeys merges the provided one-time prekey pairs into the store.
func (s *PrekeyFileStore) SaveOneTimePrekeys(pairs []domain.OneTimePair) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, opkPairsFile)
	m := map[string]opkPair{}
	_ = readJSON(path, &m)
	for _, p := range pairs {
		m[p.ID] = opkPair{Priv: p.Priv, Pub: p.Pub}
	}
	return writeJSON(path, m, 0o600)
}

// ConsumeOneTimePrekey removes and returns a single one-time prekey by id.
func (s *PrekeyFileStore) ConsumeOneTimePrekey(
	id string,
) (
	priv domain.X25519Private,
	pub domain.X25519Public,
	ok bool,
	err error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, opkPairsFile)
	m := map[string]opkPair{}
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

// ListOneTimePrekeyPublics exposes only the public halves for bundling.
func (s *PrekeyFileStore) ListOneTimePrekeyPublics() ([]domain.OneTimePub, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, opkPairsFile)
	m := map[string]opkPair{}
	if err := readJSON(path, &m); err != nil {
		return nil, err
	}

	out := make([]domain.OneTimePub, 0, len(m))
	for id, p := range m {
		out = append(out, domain.OneTimePub{ID: id, Pub: p.Pub})
	}
	return out, nil
}

// SetCurrentSignedPrekeyID records which signed prekey id is current.
func (s *PrekeyFileStore) SetCurrentSignedPrekeyID(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, prekeyMetaFile)
	meta := prekeyMeta{CurrentSPKID: id}
	return writeJSON(path, meta, 0o600)
}

// CurrentSignedPrekeyID returns the recorded current signed prekey id.
func (s *PrekeyFileStore) CurrentSignedPrekeyID() (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, prekeyMetaFile)
	var meta prekeyMeta
	if err := readJSON(path, &meta); err != nil {
		return "", false, err
	}
	if meta.CurrentSPKID == "" {
		return "", false, nil
	}
	return meta.CurrentSPKID, true, nil
}

var _ domain.PrekeyStore = (*PrekeyFileStore)(nil)
