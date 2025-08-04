package store

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"

	"ciphera/internal/domain"
)

const (
	idFile       = "identity.enc"
	spkPairsFile = "spk_pairs.json" // map[string]spkPair
	opkPairsFile = "opk_pairs.json" // map[string]opkPair
	bundleFile   = "bundle_cache.json"
	metaFile     = "prekey_meta.json" // { "current_spk_id": "spk-..." }
)

type spkPair struct {
	Priv [32]byte
	Pub  [32]byte
	Sig  []byte
	At   int64
}

type opkPair struct {
	Priv [32]byte
	Pub  [32]byte
	At   int64
}

type prekeyMeta struct {
	CurrentSPKID string `json:"current_spk_id"`
}

// FileStore stores identity and prekeys on disk.
type FileStore struct {
	dir string
	mu  sync.Mutex
}

func NewFileStore(dir string) *FileStore { return &FileStore{dir: dir} }

// ---------- Identity ----------

func (s *FileStore) Save(passphrase string, id domain.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := json.Marshal(id)
	if err != nil {
		return err
	}
	N, r, p := scryptParamsDefault()
	blob, err := encrypt(passphrase, raw, N, r, p)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, idFile), blob, 0o600)
}

func (s *FileStore) LoadIdentity(passphrase string) (domain.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	blob, err := os.ReadFile(filepath.Join(s.dir, idFile))
	if err != nil {
		return domain.Identity{}, err
	}
	raw, err := decrypt(passphrase, blob)
	if err != nil {
		return domain.Identity{}, err
	}
	var id domain.Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return domain.Identity{}, err
	}
	return id, nil
}

// ---------- Prekey Pairs ----------

func (s *FileStore) SaveSignedPrekeyPair(id string, priv domain.X25519Private, pub domain.X25519Public, sig []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := make(map[string]spkPair)
	_ = readJSON(filepath.Join(s.dir, spkPairsFile), &m)

	m[id] = spkPair{Priv: priv, Pub: pub, Sig: append([]byte(nil), sig...), At: time.Now().Unix()}
	return writeJSON(filepath.Join(s.dir, spkPairsFile), m, 0o600)
}

func (s *FileStore) LoadSignedPrekeyPair(id string) (priv domain.X25519Private, pub domain.X25519Public, sig []byte, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := make(map[string]spkPair)
	if err = readJSON(filepath.Join(s.dir, spkPairsFile), &m); err != nil {
		return priv, pub, nil, false, err
	}
	p, exists := m[id]
	if !exists {
		return priv, pub, nil, false, nil
	}
	return p.Priv, p.Pub, append([]byte(nil), p.Sig...), true, nil
}

func (s *FileStore) SaveOneTimePairs(pairs []domain.OneTimePair) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := make(map[string]opkPair)
	_ = readJSON(filepath.Join(s.dir, opkPairsFile), &m)

	for _, p := range pairs {
		m[p.ID] = opkPair{Priv: p.Priv, Pub: p.Pub, At: time.Now().Unix()}
	}
	return writeJSON(filepath.Join(s.dir, opkPairsFile), m, 0o600)
}

func (s *FileStore) ConsumeOneTimePair(id string) (priv domain.X25519Private, pub domain.X25519Public, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := make(map[string]opkPair)
	if err = readJSON(filepath.Join(s.dir, opkPairsFile), &m); err != nil {
		return priv, pub, false, err
	}
	p, exists := m[id]
	if !exists {
		return priv, pub, false, nil
	}
	delete(m, id)
	if err = writeJSON(filepath.Join(s.dir, opkPairsFile), m, 0o600); err != nil {
		return priv, pub, false, err
	}
	return p.Priv, p.Pub, true, nil
}

// ListOneTimePublics returns the remaining OPK publics.
func (s *FileStore) ListOneTimePublics() ([]domain.OneTimePub, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := make(map[string]opkPair)
	if err := readJSON(filepath.Join(s.dir, opkPairsFile), &m); err != nil {
		return nil, err
	}
	out := make([]domain.OneTimePub, 0, len(m))
	for id, p := range m {
		out = append(out, domain.OneTimePub{ID: id, Pub: p.Pub})
	}
	return out, nil
}

// ---------- SPK metadata ----------

func (s *FileStore) SetCurrentSPKID(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	meta := prekeyMeta{CurrentSPKID: id}
	return writeJSON(filepath.Join(s.dir, metaFile), meta, 0o600)
}

func (s *FileStore) CurrentSPKID() (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var meta prekeyMeta
	if err := readJSON(filepath.Join(s.dir, metaFile), &meta); err != nil {
		return "", false, err
	}
	if meta.CurrentSPKID == "" {
		return "", false, nil
	}
	return meta.CurrentSPKID, true, nil
}

// ---------- Bundle cache (public) ----------

func (s *FileStore) SaveBundle(b domain.PrekeyBundle) error {
	return writeJSON(filepath.Join(s.dir, bundleFile), b, 0o600)
}

func (s *FileStore) LoadBundle(username string) (domain.PrekeyBundle, bool, error) {
	var b domain.PrekeyBundle
	if err := readJSON(filepath.Join(s.dir, bundleFile), &b); err != nil {
		return domain.PrekeyBundle{}, false, err
	}
	if b.Username != username {
		return domain.PrekeyBundle{}, false, nil
	}
	return b, true, nil
}

// ---------- helpers ----------

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, mode)
}

// scrypt envelope (parameters fixed here; tune as needed)
func scryptParamsDefault() (N, r, p int) { return 1 << 15, 8, 1 }

type envelope struct {
	Salt []byte
	AD   []byte
	CT   []byte
}

func encrypt(passphrase string, plaintext []byte, N, r, p int) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, N, r, p, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	ct := aead.Seal(nil, nonce, plaintext, salt)
	return json.Marshal(envelope{Salt: salt, AD: nil, CT: ct})
}

func decrypt(passphrase string, blob []byte) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), env.Salt, 1<<15, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Open(nil, nonce, env.CT, env.Salt)
}
