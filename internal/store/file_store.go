package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
	"ciphera/internal/util/memzero"
)

type FileStore struct {
	home string
}

func NewFileStore(home string) *FileStore {
	return &FileStore{home: home}
}

var _ IdentityStore = (*FileStore)(nil)
var _ PrekeyStore = (*FileStore)(nil)

func (s *FileStore) idPath() string      { return filepath.Join(s.home, "identity.json") }
func (s *FileStore) prekeysPath() string { return filepath.Join(s.home, "prekeys.json") }

// ---------- Identities ----------

type identityOnDiskV2 struct {
	Version int `json:"version"` // 2
	// X25519
	XPub  []byte `json:"x_pub"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
	EncX  []byte `json:"enc_x_priv"`
	// Ed25519
	NonceEd []byte `json:"nonce_ed"`
	EncEd   []byte `json:"enc_ed_priv"` // encrypted ed25519 private key
	EdPub   []byte `json:"ed_pub"`
}

func (s *FileStore) SaveIdentity(id domain.Identity, passphrase string) error {
	if _, err := os.Stat(s.idPath()); err == nil {
		return domain.ErrIdentityExists
	}

	// encrypt XPriv
	salt := make([]byte, crypto.SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	// make a throwaway copy because EncryptSecret zeroes the plaintext slice
	xPlain := append([]byte(nil), id.XPriv.Slice()...)
	nonceX, encX, err := crypto.EncryptSecret(passphrase, xPlain, salt)
	if err != nil {
		return err
	}

	// encrypt EdPriv (reuse same salt for the assignment)
	edPlain := append([]byte(nil), id.EdPriv.Slice()...)
	nonceEd, encEd, err := crypto.EncryptSecret(passphrase, edPlain, salt)
	if err != nil {
		return err
	}

	out := identityOnDiskV2{
		Version: 2,
		XPub:    id.XPub.Slice(),
		Salt:    salt,
		Nonce:   nonceX,
		EncX:    encX,
		EdPub:   id.EdPub.Slice(),
		NonceEd: nonceEd,
		EncEd:   encEd,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.idPath(), data, 0o600)
}

func (s *FileStore) LoadIdentity(passphrase string) (domain.Identity, error) {
	data, err := os.ReadFile(s.idPath())
	if err != nil {
		return domain.Identity{}, err
	}

	var v2 identityOnDiskV2
	if err := json.Unmarshal(data, &v2); err != nil {
		return domain.Identity{}, err
	}
	if v2.Version != 2 {
		return domain.Identity{}, fmt.Errorf("unsupported identity version %d", v2.Version)
	}

	xPriv, err := crypto.DecryptSecret(passphrase, v2.Salt, v2.Nonce, v2.EncX)
	if err != nil {
		return domain.Identity{}, err
	}
	edPrivRaw, err := crypto.DecryptSecret(passphrase, v2.Salt, v2.NonceEd, v2.EncEd)
	if err != nil {
		return domain.Identity{}, err
	}
	if len(xPriv) != 32 || len(v2.XPub) != 32 {
		return domain.Identity{}, errors.New("bad x25519 key sizes")
	}
	if l := len(edPrivRaw); l != ed25519.PrivateKeySize {
		return domain.Identity{}, fmt.Errorf("bad ed25519 key size %d", l)
	}
	if len(v2.EdPub) != ed25519.PublicKeySize {
		return domain.Identity{}, errors.New("bad ed25519 public size")
	}

	id := domain.Identity{
		XPriv:  domain.MustX25519Private(xPriv),
		XPub:   domain.MustX25519Public(v2.XPub),
		EdPriv: domain.MustEd25519Private(edPrivRaw),
		EdPub:  domain.MustEd25519Public(v2.EdPub),
	}

	memzero.Zero(xPriv)
	// edPrivRaw becomes id.EdPriv; do not zero here

	return id, nil
}

// ---------- Prekeys ----------

type prekeysOnDisk struct {
	Version   int                    `json:"version"`
	SignedPre domain.SignedPreKey    `json:"signed_prekey"`
	OneTime   []domain.OneTimePreKey `json:"one_time_prekeys"`
}

func (s *FileStore) SavePrekeys(spk domain.SignedPreKey, otks []domain.OneTimePreKey) error {
	out := prekeysOnDisk{
		Version:   1,
		SignedPre: spk,
		OneTime:   otks,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.prekeysPath(), b, 0o600)
}

func (s *FileStore) LoadPrekeys() (domain.SignedPreKey, []domain.OneTimePreKey, error) {
	b, err := os.ReadFile(s.prekeysPath())
	if err != nil {
		return domain.SignedPreKey{}, nil, err
	}
	var in prekeysOnDisk
	if err := json.Unmarshal(b, &in); err != nil {
		return domain.SignedPreKey{}, nil, err
	}
	if in.Version != 1 {
		return domain.SignedPreKey{}, nil, fmt.Errorf("unsupported prekeys version")
	}
	return in.SignedPre, in.OneTime, nil
}
