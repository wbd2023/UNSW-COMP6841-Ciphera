package store

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

type FileStore struct {
	home string
}

func NewFileStore(home string) *FileStore {
	return &FileStore{home: home}
}

var _ IdentityStore = (*FileStore)(nil)

func (s *FileStore) idPath() string {
	return filepath.Join(s.home, "identity.json")
}

type identityOnDisk struct {
	Version int    `json:"version"`
	Public  []byte `json:"public"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	EncPriv []byte `json:"enc_priv"`
}

func (s *FileStore) SaveIdentity(id domain.Identity, passphrase string) error {
	if _, err := os.Stat(s.idPath()); err == nil {
		return domain.ErrIdentityExists
	}
	salt := make([]byte, crypto.SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	plain := make([]byte, len(id.Private))
	copy(plain, id.Private[:])

	nonce, ct, err := crypto.EncryptSecret(passphrase, plain, salt)
	if err != nil {
		return err
	}

	out := identityOnDisk{
		Version: 1,
		Public:  id.Public[:],
		Salt:    salt,
		Nonce:   nonce,
		EncPriv: ct,
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
	var in identityOnDisk
	if err := json.Unmarshal(data, &in); err != nil {
		return domain.Identity{}, err
	}
	if in.Version != 1 {
		return domain.Identity{}, fmt.Errorf("unsupported identity version %d", in.Version)
	}
	priv, err := crypto.DecryptSecret(passphrase, in.Salt, in.Nonce, in.EncPriv)
	if err != nil {
		return domain.Identity{}, err
	}
	if len(priv) != 32 || len(in.Public) != 32 {
		return domain.Identity{}, errors.New("bad key sizes")
	}
	var id domain.Identity
	copy(id.Private[:], priv)
	copy(id.Public[:], in.Public)
	crypto.Zero(priv)
	return id, nil
}
