package store

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const (
	// The current supported version of the encrypted blob format stored on disk.
	keystoreFormatVersion = 1
)

var (
	// Returned when the passphrase is incorrect or the ciphertext has been modified / corrupted.
	errWrongPassphrase = errors.New("wrong passphrase or corrupted identity")
)

// blob is the on‑disk JSON structure holding the ciphertext and KDF parameters.
type blob struct {
	V      int    `json:"v"`
	Salt   []byte `json:"salt"`
	N      int    `json:"scrypt_N"`
	R      int    `json:"scrypt_r"`
	P      int    `json:"scrypt_p"`
	Cipher []byte `json:"cipher"`
}

// encrypt derives a key from passphrase and seals raw into a JSON blob.
func encrypt(passphrase string, raw []byte, N, r, p int) ([]byte, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:] /* #nosec G404 */); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt[:], N, r, p, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte // zero nonce; salt‑bound key guarantees uniqueness
	ct := aead.Seal(nil, nonce[:], raw, salt[:])

	return json.Marshal(blob{
		V:      1,
		Salt:   salt[:],
		N:      N,
		R:      r,
		P:      p,
		Cipher: ct,
	})
}

// decrypt opens the JSON blob using a key derived from passphrase.
func decrypt(passphrase string, b []byte) ([]byte, error) {
	var bl blob
	if err := json.Unmarshal(b, &bl); err != nil {
		return nil, err
	}
	if bl.V > keystoreFormatVersion {
		return nil, fmt.Errorf("unsupported keystore version %d", bl.V)
	}

	key, err := scrypt.Key([]byte(passphrase), bl.Salt, bl.N, bl.R, bl.P, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	pt, err := aead.Open(nil, nonce[:], bl.Cipher, bl.Salt)
	if err != nil {
		return nil, errWrongPassphrase
	}
	return pt, nil
}

// Tunables for scrypt key derivation.
func scryptParamsDefault() (N, r, p int) { return 1 << 15, 8, 1 }
