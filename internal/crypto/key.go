package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	KeyBytes   = 32
	SaltBytes  = 16
	NonceBytes = chacha20poly1305.NonceSize
)

type Identity struct {
	Private [32]byte
	Public  [32]byte
}

func NewX25519Identity() (*Identity, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return &Identity{Private: priv, Public: pub}, nil
}

func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func DeriveKEK(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1<<16, 8, 1, KeyBytes)
}

func EncryptSecret(passphrase string, plaintext []byte, salt []byte) (nonce, ciphertext []byte, err error) {
	if len(salt) != SaltBytes {
		return nil, nil, errors.New("bad salt size")
	}
	kek := DeriveKEK(passphrase, salt)
	defer Zero(kek)

	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	Zero(plaintext)
	return nonce, ct, nil
}

func DecryptSecret(passphrase string, salt, nonce, ciphertext []byte) ([]byte, error) {
	kek := DeriveKEK(passphrase, salt)
	defer Zero(kek)

	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}
