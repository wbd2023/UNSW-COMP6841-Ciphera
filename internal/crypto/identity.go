package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"ciphera/internal/util/memzero"
)

const (
	KeyBytes   = 32
	SaltBytes  = 16
	NonceBytes = chacha20poly1305.NonceSize
)

// Identity carries both Diffie-Hellman (X25519) and signature (Ed25519) material.
type Identity struct {
	XPriv [32]byte
	XPub  [32]byte

	EdPriv ed25519.PrivateKey
	EdPub  ed25519.PublicKey
}

// NewIdentity generates a fresh X25519 key pair and an Ed25519 key pair.
func NewIdentity() (*Identity, error) {
	var xpriv [32]byte
	if _, err := rand.Read(xpriv[:]); err != nil {
		return nil, err
	}
	xpriv[0] &= 248
	xpriv[31] &= 127
	xpriv[31] |= 64

	var xpub [32]byte
	curve25519.ScalarBaseMult(&xpub, &xpriv)

	edpub, edpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Identity{
		XPriv:  xpriv,
		XPub:   xpub,
		EdPriv: edpriv,
		EdPub:  edpub,
	}, nil
}

// Fingerprint returns a SHA-256 hex digest of the X25519 public key.
func Fingerprint(xPub []byte) string {
	sum := sha256.Sum256(xPub)
	return hex.EncodeToString(sum[:])
}

// DeriveKEK derives a key-encryption key from a passphrase and salt using Argon2id.
func DeriveKEK(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1<<16, 8, 1, KeyBytes)
}

// EncryptSecret encrypts plaintext with a KEK derived from the passphrase and salt.
func EncryptSecret(passphrase string, plaintext []byte, salt []byte) (nonce, ciphertext []byte, err error) {
	if len(salt) != SaltBytes {
		return nil, nil, errors.New("invalid salt size")
	}
	kek := DeriveKEK(passphrase, salt)
	defer memzero.Zero(kek)

	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	memzero.Zero(plaintext)
	return nonce, ct, nil
}

// DecryptSecret decrypts a ciphertext with a KEK derived from the passphrase and salt.
func DecryptSecret(passphrase string, salt, nonce, ciphertext []byte) ([]byte, error) {
	if len(salt) != SaltBytes {
		return nil, errors.New("invalid salt size")
	}
	kek := DeriveKEK(passphrase, salt)
	defer memzero.Zero(kek)

	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}
