package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
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

func NewIdentity() (*Identity, error) {
	// X25519
	var xpriv [32]byte
	if _, err := rand.Read(xpriv[:]); err != nil {
		return nil, err
	}
	xpriv[0] &= 248
	xpriv[31] &= 127
	xpriv[31] |= 64
	var xpub [32]byte
	curve25519.ScalarBaseMult(&xpub, &xpriv)

	// Ed25519
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

func Fingerprint(xPub []byte) string {
	sum := sha256.Sum256(xPub)
	return hex.EncodeToString(sum[:])
}

func DeriveKEK(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1<<16, 8, 1, KeyBytes)
}

func EncryptSecret(passphrase string, plaintext []byte, salt []byte) (nonce, ciphertext []byte, err error) {
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
