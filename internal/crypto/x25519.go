package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"ciphera/internal/domain"
)

// GenerateX25519 generates a new X25519 keypair, clamping the private key per RFC7748 and
// returning (priv, pub).
func GenerateX25519() (priv domain.X25519Private, pub domain.X25519Public, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return priv, pub, fmt.Errorf("x25519: generate private key: %w", err)
	}
	ClampX25519PrivateKey(&priv)
	pubBytes, err := curve25519.X25519(priv.Slice(), curve25519.Basepoint)
	if err != nil {
		return priv, pub, fmt.Errorf("x25519: compute public key: %w", err)
	}
	copy(pub[:], pubBytes)
	return priv, pub, nil
}

// DH performs a Curve25519 Diffie–Hellman between priv and pub, returning a 32-byte shared secret.
func DH(priv domain.X25519Private, pub domain.X25519Public) (shared [32]byte, err error) {
	secret, err := curve25519.X25519(priv.Slice(), pub.Slice())
	if err != nil {
		return shared, fmt.Errorf("x25519: DH failed: %w", err)
	}
	copy(shared[:], secret)
	return shared, nil
}

// ClampX25519PrivateKey applies RFC7748 clamping to a 32-byte scalar in place.
func ClampX25519PrivateKey(k *domain.X25519Private) {
	kb := (*k)[:]
	kb[0] &= 248
	kb[31] &= 127
	kb[31] |= 64
}
