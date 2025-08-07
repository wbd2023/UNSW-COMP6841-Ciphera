package crypto

import (
	"crypto/ed25519"
	"crypto/rand"

	"ciphera/internal/domain"
)

// GenerateEd25519 returns a new Ed25519 signing key pair.
func GenerateEd25519() (priv domain.Ed25519Private, pub domain.Ed25519Public, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return priv, pub, err
	}

	// write directly into the backing arrays
	copy(priv[:], sk)
	copy(pub[:], pk)

	return priv, pub, nil
}

// SignEd25519 signs msg with priv and returns the signature.
func SignEd25519(priv domain.Ed25519Private, msg []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(priv.Slice()), msg)
}

// VerifyEd25519 verifies sig over msg with pub.
func VerifyEd25519(pub domain.Ed25519Public, msg, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub.Slice()), msg, sig)
}
