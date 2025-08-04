package crypto

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"

    "golang.org/x/crypto/curve25519"

    "ciphera/internal/domain"
)

// GenerateX25519 returns a fresh Curve25519 key pair.
// The private key is clamped per RFC 7748.
func GenerateX25519() (priv domain.X25519Private, pub domain.X25519Public, err error) {
    if _, err = rand.Read(priv[:]); err != nil {
        return
    }
    clamp(&priv)
    pb, err := curve25519.X25519(priv.Slice(), curve25519.Basepoint)
    if err != nil {
        return
    }
    copy(pub[:], pb)
    return
}

// DH computes X25519 Diffie–Hellman.
func DH(priv domain.X25519Private, pub domain.X25519Public) (out [32]byte, err error) {
    secret, err := curve25519.X25519(priv.Slice(), pub.Slice())
    if err != nil {
        return out, err
    }
    copy(out[:], secret)
    return out, nil
}

// FingerprintX25519 returns a short fingerprint of the public key.
func FingerprintX25519(pub domain.X25519Public) string {
    sum := sha256.Sum256(pub[:])
    return hex.EncodeToString(sum[:10])
}

func clamp(k *domain.X25519Private) {
    kb := k[:]
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
}
