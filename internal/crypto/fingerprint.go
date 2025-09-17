package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint returns a short hex fingerprint of a public key.
//
// It hashes with SHA-256 and truncates to 10 bytes (20 hex chars).
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:10])
}
