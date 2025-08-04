package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint returns a short hex fingerprint of a public key.
// We hash using SHA-256, truncated to 10 bytes (20 hex chars), matching the CLI output.
func Fingerprint(pub []byte) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:10])
}
