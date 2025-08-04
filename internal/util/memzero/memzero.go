package memzero

import "crypto/subtle"

// Zero overwrites b with zeros in a constant-time friendly way.
func Zero(b []byte) {
	if len(b) == 0 {
		return
	}
	zero := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zero)
}
