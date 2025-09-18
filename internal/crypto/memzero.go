package crypto

import (
	"crypto/subtle"
	"runtime"
)

// Wipe zeroes the provided buffer. Best effort to prevent compiler elision.
func Wipe(b []byte) {
	if len(b) == 0 {
		return
	}
	zero := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zero)
	runtime.KeepAlive(&b)
}

// DeferWipe returns a cleanup that wipes buf when invoked. Intended for defer use.
func DeferWipe(buf *[]byte) func() {
	return func() {
		if buf == nil || *buf == nil {
			return
		}
		Wipe(*buf)
		*buf = nil
	}
}

// Move copies src into dst in constant time and wipes src afterwards.
func Move(dst, src []byte) {
	if len(dst) != len(src) {
		panic("crypto.Move: length mismatch")
	}
	if len(src) == 0 {
		return
	}

	subtle.ConstantTimeCopy(1, dst, src)
	zero := make([]byte, len(src))
	subtle.ConstantTimeCopy(1, src, zero)
	runtime.KeepAlive(&src)
}
