package crypto

import "runtime"

// Wipe zeroes the provided buffer. Best-effort to prevent compiler elision.
//
//go:noinline
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Keep b alive until after the loop.
	runtime.KeepAlive(&b)
}
