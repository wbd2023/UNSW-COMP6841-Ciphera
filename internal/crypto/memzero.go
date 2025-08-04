package crypto

import "runtime"

// Wipe zeroes the provided buffer. This is best-effort and aims to
// reduce the chance of the compiler eliding the write.
//
//go:noinline
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Ensure b is considered live until after the loop.
	runtime.KeepAlive(&b)
}
