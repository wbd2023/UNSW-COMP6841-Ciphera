package domain

import "fmt"

// ------------- X25519 -------------

type X25519Private [32]byte
type X25519Public [32]byte

func (k X25519Private) Slice() []byte { return k[:] }
func (k X25519Public) Slice() []byte  { return k[:] }

func MustX25519Private(b []byte) X25519Private {
	if len(b) != 32 {
		panic(fmt.Errorf("X25519 private: want 32 bytes, got %d", len(b)))
	}
	var out X25519Private
	copy(out[:], b)
	return out
}

func MustX25519Public(b []byte) X25519Public {
	if len(b) != 32 {
		panic(fmt.Errorf("X25519 public: want 32 bytes, got %d", len(b)))
	}
	var out X25519Public
	copy(out[:], b)
	return out
}

// ------------- Ed25519 -------------

type Ed25519Private [64]byte
type Ed25519Public [32]byte

func (k Ed25519Private) Slice() []byte { return k[:] }
func (k Ed25519Public) Slice() []byte  { return k[:] }

func MustEd25519Private(b []byte) Ed25519Private {
	if len(b) != 64 {
		panic(fmt.Errorf("Ed25519 private: want 64 bytes, got %d", len(b)))
	}
	var out Ed25519Private
	copy(out[:], b)
	return out
}

func MustEd25519Public(b []byte) Ed25519Public {
	if len(b) != 32 {
		panic(fmt.Errorf("Ed25519 public: want 32 bytes, got %d", len(b)))
	}
	var out Ed25519Public
	copy(out[:], b)
	return out
}
