package types

// X25519Public is a Curve25519 public key.
type X25519Public [32]byte

// Slice returns the key as a []byte.
func (p X25519Public) Slice() []byte { return p[:] }

// X25519Private is a Curve25519 private key.
type X25519Private [32]byte

// Slice returns the key as a []byte.
func (k X25519Private) Slice() []byte { return k[:] }

// Ed25519Public is an Ed25519 signing public key.
type Ed25519Public [32]byte

// Slice returns the key as a []byte.
func (p Ed25519Public) Slice() []byte { return p[:] }

// Ed25519Private is an Ed25519 signing private key.
type Ed25519Private [64]byte

// Slice returns the key as a []byte.
func (k Ed25519Private) Slice() []byte { return k[:] }
