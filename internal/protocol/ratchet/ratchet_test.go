package ratchet_test

import (
	"bytes"
	"testing"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
	"ciphera/internal/protocol/ratchet"
)

// makeIdentity returns a fresh X25519 identity pair.
func makeIdentity(t *testing.T) (priv domain.X25519Private, pub domain.X25519Public) {
	t.Helper()
	p, P, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	return p, P
}

func TestDoubleRatchet_OneRoundTrip(t *testing.T) {
	// Shared root key from a prior X3DH (simulate).
	rk := bytes.Repeat([]byte{0x42}, 32)

	// Two parties (A initiates).
	aPriv, aPub := makeIdentity(t)
	bPriv, bPub := makeIdentity(t)

	// Initiator seeds SendCK using peer identity.
	aState, err := ratchet.InitAsInitiator(rk, aPriv, aPub, bPub)
	if err != nil {
		t.Fatalf("InitAsInitiator: %v", err)
	}

	// Responder seeds RecvCK using its identity and sender's current ratchet pub.
	bState, err := ratchet.InitAsResponder(rk, bPriv, bPub, aState.DHPub)
	if err != nil {
		t.Fatalf("InitAsResponder: %v", err)
	}

	header, ct, err := ratchet.Encrypt(&aState, nil, []byte("hi"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := ratchet.Decrypt(&bState, nil, header, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "hi" {
		t.Fatalf("got %q, want %q", pt, "hi")
	}
}
