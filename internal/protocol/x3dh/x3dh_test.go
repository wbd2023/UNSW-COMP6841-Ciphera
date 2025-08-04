package x3dh_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
	"ciphera/internal/protocol/x3dh"
)

// makeIdentity creates a domain.Identity with fresh X25519 and Ed25519 pairs.
func makeIdentity(t *testing.T) domain.Identity {
	t.Helper()
	xPriv, xPub, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	var edPrivArr domain.Ed25519Private
	var edPubArr domain.Ed25519Public
	copy(edPrivArr[:], edPriv)
	copy(edPubArr[:], edPub)

	return domain.Identity{
		XPub:   xPub,
		XPriv:  xPriv,
		EdPub:  edPubArr,
		EdPriv: edPrivArr,
	}
}

func TestInitiatorAndResponderRoot_NoOPK(t *testing.T) {
	// Alice is initiator, Bob is responder.
	alice := makeIdentity(t)
	bob := makeIdentity(t)

	// Bob's signed prekey pair + sig.
	spkPriv, spkPub, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	sig := crypto.SignEd25519(bob.EdPriv, spkPub[:])

	// Bob publishes a bundle with no OPKs.
	bundle := domain.PrekeyBundle{
		Username:        "bob",
		IdentityKey:     bob.XPub,
		SignKey:         bob.EdPub,
		SPKID:           "spk-test",
		SignedPrekey:    spkPub,
		SignedPrekeySig: sig,
		OneTime:         nil,
	}

	// Alice derives RK and emits eph pub.
	rkA, spkID, opkID, ephPub, err := x3dh.InitiatorRoot(alice, bundle)
	if err != nil {
		t.Fatalf("InitiatorRoot: %v", err)
	}
	if spkID != "spk-test" {
		t.Fatalf("want spkID=spk-test, got %q", spkID)
	}
	if opkID != "" {
		t.Fatalf("want empty opkID, got %q", opkID)
	}

	// Alice's first message would carry this.
	pm := domain.PrekeyMessage{
		InitiatorIK: alice.XPub,
		Ephemeral:   ephPub,
		SPKID:       spkID,
		OPKID:       opkID,
	}

	// Bob recomputes the same RK using his SPK private and identity.
	rkB, err := x3dh.ResponderRoot(bob, spkPriv, nil, pm)
	if err != nil {
		t.Fatalf("ResponderRoot: %v", err)
	}
	if !bytes.Equal(rkA, rkB) {
		t.Fatal("root keys differ (no OPK)")
	}
}

func TestInitiatorAndResponderRoot_WithOPK(t *testing.T) {
	// Alice is initiator, Bob is responder.
	alice := makeIdentity(t)
	bob := makeIdentity(t)

	// Bob's signed prekey.
	spkPriv, spkPub, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	sig := crypto.SignEd25519(bob.EdPriv, spkPub[:])

	// Bob has a one-time prekey too.
	opkPriv, opkPub, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519 (opk): %v", err)
	}

	bundle := domain.PrekeyBundle{
		Username:        "bob",
		IdentityKey:     bob.XPub,
		SignKey:         bob.EdPub,
		SPKID:           "spk-test",
		SignedPrekey:    spkPub,
		SignedPrekeySig: sig,
		OneTime: []domain.OneTimePub{
			{ID: "opk-1", Pub: opkPub},
		},
	}

	// Alice picks Bob's OPK and derives RK.
	rkA, spkID, opkID, ephPub, err := x3dh.InitiatorRoot(alice, bundle)
	if err != nil {
		t.Fatalf("InitiatorRoot: %v", err)
	}
	if spkID != "spk-test" || opkID != "opk-1" {
		t.Fatalf("unexpected IDs spk=%q opk=%q", spkID, opkID)
	}

	// Alice's first message would carry this.
	pm := domain.PrekeyMessage{
		InitiatorIK: alice.XPub,
		Ephemeral:   ephPub,
		SPKID:       spkID,
		OPKID:       opkID,
	}

	// Bob recomputes with SPK and OPK privs.
	rkB, err := x3dh.ResponderRoot(bob, spkPriv, &opkPriv, pm)
	if err != nil {
		t.Fatalf("ResponderRoot: %v", err)
	}
	if !bytes.Equal(rkA, rkB) {
		t.Fatal("root keys differ (with OPK)")
	}
}
