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

func TestInitiatorAndResponderRoot_NoOneTimePreKey(t *testing.T) {
	// Alice is initiator, Bob is responder.
	alice := makeIdentity(t)
	bob := makeIdentity(t)

	// Bob's signed prekey pair + sig.
	signedPreKeyPrivateKey, signedPreKeyPublicKey, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	signedPreKeySignature := crypto.SignEd25519(bob.EdPriv, signedPreKeyPublicKey[:])

	// Bob publishes a bundle with no OPKs.
	bundle := domain.PreKeyBundle{
		Username:              domain.Username("bob"),
		IdentityKey:           bob.XPub,
		SigningKey:            bob.EdPub,
		SignedPreKeyID:        domain.SignedPreKeyID("spk-test"),
		SignedPreKey:          signedPreKeyPublicKey,
		SignedPreKeySignature: signedPreKeySignature,
		OneTimePreKeys:        nil,
	}

	// Alice derives RK and emits eph pub.
	rootKeyInitiator,
		signedPreKeyID,
		oneTimePreKeyID,
		initiatorEphemeralPublicKey,
		err := x3dh.InitiatorRoot(alice, bundle)
	if err != nil {
		t.Fatalf("InitiatorRoot: %v", err)
	}
	if signedPreKeyID != domain.SignedPreKeyID("spk-test") {
		t.Fatalf("want signed pre-key id spk-test, got %q", signedPreKeyID)
	}
	if oneTimePreKeyID != "" {
		t.Fatalf("want empty one-time pre-key id, got %q", oneTimePreKeyID)
	}

	// Alice's first message would carry this.
	pm := domain.PreKeyMessage{
		InitiatorIdentityKey: alice.XPub,
		EphemeralKey:         initiatorEphemeralPublicKey,
		SignedPreKeyID:       signedPreKeyID,
		OneTimePreKeyID:      oneTimePreKeyID,
	}

	// Bob recomputes the same RK using his SPK private and identity.
	rootKeyResponder, err := x3dh.ResponderRoot(bob, signedPreKeyPrivateKey, nil, pm)
	if err != nil {
		t.Fatalf("ResponderRoot: %v", err)
	}
	if !bytes.Equal(rootKeyInitiator, rootKeyResponder) {
		t.Fatal("root keys differ (no OPK)")
	}
}

func TestInitiatorAndResponderRoot_WithOneTimePreKey(t *testing.T) {
	// Alice is initiator, Bob is responder.
	alice := makeIdentity(t)
	bob := makeIdentity(t)

	// Bob's signed prekey.
	signedPreKeyPrivateKey, signedPreKeyPublicKey, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	signedPreKeySignature := crypto.SignEd25519(bob.EdPriv, signedPreKeyPublicKey[:])

	// Bob has a one-time prekey too.
	oneTimePreKeyPrivateKey, oneTimePreKeyPublicKey, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519 (opk): %v", err)
	}

	bundle := domain.PreKeyBundle{
		Username:              domain.Username("bob"),
		IdentityKey:           bob.XPub,
		SigningKey:            bob.EdPub,
		SignedPreKeyID:        domain.SignedPreKeyID("spk-test"),
		SignedPreKey:          signedPreKeyPublicKey,
		SignedPreKeySignature: signedPreKeySignature,
		OneTimePreKeys: []domain.OneTimePreKeyPublic{
			{ID: domain.OneTimePreKeyID("opk-1"), Pub: oneTimePreKeyPublicKey},
		},
	}

	// Alice picks Bob's OPK and derives RK.
	rootKeyInitiator,
		signedPreKeyID,
		oneTimePreKeyID,
		initiatorEphemeralPublicKey,
		err := x3dh.InitiatorRoot(alice, bundle)
	if err != nil {
		t.Fatalf("InitiatorRoot: %v", err)
	}
	if signedPreKeyID != domain.SignedPreKeyID("spk-test") ||
		oneTimePreKeyID != domain.OneTimePreKeyID("opk-1") {
		t.Fatalf("unexpected IDs signed=%q one-time=%q", signedPreKeyID, oneTimePreKeyID)
	}

	// Alice's first message would carry this.
	pm := domain.PreKeyMessage{
		InitiatorIdentityKey: alice.XPub,
		EphemeralKey:         initiatorEphemeralPublicKey,
		SignedPreKeyID:       signedPreKeyID,
		OneTimePreKeyID:      oneTimePreKeyID,
	}

	// Bob recomputes with SPK and OPK privs.
	rootKeyResponder, err := x3dh.ResponderRoot(
		bob,
		signedPreKeyPrivateKey,
		&oneTimePreKeyPrivateKey,
		pm,
	)
	if err != nil {
		t.Fatalf("ResponderRoot: %v", err)
	}
	if !bytes.Equal(rootKeyInitiator, rootKeyResponder) {
		t.Fatal("root keys differ (with OPK)")
	}
}
