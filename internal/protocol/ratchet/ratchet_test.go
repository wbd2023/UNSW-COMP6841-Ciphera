package ratchet_test

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	mrand "math/rand"
	"strconv"
	"testing"
	"time"

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

// newPair returns an initiator and responder ratchet state, ready for use.
func newPair(t *testing.T) (a, b domain.RatchetState) {
	t.Helper()
	// Shared root key from a prior X3DH (simulate).
	rk := bytes.Repeat([]byte{0x42}, 32)

	// Two parties (A initiates).
	aPriv, aPub := makeIdentity(t)
	bPriv, bPub := makeIdentity(t)

	// Initiator seeds SendCK using peer identity.
	init, err := ratchet.InitAsInitiator(rk, aPriv, aPub, bPub)
	if err != nil {
		t.Fatalf("InitAsInitiator: %v", err)
	}

	// Responder seeds RecvCK using its identity and sender's current ratchet pub.
	resp, err := ratchet.InitAsResponder(rk, bPriv, bPub, init.DiffieHellmanPublic)
	if err != nil {
		t.Fatalf("InitAsResponder: %v", err)
	}

	return init, resp
}

// send is a thin wrapper around Encrypt for tests.
func send(
	t *testing.T,
	st *domain.RatchetState,
	ad []byte,
	msg []byte,
) (domain.RatchetHeader, []byte) {
	t.Helper()
	h, ct, err := ratchet.Encrypt(st, ad, msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return h, ct
}

// recv is a thin wrapper around Decrypt for tests.
func recv(
	t *testing.T,
	st *domain.RatchetState,
	ad []byte,
	h domain.RatchetHeader,
	ct []byte,
) []byte {
	t.Helper()
	pt, err := ratchet.Decrypt(st, ad, h, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	return pt
}

func TestDoubleRatchet_RoundTrip_Simple(t *testing.T) {
	// Shared root key from a prior X3DH (simulate).
	a, b := newPair(t)

	header, ct := send(t, &a, nil, []byte("hi"))
	pt := recv(t, &b, nil, header, ct)
	if string(pt) != "hi" {
		t.Fatalf("got %q, want %q", pt, "hi")
	}
}

func TestDoubleRatchet_RoundTrip_Table(t *testing.T) {
	a, b := newPair(t)

	tests := []struct {
		name string
		ad   []byte
		msg  []byte
	}{
		{name: "empty", ad: nil, msg: nil},
		{name: "small", ad: nil, msg: []byte("hello")},
		{name: "unicode", ad: []byte("meta"), msg: []byte("こんにちは 👋")},
		{name: "binary_128", ad: nil, msg: bytes.Repeat([]byte{0xAB}, 128)},
		{name: "binary_4k", ad: []byte{1, 2, 3}, msg: bytes.Repeat([]byte{0xCD}, 4096)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, ct := send(t, &a, tc.ad, tc.msg)
			got := recv(t, &b, tc.ad, h, ct)
			if !bytes.Equal(got, tc.msg) {
				t.Fatalf("mismatch: got %q want %q", got, tc.msg)
			}
		})
	}
}

func TestDoubleRatchet_OutOfOrder_WithinChain_UsesSkippedKeys(t *testing.T) {
	a, b := newPair(t)

	// A sends two messages in the same chain.
	h1, ct1 := send(t, &a, nil, []byte("first"))
	h2, ct2 := send(t, &a, nil, []byte("second"))

	// Deliver the second first. Receiver should derive and stash the key for N=0, then decrypt N=1.
	got2 := recv(t, &b, nil, h2, ct2)
	if string(got2) != "second" {
		t.Fatalf("got %q, want %q", got2, "second")
	}

	// Now deliver the first. Receiver should consume the stashed skipped key.
	got1 := recv(t, &b, nil, h1, ct1)
	if string(got1) != "first" {
		t.Fatalf("got %q, want %q", got1, "first")
	}
}

func TestDoubleRatchet_OutOfOrderAndLoss(t *testing.T) {
	a, b := newPair(t)

	type pkt struct {
		h   domain.RatchetHeader
		ct  []byte
		lbl string
	}
	var pkts []pkt
	for i := 0; i < 30; i++ {
		lbl := "msg-" + strconv.Itoa(i)
		h, ct := send(t, &a, nil, []byte(lbl))
		pkts = append(pkts, pkt{h: h, ct: ct, lbl: lbl})
	}

	// Shuffle to simulate reordering.
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(pkts), func(i, j int) { pkts[i], pkts[j] = pkts[j], pkts[i] })

	// Drop about 20 percent to simulate loss.
	var delivered []pkt
	for _, p := range pkts {
		if r.Intn(5) != 0 {
			delivered = append(delivered, p)
		}
	}

	// Deliver to B.
	for _, p := range delivered {
		got := recv(t, &b, nil, p.h, p.ct)
		if string(got) != p.lbl {
			t.Fatalf("out-of-order: got %q want %q", got, p.lbl)
		}
	}

	// B should be able to continue receiving future messages after gaps.
	h, ct := send(t, &a, nil, []byte("after-gaps"))
	got := recv(t, &b, nil, h, ct)
	if string(got) != "after-gaps" {
		t.Fatalf("post-gap decrypt failed: %q", got)
	}
}

func TestDoubleRatchet_AssociatedData_PositiveAndNegative(t *testing.T) {
	a, b := newPair(t)

	ad1 := []byte("header-meta-v1")
	ad2 := []byte("header-meta-v2")

	// Correct AD.
	h, ct := send(t, &a, ad1, []byte("secret"))
	got := recv(t, &b, ad1, h, ct)
	if string(got) != "secret" {
		t.Fatalf("AD correct: got %q", got)
	}

	// Wrong AD must fail.
	if _, err := ratchet.Decrypt(&b, ad2, h, ct); err == nil {
		t.Fatalf("want error with wrong AD, got nil")
	}
}

func TestDoubleRatchet_TamperDetection(t *testing.T) {
	a, b := newPair(t)

	h, ct := send(t, &a, []byte("ad"), []byte("payload"))

	// Flip a byte in ciphertext.
	ctBad := append([]byte(nil), ct...)
	ctBad[len(ctBad)/2] ^= 0x80
	if _, err := ratchet.Decrypt(&b, []byte("ad"), h, ctBad); err == nil {
		t.Fatalf("want error on tampered ciphertext, got nil")
	}

	// Corrupt header.DiffieHellmanPublicKey to ensure header is bound in AEAD.
	hBad := h
	if len(hBad.DiffieHellmanPublicKey) > 0 {
		hBad.DiffieHellmanPublicKey[0] ^= 0x01
	}
	if _, err := ratchet.Decrypt(&b, []byte("ad"), hBad, ct); err == nil {
		t.Fatalf("want error on tampered header, got nil")
	}
}

func TestDoubleRatchet_ReplayProtection(t *testing.T) {
	a, b := newPair(t)

	h, ct := send(t, &a, nil, []byte("once"))

	// First delivery succeeds.
	if _, err := ratchet.Decrypt(&b, nil, h, ct); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}

	// Replay should fail because the receive chain has advanced.
	if _, err := ratchet.Decrypt(&b, nil, h, ct); err == nil {
		t.Fatalf("want replay error, got nil")
	}
}

func TestDoubleRatchet_SimultaneousSending(t *testing.T) {
	a, b := newPair(t)

	// Both parties send before receiving the other. Responder should lazily set up SendCK.
	hA1, ctA1 := send(t, &a, nil, []byte("A1"))
	hB1, ctB1 := send(t, &b, nil, []byte("B1"))

	gotAtA := recv(t, &a, nil, hB1, ctB1)
	gotAtB := recv(t, &b, nil, hA1, ctA1)

	if string(gotAtA) != "B1" || string(gotAtB) != "A1" {
		t.Fatalf("simultaneous send mismatch: gotAtA=%q gotAtB=%q", gotAtA, gotAtB)
	}

	// Continue a couple of messages to ensure both chains are consistent.
	hA2, ctA2 := send(t, &a, nil, []byte("A2"))
	hB2, ctB2 := send(t, &b, nil, []byte("B2"))
	_ = recv(t, &b, nil, hA2, ctA2)
	_ = recv(t, &a, nil, hB2, ctB2)
}

func TestDoubleRatchet_LargePayload(t *testing.T) {
	a, b := newPair(t)

	large := make([]byte, 1<<20) // 1 MiB
	if _, err := crand.Read(large); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	h, ct := send(t, &a, nil, large)
	got := recv(t, &b, nil, h, ct)
	if !bytes.Equal(got, large) {
		t.Fatalf("large payload mismatch")
	}
}

func TestDoubleRatchet_RejectsExcessiveWithinChainGap(t *testing.T) {
	a, b := newPair(t)

	// Establish chain.
	h1, ct1 := send(t, &a, nil, []byte("ok"))
	_ = recv(t, &b, nil, h1, ct1)

	// Take a valid header, then inflate N to a huge value to trigger gap cap.
	h, ct := send(t, &a, nil, []byte("big-gap"))
	h.MessageIndex = 1 << 20

	_, err := ratchet.Decrypt(&b, nil, h, ct)
	if !errors.Is(err, ratchet.ErrGapTooLarge) {
		t.Fatalf("want ErrGapTooLarge, got %v", err)
	}
}

func TestDoubleRatchet_RejectsExcessivePrevChainGap(t *testing.T) {
	a, b := newPair(t)

	// Forge a "new peer key" by tweaking header.DiffieHellmanPublicKey and set a huge PN.
	h, ct := send(t, &a, nil, []byte("pn-gap"))
	if len(h.DiffieHellmanPublicKey) == 0 {
		t.Fatalf("empty dhpub")
	}
	h.DiffieHellmanPublicKey[0] ^= 0x01 // force peer DH change
	h.PreviousChainLength = 1 << 20     // excessive previous-chain gap

	_, err := ratchet.Decrypt(&b, nil, h, ct)
	if !errors.Is(err, ratchet.ErrGapTooLarge) {
		t.Fatalf("want ErrGapTooLarge, got %v", err)
	}
}

func TestDoubleRatchet_InvalidHeaderLength(t *testing.T) {
	a, b := newPair(t)

	h, ct := send(t, &a, nil, []byte("x"))
	trim := len(h.DiffieHellmanPublicKey) - 1
	h.DiffieHellmanPublicKey = h.DiffieHellmanPublicKey[:trim] // make it 31 bytes

	if _, err := ratchet.Decrypt(&b, nil, h, ct); err == nil {
		t.Fatalf("want error for invalid dh_pub length, got nil")
	}
}

func TestDoubleRatchet_LazySendDoesNotChangeNr(t *testing.T) {
	a, b := newPair(t)

	// Make B receive once to bump ReceiveMessageIndex.
	h1, ct1 := send(t, &a, nil, []byte("hello"))
	_ = recv(t, &b, nil, h1, ct1)
	before := b.ReceiveMessageIndex

	// B's first send lazily sets up SendChainKey.
	// ReceiveMessageIndex must not change.
	_, _, err := ratchet.Encrypt(&b, nil, []byte("ping"))
	if err != nil {
		t.Fatalf("encrypt at B: %v", err)
	}
	if b.ReceiveMessageIndex != before {
		t.Fatalf(
			"ReceiveMessageIndex changed on lazy send: got %d, want %d",
			b.ReceiveMessageIndex,
			before,
		)
	}
}

func TestDoubleRatchet_OldOrReplayErrorDoesNotAdvance(t *testing.T) {
	a, b := newPair(t)

	h, ct := send(t, &a, nil, []byte("once"))
	// First decrypt advances ReceiveMessageIndex by 1.
	if _, err := ratchet.Decrypt(&b, nil, h, ct); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	nr := b.ReceiveMessageIndex

	// Second decrypt should return ErrOldOrReplay and leave
	// ReceiveMessageIndex unchanged.
	_, err := ratchet.Decrypt(&b, nil, h, ct)
	if !errors.Is(err, ratchet.ErrOldOrReplay) {
		t.Fatalf("want ErrOldOrReplay, got %v", err)
	}
	if b.ReceiveMessageIndex != nr {
		t.Fatalf(
			"ReceiveMessageIndex changed after old/replay attempt: got %d, want %d",
			b.ReceiveMessageIndex,
			nr,
		)
	}
}

func TestDoubleRatchet_HeaderTamperSmallPNAndN(t *testing.T) {
	a, b := newPair(t)

	h, ct := send(t, &a, nil, []byte("hdr-bound"))
	h.PreviousChainLength ^= 1 // small change
	if _, err := ratchet.Decrypt(&b, nil, h, ct); err == nil {
		t.Fatalf("want error on PN tamper, got nil")
	}

	// Recreate a valid packet then tamper N by +/-1.
	h2, ct2 := send(t, &a, nil, []byte("hdr-bound-2"))
	h2.MessageIndex ^= 1
	if _, err := ratchet.Decrypt(&b, nil, h2, ct2); err == nil {
		t.Fatalf("want error on N tamper, got nil")
	}
}
