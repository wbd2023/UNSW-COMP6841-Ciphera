package ratchet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"ciphera/internal/domain"
	"ciphera/internal/util/memzero"
)

const (
	aeadKeySize  = 32
	nonceSize    = chacha20poly1305.NonceSize
	maxSkippedMK = 1000
)

var (
	ErrSkippedKeyNotFound = errors.New("skipped message key not found")
	errChainUninitialised = errors.New("ratchet chain key is uninitialised")
)

// InitAsInitiator seeds the sending chain from rk using a fresh ratchet key and the peer identity pub.
func InitAsInitiator(root []byte, _ domain.X25519Private, _ domain.X25519Public, peerIdentity domain.X25519Public) (domain.RatchetState, error) {
	var priv domain.X25519Private
	if _, err := rand.Read(priv[:]); err != nil {
		return domain.RatchetState{}, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pubBytes, err := curve25519.X25519(priv.Slice(), curve25519.Basepoint)
	if err != nil {
		return domain.RatchetState{}, err
	}
	var pub domain.X25519Public
	copy(pub[:], pubBytes)

	dh, err := x25519(priv, peerIdentity)
	if err != nil {
		return domain.RatchetState{}, err
	}
	newRK, sendCK := kdfRK(root, dh[:])
	memzero.Zero(dh[:])

	return domain.RatchetState{
		RootKey:   newRK,
		DHPriv:    priv,
		DHPub:     pub,
		PeerDHPub: peerIdentity, // placeholder until first remote ratchet pub arrives
		SendCK:    sendCK,
		RecvCK:    nil,
		Ns:        0,
		Nr:        0,
		PN:        0,
		Skipped:   make(map[string][]byte),
	}, nil
}

// InitAsResponder seeds the receiving chain from rk using our identity priv and the sender ratchet pub.
func InitAsResponder(root []byte, ourIDPriv domain.X25519Private, _ domain.X25519Public, senderRatchetPub domain.X25519Public) (domain.RatchetState, error) {
	var priv domain.X25519Private
	if _, err := rand.Read(priv[:]); err != nil {
		return domain.RatchetState{}, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pubBytes, err := curve25519.X25519(priv.Slice(), curve25519.Basepoint)
	if err != nil {
		return domain.RatchetState{}, err
	}
	var pub domain.X25519Public
	copy(pub[:], pubBytes)

	dh, err := x25519(ourIDPriv, senderRatchetPub)
	if err != nil {
		return domain.RatchetState{}, err
	}
	newRK, recvCK := kdfRK(root, dh[:])
	memzero.Zero(dh[:])

	return domain.RatchetState{
		RootKey:   newRK,
		DHPriv:    priv,
		DHPub:     pub,
		PeerDHPub: senderRatchetPub,
		SendCK:    nil,
		RecvCK:    recvCK,
		Ns:        0,
		Nr:        0,
		PN:        0,
		Skipped:   make(map[string][]byte),
	}, nil
}

// Encrypt produces a header and ciphertext, auto-stepping the DH ratchet on the first send after responding.
func Encrypt(st *domain.RatchetState, ad, plaintext []byte) (domain.RatchetHeader, []byte, error) {
	// If SendCK is not yet initialised (responder’s first send), perform a DH ratchet step.
	if len(st.SendCK) == 0 {
		st.PN = st.Ns
		st.Ns = 0

		// New sending ratchet key pair.
		var newPriv domain.X25519Private
		if _, err := rand.Read(newPriv[:]); err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		newPriv[0] &= 248
		newPriv[31] &= 127
		newPriv[31] |= 64

		pubBytes, err := curve25519.X25519(newPriv.Slice(), curve25519.Basepoint)
		if err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		var newPub domain.X25519Public
		copy(newPub[:], pubBytes)

		// Advance root and create SendCK using our new priv and the peer’s current ratchet pub.
		dh, err := x25519(newPriv, st.PeerDHPub)
		if err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		rk2, sendCK := kdfRK(st.RootKey, dh[:])
		memzero.Zero(dh[:])

		st.RootKey = rk2
		st.DHPriv, st.DHPub = newPriv, newPub
		st.SendCK = sendCK
	}

	mk, err := kdfCKSend(st)
	if err != nil {
		return domain.RatchetHeader{}, nil, err
	}
	h := domain.RatchetHeader{DHPub: st.DHPub.Slice(), PN: st.PN, N: st.Ns}

	ct, err := seal(mk, h, ad, plaintext)
	memzero.Zero(mk)
	if err != nil {
		return domain.RatchetHeader{}, nil, err
	}
	st.Ns++
	return h, ct, nil
}

// Decrypt handles skipped keys, does DH ratchet on new remote pubs, then opens the message.
func Decrypt(st *domain.RatchetState, ad []byte, header domain.RatchetHeader, ciphertext []byte) ([]byte, error) {
	// Same DH pub: try a skipped key.
	if equal32(st.PeerDHPub[:], header.DHPub) {
		skipUntil(st, header.N)
		keyID := skippedKeyID(st.PeerDHPub, header.N)
		if mk, ok := st.Skipped[keyID]; ok {
			delete(st.Skipped, keyID)
			pt, err := open(mk, header, ad, ciphertext)
			memzero.Zero(mk)
			if err != nil {
				return nil, err
			}
			st.Nr = header.N + 1
			return pt, nil
		}
	}

	// New DH pub: advance receiving and then sending chains.
	if !equal32(st.PeerDHPub[:], header.DHPub) {
		skipUntil(st, header.PN)

		var newPeer domain.X25519Public
		copy(newPeer[:], header.DHPub)

		dh, err := x25519(st.DHPriv, newPeer)
		if err != nil {
			return nil, err
		}
		rk2, recvCK := kdfRK(st.RootKey, dh[:])
		memzero.Zero(dh[:])

		var newPriv domain.X25519Private
		if _, err := rand.Read(newPriv[:]); err != nil {
			return nil, err
		}
		newPriv[0] &= 248
		newPriv[31] &= 127
		newPriv[31] |= 64

		pubBytes, err := curve25519.X25519(newPriv.Slice(), curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		var newPub domain.X25519Public
		copy(newPub[:], pubBytes)

		dh2, err := x25519(newPriv, newPeer)
		if err != nil {
			return nil, err
		}
		rk3, sendCK := kdfRK(rk2, dh2[:])
		memzero.Zero(dh2[:])

		st.PN = st.Ns
		st.Ns, st.Nr = 0, 0
		st.RootKey = rk3
		st.DHPriv, st.DHPub = newPriv, newPub
		st.PeerDHPub = newPeer
		st.SendCK, st.RecvCK = sendCK, recvCK
	}

	mk, err := kdfCKRecv(st)
	if err != nil {
		return nil, err
	}
	pt, err := open(mk, header, ad, ciphertext)
	memzero.Zero(mk)
	if err != nil {
		return nil, err
	}
	st.Nr++
	return pt, nil
}

// --- helpers ---

func seal(mk []byte, header domain.RatchetHeader, ad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(mk[:aeadKeySize])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	binary.BigEndian.PutUint32(nonce[nonceSize-4:], header.N)
	return aead.Seal(nil, nonce, plaintext, append(ad, headerBytes(header)...)), nil
}

func open(mk []byte, header domain.RatchetHeader, ad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(mk[:aeadKeySize])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	binary.BigEndian.PutUint32(nonce[nonceSize-4:], header.N)
	return aead.Open(nil, nonce, ciphertext, append(ad, headerBytes(header)...))
}

func headerBytes(h domain.RatchetHeader) []byte {
	out := make([]byte, 0, len(h.DHPub)+8)
	out = append(out, h.DHPub...)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], h.PN)
	out = append(out, b[:]...)
	binary.BigEndian.PutUint32(b[:], h.N)
	out = append(out, b[:]...)
	return out
}

func x25519(priv domain.X25519Private, pub domain.X25519Public) ([32]byte, error) {
	res, err := curve25519.X25519(priv.Slice(), pub.Slice())
	var out [32]byte
	if err != nil {
		return out, err
	}
	copy(out[:], res)
	return out, nil
}

// HKDF-based KDFs with labels.
func kdfRK(rk, dh []byte) (newRK, ck []byte) {
	r := hkdf.New(sha256.New, dh, rk, []byte("DR|rk"))
	newRK = make([]byte, 32)
	ck = make([]byte, 32)
	_, _ = io.ReadFull(r, newRK)
	_, _ = io.ReadFull(r, ck)
	return
}

func kdfCK(ck []byte) (nextCK, mk []byte) {
	r := hkdf.New(sha256.New, ck, nil, []byte("DR|ck"))
	nextCK = make([]byte, 32)
	mk = make([]byte, 32)
	_, _ = io.ReadFull(r, nextCK)
	_, _ = io.ReadFull(r, mk)
	return
}

func kdfCKSend(st *domain.RatchetState) ([]byte, error) {
	if len(st.SendCK) == 0 {
		return nil, errChainUninitialised
	}
	nextCK, mk := kdfCK(st.SendCK)
	st.SendCK = nextCK
	return mk, nil
}

func kdfCKRecv(st *domain.RatchetState) ([]byte, error) {
	if len(st.RecvCK) == 0 {
		return nil, errChainUninitialised
	}
	nextCK, mk := kdfCK(st.RecvCK)
	st.RecvCK = nextCK
	return mk, nil
}

func skippedKeyID(peer domain.X25519Public, n uint32) string {
	b := make([]byte, 32+4)
	copy(b, peer[:])
	binary.BigEndian.PutUint32(b[32:], n)
	return string(b)
}

// skipUntil derives and stores message keys up to pn with a hard cap.
func skipUntil(st *domain.RatchetState, pn uint32) {
	for st.Nr < pn {
		mk, _ := kdfCKRecv(st)
		if len(st.Skipped) >= maxSkippedMK {
			for k := range st.Skipped {
				delete(st.Skipped, k)
				break
			}
		}
		st.Skipped[skippedKeyID(st.PeerDHPub, st.Nr)] = mk
		st.Nr++
	}
}

func equal32(a, b []byte) bool {
	if len(a) != 32 || len(b) != 32 {
		return false
	}
	var v byte
	for i := 0; i < 32; i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
