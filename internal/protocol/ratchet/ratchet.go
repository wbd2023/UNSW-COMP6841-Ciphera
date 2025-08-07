// Package ratchet implements the Double Ratchet algorithm following Signal’s design.
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

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

const (
	aeadKeySize  = chacha20poly1305.KeySize
	nonceSize    = chacha20poly1305.NonceSize
	maxSkippedMK = 1000
)

var (
	errChainUninitialised        = errors.New("ratchet chain key uninitialised")
	ErrSkippedMessageKeyNotFound = errors.New("skipped message key not found")
)

// InitAsInitiator initialises the ratchet state for the sender, deriving only the send chain key
// from the given root and peer identity.
func InitAsInitiator(
	root []byte,
	_ domain.X25519Private,
	_ domain.X25519Public,
	peerIdentity domain.X25519Public,
) (domain.RatchetState, error) {
	// Generate ephemeral key
	var priv domain.X25519Private
	if _, err := rand.Read(priv[:]); err != nil {
		return domain.RatchetState{}, err
	}
	crypto.ClampX25519PrivateKey(&priv)

	pubBytes, err := curve25519.X25519(priv.Slice(), curve25519.Basepoint)
	if err != nil {
		return domain.RatchetState{}, err
	}
	var pub domain.X25519Public
	copy(pub[:], pubBytes)

	// Single DH: EK_A ⋅ IK_B
	dh, err := crypto.DH(priv, peerIdentity)
	if err != nil {
		return domain.RatchetState{}, err
	}
	newRoot, sendCK := kdfRK(root, dh[:])
	crypto.Wipe(dh[:])

	return domain.RatchetState{
		RootKey:   newRoot,
		DHPriv:    priv,
		DHPub:     pub,
		PeerDHPub: peerIdentity,
		SendCK:    sendCK,
		Skipped:   make(map[string][]byte),
	}, nil
}

// InitAsResponder initialises the ratchet state for the receiver, deriving only the receive chain
// key from the given root and sender’s ratchet pub.
func InitAsResponder(
	root []byte,
	ourIDPriv domain.X25519Private,
	_ domain.X25519Public,
	senderRatchetPub domain.X25519Public,
) (domain.RatchetState, error) {
	// Generate ephemeral key
	var priv domain.X25519Private
	if _, err := rand.Read(priv[:]); err != nil {
		return domain.RatchetState{}, err
	}
	crypto.ClampX25519PrivateKey(&priv)

	pubBytes, err := curve25519.X25519(priv.Slice(), curve25519.Basepoint)
	if err != nil {
		return domain.RatchetState{}, err
	}
	var pub domain.X25519Public
	copy(pub[:], pubBytes)

	// Single DH: IK_B ⋅ EK_A
	dh, err := crypto.DH(ourIDPriv, senderRatchetPub)
	if err != nil {
		return domain.RatchetState{}, err
	}
	newRoot, recvCK := kdfRK(root, dh[:])
	crypto.Wipe(dh[:])

	return domain.RatchetState{
		RootKey:   newRoot,
		DHPriv:    priv,
		DHPub:     pub,
		PeerDHPub: senderRatchetPub,
		RecvCK:    recvCK,
		Skipped:   make(map[string][]byte),
	}, nil
}

// Encrypt encrypts plaintext under the send chain, performing a lazy ratchet step on the first send
// when SendCK is nil.
func Encrypt(
	st *domain.RatchetState,
	ad, plaintext []byte,
) (domain.RatchetHeader, []byte, error) {
	if st == nil {
		return domain.RatchetHeader{}, nil, errors.New("ratchet state uninitialised")
	}

	// Lazy responder ratchet
	if st.SendCK == nil {
		st.PN = st.Ns
		st.Ns, st.Nr = 0, 0

		var priv domain.X25519Private
		if _, err := rand.Read(priv[:]); err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		crypto.ClampX25519PrivateKey(&priv)

		pubBytes, err := curve25519.X25519(priv.Slice(), curve25519.Basepoint)
		if err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		var pub domain.X25519Public
		copy(pub[:], pubBytes)

		dh, err := crypto.DH(priv, st.PeerDHPub)
		if err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		newRoot, sendCK := kdfRK(st.RootKey, dh[:])
		crypto.Wipe(dh[:])

		st.RootKey, st.DHPriv, st.DHPub, st.SendCK = newRoot, priv, pub, sendCK
	}

	mk, err := kdfCKSend(st)
	if err != nil {
		return domain.RatchetHeader{}, nil, err
	}

	header := domain.RatchetHeader{
		DHPub: st.DHPub.Slice(),
		PN:    st.PN,
		N:     st.Ns,
	}
	ct, err := seal(mk, header, ad, plaintext)
	crypto.Wipe(mk)
	if err != nil {
		return domain.RatchetHeader{}, nil, err
	}

	st.Ns++
	return header, ct, nil
}

// Decrypt decrypts ciphertext, handling skipped keys and ratchet steps.
func Decrypt(
	st *domain.RatchetState,
	ad []byte,
	header domain.RatchetHeader,
	ciphertext []byte,
) ([]byte, error) {
	if st == nil {
		return nil, errors.New("ratchet state uninitialised")
	}

	// Try skipped messages
	skipUntil(st, header.PN)
	keyID := skippedKeyID(st.PeerDHPub, header.N)
	if mk, ok := st.Skipped[keyID]; ok {
		delete(st.Skipped, keyID)
		pt, err := open(mk, header, ad, ciphertext)
		crypto.Wipe(mk)
		if err != nil {
			return nil, err
		}
		st.Nr = header.N + 1
		return pt, nil
	}

	// New ratchet step?
	if !equal32(st.PeerDHPub.Slice(), header.DHPub) {
		var peer domain.X25519Public
		copy(peer[:], header.DHPub)

		dh, err := crypto.DH(st.DHPriv, peer)
		if err != nil {
			return nil, err
		}
		newRoot, recvCK := kdfRK(st.RootKey, dh[:])
		crypto.Wipe(dh[:])

		var priv domain.X25519Private
		if _, err := rand.Read(priv[:]); err != nil {
			return nil, err
		}
		crypto.ClampX25519PrivateKey(&priv)

		pubBytes, err := curve25519.X25519(priv.Slice(), curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		var pub domain.X25519Public
		copy(pub[:], pubBytes)

		dh2, err := crypto.DH(priv, peer)
		if err != nil {
			return nil, err
		}
		rk2, sendCK := kdfRK(newRoot, dh2[:])
		crypto.Wipe(dh2[:])

		st.PN, st.Ns, st.Nr = st.Ns, 0, 0
		st.RootKey, st.DHPriv, st.DHPub, st.PeerDHPub, st.SendCK, st.RecvCK = rk2, priv, pub, peer, sendCK, recvCK
		st.Skipped = make(map[string][]byte)
	}

	mk, err := kdfCKRecv(st)
	if err != nil {
		return nil, err
	}
	pt, err := open(mk, header, ad, ciphertext)
	crypto.Wipe(mk)
	if err != nil {
		return nil, err
	}
	st.Nr++
	return pt, nil
}

// --- Helpers ---

// kdfRK derives a new root key and chain key from the DH output.
func kdfRK(root, dh []byte) (newRoot, ck []byte) {
	hk := hkdf.New(sha256.New, dh, root, []byte("DR|rk"))
	newRoot = make([]byte, 32)
	ck = make([]byte, 32)
	io.ReadFull(hk, newRoot)
	io.ReadFull(hk, ck)
	return
}

// kdfCKSend advances the send-chain key, returning the next message key.
func kdfCKSend(st *domain.RatchetState) ([]byte, error) {
	if st.SendCK == nil {
		return nil, errChainUninitialised
	}
	hk := hkdf.New(sha256.New, st.SendCK, nil, []byte("DR|ck"))
	nextCK := make([]byte, 32)
	mk := make([]byte, 32)
	io.ReadFull(hk, nextCK)
	io.ReadFull(hk, mk)
	st.SendCK = nextCK
	return mk, nil
}

// kdfCKRecv advances the receive-chain key, returning the next message key.
func kdfCKRecv(st *domain.RatchetState) ([]byte, error) {
	if st.RecvCK == nil {
		return nil, errChainUninitialised
	}
	hk := hkdf.New(sha256.New, st.RecvCK, nil, []byte("DR|ck"))
	nextCK := make([]byte, 32)
	mk := make([]byte, 32)
	io.ReadFull(hk, nextCK)
	io.ReadFull(hk, mk)
	st.RecvCK = nextCK
	return mk, nil
}

// seal encrypts plaintext with ChaCha20-Poly1305 using header||PN as associated data.
func seal(mk []byte, header domain.RatchetHeader, ad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(mk[:aeadKeySize])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	binary.BigEndian.PutUint32(nonce[nonceSize-4:], header.N)
	return aead.Seal(nil, nonce, plaintext, append(ad, headerBytes(header)...)), nil
}

// open decrypts ciphertext with ChaCha20-Poly1305.
func open(mk []byte, header domain.RatchetHeader, ad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(mk[:aeadKeySize])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	binary.BigEndian.PutUint32(nonce[nonceSize-4:], header.N)
	return aead.Open(nil, nonce, ciphertext, append(ad, headerBytes(header)...))
}

// headerBytes serializes PN and N into big-endian bytes appended after DHPub.
func headerBytes(h domain.RatchetHeader) []byte {
	var tmp [4]byte
	out := append([]byte{}, h.DHPub...)
	binary.BigEndian.PutUint32(tmp[:], h.PN)
	out = append(out, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:], h.N)
	return append(out, tmp[:]...)
}

// skipUntil derives and stores skipped message keys up to pn.
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

// skippedKeyID yields a unique map key from peerDHPub||n.
func skippedKeyID(pub domain.X25519Public, n uint32) string {
	var buf [36]byte
	copy(buf[:32], pub[:])
	binary.BigEndian.PutUint32(buf[32:], n)
	return string(buf[:])
}

// equal32 compares two 32-byte slices in constant time.
func equal32(a, b []byte) bool {
	if len(a) != 32 || len(b) != 32 {
		return false
	}
	var v byte
	for i := range 32 {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
