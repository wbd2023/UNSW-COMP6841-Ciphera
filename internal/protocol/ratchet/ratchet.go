package ratchet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

const (
	aeadKeySize       = chacha20poly1305.KeySize
	nonceSize         = chacha20poly1305.NonceSize
	maxSkippedMK      = 1000 // maximum number of skipped message keys to retain
	maxGapWithinChain = 2000 // in-chain gap cap (Nr..N-1)
	maxPrevChainGap   = 2000 // previous-chain gap cap (PN)
	x25519PubSize     = 32
	headerIntsSize    = 8 // PN (4) + N (4)
)

var (
	labelRK    = []byte("DR|rk")
	labelCK    = []byte("DR|ck") // single label for both send and receive chains
	labelNonce = []byte("DR|nonce")
)

var (
	// ErrChainUninitialised indicates SendCK or RecvCK is nil when it is required.
	ErrChainUninitialised = errors.New("ratchet chain key uninitialised")
	// ErrGapTooLarge indicates header.N or header.PN requires advancing beyond configured caps.
	ErrGapTooLarge = errors.New("ratchet message gap too large")
	// ErrOldOrReplay indicates header.N older than current receive index and no skipped key exists.
	ErrOldOrReplay = errors.New("ratchet old or replayed message")
)

/* --------------------------------------- Initialisation --------------------------------------- */

// InitAsInitiator initialises state for a sender.
//
// It derives only the send chain key from the supplied root and the peer's long-term identity key.
// The initiator creates a fresh Diffie-Hellman (DH) key pair for its ratchet key.
func InitAsInitiator(
	root []byte,
	_ domain.X25519Private,
	_ domain.X25519Public,
	peerIdentity domain.X25519Public,
) (domain.RatchetState, error) {
	var privateKey domain.X25519Private
	if _, err := rand.Read(privateKey[:]); err != nil {
		return domain.RatchetState{}, err
	}
	crypto.ClampX25519PrivateKey(&privateKey)

	publicKeyBytes, err := curve25519.X25519(privateKey.Slice(), curve25519.Basepoint)
	if err != nil {
		return domain.RatchetState{}, err
	}
	var publicKey domain.X25519Public
	copy(publicKey[:], publicKeyBytes)

	// Single DH: EK_A · IK_B.
	diffieHellmanOutput, err := crypto.DH(privateKey, peerIdentity)
	if err != nil {
		return domain.RatchetState{}, err
	}
	newRootKey, sendChainKey, err := kdfRK(root, diffieHellmanOutput[:])
	if err != nil {
		return domain.RatchetState{}, err
	}
	crypto.Wipe(diffieHellmanOutput[:])

	return domain.RatchetState{
		RootKey:   append([]byte(nil), newRootKey...),
		DHPriv:    privateKey,
		DHPub:     publicKey,
		PeerDHPub: peerIdentity,
		SendCK:    append([]byte(nil), sendChainKey...),
		Skipped:   make(map[string][]byte),
	}, nil
}

// InitAsResponder initialises state for a receiver.
//
// It derives only the receive chain key from the supplied root and the sender's ratchet public key.
// The responder also creates a fresh ratchet key pair for its next send.
func InitAsResponder(
	root []byte,
	ourIdentityPrivate domain.X25519Private,
	_ domain.X25519Public,
	senderRatchetPublic domain.X25519Public,
) (domain.RatchetState, error) {
	var privateKey domain.X25519Private
	if _, err := rand.Read(privateKey[:]); err != nil {
		return domain.RatchetState{}, err
	}
	crypto.ClampX25519PrivateKey(&privateKey)

	publicKeyBytes, err := curve25519.X25519(privateKey.Slice(), curve25519.Basepoint)
	if err != nil {
		return domain.RatchetState{}, err
	}
	var publicKey domain.X25519Public
	copy(publicKey[:], publicKeyBytes)

	// Single DH: IK_B · EK_A.
	diffieHellmanOutput, err := crypto.DH(ourIdentityPrivate, senderRatchetPublic)
	if err != nil {
		return domain.RatchetState{}, err
	}
	newRootKey, receiveChainKey, err := kdfRK(root, diffieHellmanOutput[:])
	if err != nil {
		return domain.RatchetState{}, err
	}
	crypto.Wipe(diffieHellmanOutput[:])

	return domain.RatchetState{
		RootKey:   append([]byte(nil), newRootKey...),
		DHPriv:    privateKey,
		DHPub:     publicKey,
		PeerDHPub: senderRatchetPublic,
		RecvCK:    append([]byte(nil), receiveChainKey...),
		Skipped:   make(map[string][]byte),
	}, nil
}

/* -------------------------------------------- Send -------------------------------------------- */

// Encrypt encrypts plaintext using the send chain.
//
// If SendCK is nil, a lazy ratchet step is performed first to set up the sending chain.
// State is mutated in place. Not safe for concurrent use.
func Encrypt(
	state *domain.RatchetState,
	associatedData []byte,
	plaintext []byte,
) (domain.RatchetHeader, []byte, error) {
	if state == nil {
		return domain.RatchetHeader{}, nil, errors.New("ratchet state uninitialised")
	}

	// First send by the responder: perform a sending ratchet step.
	if state.SendCK == nil {
		// Do not change the receive counter here.
		state.PN, state.Ns = state.Ns, 0

		var nextPrivateKey domain.X25519Private
		if _, err := rand.Read(nextPrivateKey[:]); err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		crypto.ClampX25519PrivateKey(&nextPrivateKey)

		nextPublicKeyBytes, err := curve25519.X25519(nextPrivateKey.Slice(), curve25519.Basepoint)
		if err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		var nextPublicKey domain.X25519Public
		copy(nextPublicKey[:], nextPublicKeyBytes)

		diffieHellmanOutput, err := crypto.DH(nextPrivateKey, state.PeerDHPub)
		if err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		newRootKey, sendChainKey, err := kdfRK(state.RootKey, diffieHellmanOutput[:])
		if err != nil {
			return domain.RatchetHeader{}, nil, err
		}
		crypto.Wipe(diffieHellmanOutput[:])

		// Replace secrets with wiping.
		wipeAndCopy(&state.RootKey, newRootKey)
		crypto.Wipe(state.DHPriv[:])
		state.DHPriv = nextPrivateKey
		state.DHPub = nextPublicKey
		wipeAndCopy(&state.SendCK, sendChainKey)
	}

	messageKey, err := kdfCKSend(state)
	if err != nil {
		return domain.RatchetHeader{}, nil, err
	}

	header := domain.RatchetHeader{
		DHPub: append([]byte(nil), state.DHPub.Slice()...),
		PN:    state.PN,
		N:     state.Ns,
	}

	// AAD binds the header to the ciphertext.
	aad := composeAAD(associatedData, header)

	ciphertext, err := seal(messageKey, header, aad, plaintext)
	crypto.Wipe(messageKey)
	if err != nil {
		return domain.RatchetHeader{}, nil, err
	}

	state.Ns++
	return header, ciphertext, nil
}

/* ------------------------------------------- Receive ------------------------------------------ */

// Decrypt decrypts a message using the receive chain.
//
// It performs peer ratchet steps and uses skipped keys when necessary.
// State is mutated in place. Not safe for concurrent use.
func Decrypt(
	state *domain.RatchetState,
	associatedData []byte,
	header domain.RatchetHeader,
	ciphertext []byte,
) ([]byte, error) {
	if state == nil {
		return nil, errors.New("ratchet state uninitialised")
	}
	// Quick header validation.
	if len(header.DHPub) != x25519PubSize {
		return nil, errors.New("invalid header: dh_pub length")
	}

	// Copy header public key into our fixed-size type.
	var headerPublicKey domain.X25519Public
	copy(headerPublicKey[:], header.DHPub)

	keyID := skippedKeyID(headerPublicKey, header.N)

	// 1) If we have a stashed key for this exact (DHPub, N), try it immediately.
	if messageKey, ok := state.Skipped[keyID]; ok {
		aad := composeAAD(associatedData, header)

		plaintext, err := open(messageKey, header, aad, ciphertext)
		crypto.Wipe(messageKey)
		if err != nil {
			return nil, err // Keep skipped key on failed auth for later correct packet.
		}
		wipeAndDelete(state.Skipped, keyID) // enforce single-use
		return plaintext, nil               // Do not advance Nr when consuming a skipped key.
	}

	// Determine whether this header belongs to the current receive chain.
	sameChain := subtle.ConstantTimeCompare(state.PeerDHPub.Slice(), headerPublicKey.Slice()) == 1

	// 2) In-chain checks only when the peer DH has not changed.
	if sameChain {
		// Fail fast on excessive within-chain gaps to avoid unbounded work.
		if header.N > state.Nr && header.N-state.Nr > maxGapWithinChain {
			return nil, ErrGapTooLarge
		}
		// If this message is older than what we've processed in this chain, reject it.
		if header.N < state.Nr {
			return nil, ErrOldOrReplay
		}
	}

	// 3) Peer ratchet step if the sender's ratchet public key changed.
	if !sameChain {
		// Fail fast on excessive PN gap before stashing skipped keys.
		if header.PN > state.Nr && header.PN-state.Nr > maxPrevChainGap {
			return nil, ErrGapTooLarge
		}

		// Stash remaining keys from the previous chain up to PN.
		skipUntil(state, header.PN)

		peerPublicKey := headerPublicKey // by value

		diffieHellmanOutput, err := crypto.DH(state.DHPriv, peerPublicKey)
		if err != nil {
			return nil, err
		}
		newRootKey, receiveChainKey, err := kdfRK(state.RootKey, diffieHellmanOutput[:])
		if err != nil {
			return nil, err
		}
		crypto.Wipe(diffieHellmanOutput[:])

		var nextPrivateKey domain.X25519Private
		if _, err := rand.Read(nextPrivateKey[:]); err != nil {
			return nil, err
		}
		crypto.ClampX25519PrivateKey(&nextPrivateKey)

		nextPublicKeyBytes, err := curve25519.X25519(nextPrivateKey.Slice(), curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		var nextPublicKey domain.X25519Public
		copy(nextPublicKey[:], nextPublicKeyBytes)

		diffieHellmanOutput2, err := crypto.DH(nextPrivateKey, peerPublicKey)
		if err != nil {
			return nil, err
		}
		nextRootKey, sendChainKey, err := kdfRK(newRootKey, diffieHellmanOutput2[:])
		if err != nil {
			return nil, err
		}
		crypto.Wipe(diffieHellmanOutput2[:])

		state.PN, state.Ns, state.Nr = state.Ns, 0, 0
		wipeAndCopy(&state.RootKey, nextRootKey)
		crypto.Wipe(state.DHPriv[:])
		state.DHPriv = nextPrivateKey
		state.DHPub = nextPublicKey
		state.PeerDHPub = peerPublicKey
		wipeAndCopy(&state.SendCK, sendChainKey)
		wipeAndCopy(&state.RecvCK, receiveChainKey)
		// Keep state.Skipped so late packets from the previous chain remain decryptable.
	}

	// 4) Derive and stash skipped keys for messages in (Nr..N-1).
	for state.Nr < header.N {
		skippedMessageKey, _ := kdfCKRecv(state) // RecvCK initialised; error not expected
		if len(state.Skipped) >= maxSkippedMK {
			evictOldestForPeer(state.Skipped, state.PeerDHPub)
		}
		state.Skipped[skippedKeyID(state.PeerDHPub, state.Nr)] = skippedMessageKey
		state.Nr++
	}

	// 5) Decrypt the target message at N.
	messageKey, err := kdfCKRecv(state)
	if err != nil {
		return nil, err
	}

	aad := composeAAD(associatedData, header)

	plaintext, err := open(messageKey, header, aad, ciphertext)
	crypto.Wipe(messageKey)
	if err != nil {
		return nil, err
	}
	state.Nr++
	return plaintext, nil
}

/* ----------------------------------------- KDF helpers ---------------------------------------- */

// kdfRK derives a new root key and a chain key from the previous root and a DH output.
func kdfRK(root, diffieHellmanOutput []byte) (newRootKey, chainKey []byte, err error) {
	hk := hkdf.New(sha256.New, diffieHellmanOutput, root, labelRK)
	newRootKey = make([]byte, 32)
	chainKey = make([]byte, 32)
	if err = readFull(hk, newRootKey); err != nil {
		return nil, nil, err
	}
	if err = readFull(hk, chainKey); err != nil {
		return nil, nil, err
	}
	return
}

// kdfCKSend advances the send chain and returns the next message key.
func kdfCKSend(state *domain.RatchetState) ([]byte, error) {
	if state.SendCK == nil {
		return nil, ErrChainUninitialised
	}
	hk := hkdf.New(sha256.New, state.SendCK, nil, labelCK)
	nextChainKey := make([]byte, 32)
	messageKey := make([]byte, 32)
	if err := readFull(hk, nextChainKey); err != nil {
		return nil, err
	}
	if err := readFull(hk, messageKey); err != nil {
		return nil, err
	}
	crypto.Wipe(state.SendCK)
	state.SendCK = nextChainKey
	return messageKey, nil
}

// kdfCKRecv advances the receive chain and returns the next message key.
func kdfCKRecv(state *domain.RatchetState) ([]byte, error) {
	if state.RecvCK == nil {
		return nil, ErrChainUninitialised
	}
	hk := hkdf.New(sha256.New, state.RecvCK, nil, labelCK)
	nextChainKey := make([]byte, 32)
	messageKey := make([]byte, 32)
	if err := readFull(hk, nextChainKey); err != nil {
		return nil, err
	}
	if err := readFull(hk, messageKey); err != nil {
		return nil, err
	}
	crypto.Wipe(state.RecvCK)
	state.RecvCK = nextChainKey
	return messageKey, nil
}

/* ------------------------------------- AEAD/nonce helpers ------------------------------------- */

// deriveNonce deterministically derives a unique 12-byte nonce from the per-message key.
func deriveNonce(messageKey []byte) ([]byte, error) {
	hk := hkdf.New(sha256.New, messageKey, nil, labelNonce)
	nonce := make([]byte, nonceSize)
	if err := readFull(hk, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// seal encrypts plaintext with the given per-message key and header-associated data.
func seal(
	messageKey []byte,
	_ domain.RatchetHeader,
	associatedData []byte,
	plaintext []byte,
) ([]byte, error) {
	aead, err := chacha20poly1305.New(messageKey[:aeadKeySize])
	if err != nil {
		return nil, err
	}
	nonce, err := deriveNonce(messageKey)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, associatedData), nil
}

// open decrypts ciphertext with the given per-message key and header-associated data.
func open(
	messageKey []byte,
	_ domain.RatchetHeader,
	associatedData []byte,
	ciphertext []byte,
) ([]byte, error) {
	aead, err := chacha20poly1305.New(messageKey[:aeadKeySize])
	if err != nil {
		return nil, err
	}
	nonce, err := deriveNonce(messageKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, associatedData)
}

/* ----------------------------------------- Serialisers ---------------------------------------- */

// headerBytes serialises PN || N in big-endian after DHPub.
func headerBytes(h domain.RatchetHeader) []byte {
	var tmp [4]byte
	out := append([]byte{}, h.DHPub...)
	binary.BigEndian.PutUint32(tmp[:], h.PN)
	out = append(out, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:], h.N)
	return append(out, tmp[:]...)
}

// composeAAD builds the AAD = associatedData || headerBytes(header).
func composeAAD(associatedData []byte, header domain.RatchetHeader) []byte {
	aad := make([]byte, 0, len(associatedData)+len(header.DHPub)+headerIntsSize)
	aad = append(aad, associatedData...)
	aad = append(aad, headerBytes(header)...)
	return aad
}

/* ----------------------------------- Skipped-key management ----------------------------------- */

// skipUntil derives and stashes skipped message keys from the current receive
// chain until state.Nr reaches previousChainLength, evicting old entries if the cap is exceeded.
func skipUntil(state *domain.RatchetState, previousChainLength uint32) {
	for state.Nr < previousChainLength {
		skippedMessageKey, _ := kdfCKRecv(state) // RecvCK initialised; error not expected
		if len(state.Skipped) >= maxSkippedMK {
			evictOldestForPeer(state.Skipped, state.PeerDHPub)
		}
		state.Skipped[skippedKeyID(state.PeerDHPub, state.Nr)] = skippedMessageKey
		state.Nr++
	}
}

// skippedKeyID creates a stable, JSON-safe map key for a (peer DHPub, N) pair.
func skippedKeyID(pub domain.X25519Public, n uint32) string {
	var buf [x25519PubSize + 4]byte
	copy(buf[:x25519PubSize], pub.Slice())
	binary.BigEndian.PutUint32(buf[x25519PubSize:], n)
	return hex.EncodeToString(buf[:]) // Hex-encode to prevent non-UTF-8 keys from breaking JSON.
}

// wipeAndDelete zeroes the value for key in m (if present) and removes the entry.
func wipeAndDelete(m map[string][]byte, key string) {
	if v, ok := m[key]; ok && v != nil {
		crypto.Wipe(v)
		delete(m, key)
	}
}

// evictOldestForPeer removes the lowest-N skipped key for the given peer if present; otherwise
// evicts any.
func evictOldestForPeer(skipped map[string][]byte, peer domain.X25519Public) {
	var (
		oldestKey string
		oldestN   uint32
		found     bool
	)
	for k := range skipped {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != x25519PubSize+4 {
			continue
		}
		if subtle.ConstantTimeCompare(b[:x25519PubSize], peer.Slice()) != 1 {
			continue
		}
		n := binary.BigEndian.Uint32(b[x25519PubSize:])
		if !found || n < oldestN {
			oldestN, oldestKey, found = n, k, true
		}
	}
	if found {
		wipeAndDelete(skipped, oldestKey)
		return
	}
	// Fallback: evict any single entry.
	for k := range skipped {
		wipeAndDelete(skipped, k)
		return
	}
}

/* -------------------------------------------- Utils ------------------------------------------- */

// wipeAndCopy wipes the current value pointed to by dst (if any) and replaces it with a copy of
// src.
func wipeAndCopy(dst *[]byte, src []byte) {
	if *dst != nil {
		crypto.Wipe(*dst)
	}
	*dst = append([]byte(nil), src...)
}

// readFull reads len(b) bytes, returning an error on short read.
func readFull(r io.Reader, b []byte) error {
	_, err := io.ReadFull(r, b)
	return err
}
