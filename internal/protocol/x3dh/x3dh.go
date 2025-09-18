package x3dh

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

const x3dhLabel = "ciphera/x3dh-v1"

var ErrBadSignedPreKey = errors.New("signed prekey verification failed")

// InitiatorRoot performs the X3DH handshake as the initiator.
// Returns (rootKey, used Signed Pre-Key ID, used One-Time Pre-Key ID,
// initiator ephemeral public key, error).
func InitiatorRoot(
	initiatorIdentity domain.Identity,
	responderPreKeyBundle domain.PreKeyBundle,
) (
	root []byte,
	signedPreKeyID domain.SignedPreKeyID,
	oneTimePreKeyID domain.OneTimePreKeyID,
	initiatorEphemeralPublicKey domain.X25519Public,
	err error,
) {
	if !verifySignedPreKey(responderPreKeyBundle) {
		return nil, "", "", initiatorEphemeralPublicKey, ErrBadSignedPreKey
	}

	initiatorEphemeralPrivateKey, initiatorEphemeralPublicKey, err := crypto.GenerateX25519()
	if err != nil {
		return nil, "", "", initiatorEphemeralPublicKey, err
	}
	signedPreKeyID = responderPreKeyBundle.SignedPreKeyID

	var oneTimePreKeyPublic *domain.X25519Public
	if len(responderPreKeyBundle.OneTimePreKeys) > 0 {
		oneTimePreKeyID = responderPreKeyBundle.OneTimePreKeys[0].ID
		oneTimePreKeyPublic = &responderPreKeyBundle.OneTimePreKeys[0].Pub
	}

	diffieHellman1, err := crypto.DH(initiatorIdentity.XPriv, responderPreKeyBundle.SignedPreKey)
	if err != nil {
		return nil, "", "", initiatorEphemeralPublicKey, err
	}
	diffieHellman2, err := crypto.DH(initiatorEphemeralPrivateKey, responderPreKeyBundle.IdentityKey)
	if err != nil {
		return nil, "", "", initiatorEphemeralPublicKey, err
	}
	diffieHellman3, err := crypto.DH(initiatorEphemeralPrivateKey, responderPreKeyBundle.SignedPreKey)
	if err != nil {
		return nil, "", "", initiatorEphemeralPublicKey, err
	}

	if oneTimePreKeyPublic != nil {
		diffieHellman4, derr := crypto.DH(initiatorEphemeralPrivateKey, *oneTimePreKeyPublic)
		if derr != nil {
			return nil, "", "", initiatorEphemeralPublicKey, derr
		}
		root, err = deriveRootFromShared(diffieHellman1, diffieHellman2, diffieHellman3, diffieHellman4)
	} else {
		root, err = deriveRootFromShared(diffieHellman1, diffieHellman2, diffieHellman3)
	}
	return root, signedPreKeyID, oneTimePreKeyID, initiatorEphemeralPublicKey, err
}

// ResponderRoot performs the X3DH handshake as the responder.
func ResponderRoot(
	responderIdentity domain.Identity,
	signedPreKeyPrivateKey domain.X25519Private,
	oneTimePreKeyPrivateKey *domain.X25519Private,
	preKeyMessage domain.PreKeyMessage,
) (root []byte, err error) {
	diffieHellman1, err := crypto.DH(signedPreKeyPrivateKey, preKeyMessage.InitiatorIdentityKey)
	if err != nil {
		return nil, err
	}
	diffieHellman2, err := crypto.DH(responderIdentity.XPriv, preKeyMessage.EphemeralKey)
	if err != nil {
		return nil, err
	}
	diffieHellman3, err := crypto.DH(signedPreKeyPrivateKey, preKeyMessage.EphemeralKey)
	if err != nil {
		return nil, err
	}

	if oneTimePreKeyPrivateKey != nil {
		diffieHellman4, derr := crypto.DH(*oneTimePreKeyPrivateKey, preKeyMessage.EphemeralKey)
		if derr != nil {
			return nil, derr
		}
		root, err = deriveRootFromShared(diffieHellman1, diffieHellman2, diffieHellman3, diffieHellman4)
	} else {
		root, err = deriveRootFromShared(diffieHellman1, diffieHellman2, diffieHellman3)
	}
	return root, err
}

// --- Helpers ---

// verifySignedPreKey checks that the signed pre-key was signed by the advertised signing key.
func verifySignedPreKey(bundle domain.PreKeyBundle) bool {
	return crypto.VerifyEd25519(
		bundle.SigningKey,
		bundle.SignedPreKey[:],
		bundle.SignedPreKeySignature,
	)
}

// deriveRootFromShared concatenates the DH outputs and runs HKDF to produce a 32-byte root key.
// Uses x3dhLabel internally.
func deriveRootFromShared(dhs ...[32]byte) ([]byte, error) {
	transcriptBuf := make([]byte, len(dhs)*32)
	defer crypto.DeferWipe(&transcriptBuf)()
	transcript := transcriptBuf[:0] // zero-length slice backed by the allocated buffer
	for _, dh := range dhs {
		transcript = append(transcript, dh[:]...)
	}

	hk := hkdf.New(sha256.New, transcript, nil, []byte(x3dhLabel))
	root := make([]byte, 32)
	if _, err := io.ReadFull(hk, root); err != nil {
		return nil, err
	}

	return root, nil
}
