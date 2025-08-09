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

var ErrBadSPK = errors.New("signed prekey verification failed")

// InitiatorRoot performs the X3DH handshake as the initiator.
// Returns (rootKey, usedSPKID, usedOPKID, ephPub, error).
func InitiatorRoot(
	our domain.Identity,
	b domain.PrekeyBundle,
) (
	root []byte,
	spkID string,
	opkID string,
	ephPub domain.X25519Public,
	err error,
) {
	if !verifySPK(b) {
		return nil, "", "", ephPub, ErrBadSPK
	}

	ephPriv, ephPub, err := crypto.GenerateX25519()
	if err != nil {
		return nil, "", "", ephPub, err
	}
	spkID = b.SPKID

	var opk *domain.X25519Public
	if len(b.OneTime) > 0 {
		opkID = b.OneTime[0].ID
		opk = &b.OneTime[0].Pub
	}

	dh1, err := crypto.DH(our.XPriv, b.SignedPrekey)
	if err != nil {
		return nil, "", "", ephPub, err
	}
	dh2, err := crypto.DH(ephPriv, b.IdentityKey)
	if err != nil {
		return nil, "", "", ephPub, err
	}
	dh3, err := crypto.DH(ephPriv, b.SignedPrekey)
	if err != nil {
		return nil, "", "", ephPub, err
	}

	if opk != nil {
		dh4, derr := crypto.DH(ephPriv, *opk)
		if derr != nil {
			return nil, "", "", ephPub, derr
		}
		root, err = deriveRootFromShared(dh1, dh2, dh3, dh4)
	} else {
		root, err = deriveRootFromShared(dh1, dh2, dh3)
	}
	return root, spkID, opkID, ephPub, err
}

// ResponderRoot performs the X3DH handshake as the responder.
func ResponderRoot(
	my domain.Identity,
	spkPriv domain.X25519Private,
	opkPriv *domain.X25519Private,
	pm domain.PrekeyMessage,
) (root []byte, err error) {
	dh1, err := crypto.DH(spkPriv, pm.InitiatorIK)
	if err != nil {
		return nil, err
	}
	dh2, err := crypto.DH(my.XPriv, pm.Ephemeral)
	if err != nil {
		return nil, err
	}
	dh3, err := crypto.DH(spkPriv, pm.Ephemeral)
	if err != nil {
		return nil, err
	}

	if opkPriv != nil {
		dh4, derr := crypto.DH(*opkPriv, pm.Ephemeral)
		if derr != nil {
			return nil, derr
		}
		root, err = deriveRootFromShared(dh1, dh2, dh3, dh4)
	} else {
		root, err = deriveRootFromShared(dh1, dh2, dh3)
	}
	return root, err
}

// --- Helpers ---

// verifySPK checks that bundle.SignedPrekey was signed by bundle.SignKey.
func verifySPK(b domain.PrekeyBundle) bool {
	return crypto.VerifyEd25519(
		b.SignKey,
		b.SignedPrekey[:],
		b.SignedPrekeySig,
	)
}

// deriveRootFromShared concatenates the DH outputs and runs HKDF to produce a 32-byte root key.
// Uses x3dhLabel internally.
func deriveRootFromShared(dhs ...[32]byte) ([]byte, error) {
	transcript := make([]byte, 0, len(dhs)*32)
	for _, dh := range dhs {
		transcript = append(transcript, dh[:]...)
	}

	hk := hkdf.New(sha256.New, transcript, nil, []byte(x3dhLabel))
	root := make([]byte, 32)
	if _, err := io.ReadFull(hk, root); err != nil {
		return nil, err
	}

	crypto.Wipe(transcript)
	return root, nil
}
