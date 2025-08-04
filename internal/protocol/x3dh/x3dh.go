package x3dh

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

// VerifySPK checks the Ed25519 signature over the Signed Prekey.
func VerifySPK(bundle domain.PrekeyBundle) bool {
	return crypto.VerifyEd25519(bundle.SignKey, bundle.SignedPrekey[:], bundle.SignedPrekeySig)
}

// InitiatorRoot computes RK and chooses an OPK id (if any).
// Returns (rk, spkID, opkID, ephPub).
func InitiatorRoot(our domain.Identity, bundle domain.PrekeyBundle) (rk []byte, spkID, opkID string, ephPub domain.X25519Public, err error) {
	if !VerifySPK(bundle) {
		return nil, "", "", ephPub, errBadSPK
	}

	ephPriv, ephPub0, err := crypto.GenerateX25519()
	if err != nil {
		return nil, "", "", ephPub, err
	}
	ephPub = ephPub0
	spkID = bundle.SPKID

	var opk *domain.X25519Public
	if len(bundle.OneTime) > 0 {
		opkID = bundle.OneTime[0].ID
		opk = &bundle.OneTime[0].Pub
	}

	// DH1: IK_A ⋅ SPK_B
	dh1, err := crypto.DH(our.XPriv, bundle.SignedPrekey)
	if err != nil {
		return nil, "", "", ephPub, err
	}
	// DH2: EK_A ⋅ IK_B
	dh2, err := crypto.DH(ephPriv, bundle.IdentityKey)
	if err != nil {
		return nil, "", "", ephPub, err
	}
	// DH3: EK_A ⋅ SPK_B
	dh3, err := crypto.DH(ephPriv, bundle.SignedPrekey)
	if err != nil {
		return nil, "", "", ephPub, err
	}

	transcript := make([]byte, 0, 32*4)
	transcript = append(transcript, dh1[:]...)
	transcript = append(transcript, dh2[:]...)
	transcript = append(transcript, dh3[:]...)
	if opk != nil {
		dh4, err := crypto.DH(ephPriv, *opk) // DH4: EK_A ⋅ OPK_B
		if err != nil {
			return nil, "", "", ephPub, err
		}
		transcript = append(transcript, dh4[:]...)
	}

	r := hkdf.New(sha256.New, transcript, nil, []byte("ciphera/x3dh-v1"))
	rk = make([]byte, 32)
	_, _ = io.ReadFull(r, rk)
	crypto.Wipe(transcript)

	return rk, spkID, opkID, ephPub, nil
}

// ResponderRoot computes RK from PrekeyMessage using SPK/OPK private keys.
func ResponderRoot(my domain.Identity, spkPriv domain.X25519Private, opkPriv *domain.X25519Private, pm domain.PrekeyMessage) ([]byte, error) {
	// DH1: SPK_B ⋅ IK_A
	dh1, err := crypto.DH(spkPriv, pm.InitiatorIK)
	if err != nil {
		return nil, err
	}
	// DH2: IK_B ⋅ EK_A
	dh2, err := crypto.DH(my.XPriv, pm.Ephemeral)
	if err != nil {
		return nil, err
	}
	// DH3: SPK_B ⋅ EK_A
	dh3, err := crypto.DH(spkPriv, pm.Ephemeral)
	if err != nil {
		return nil, err
	}

	transcript := make([]byte, 0, 32*4)
	transcript = append(transcript, dh1[:]...)
	transcript = append(transcript, dh2[:]...)
	transcript = append(transcript, dh3[:]...)
	if opkPriv != nil {
		dh4, err := crypto.DH(*opkPriv, pm.Ephemeral) // DH4: OPK_B ⋅ EK_A
		if err != nil {
			return nil, err
		}
		transcript = append(transcript, dh4[:]...)
	}

	r := hkdf.New(sha256.New, transcript, nil, []byte("ciphera/x3dh-v1"))
	rk := make([]byte, 32)
	_, _ = io.ReadFull(r, rk)
	crypto.Wipe(transcript)

	return rk, nil
}

type errString string

func (e errString) Error() string { return string(e) }

var errBadSPK = errString("signed prekey verification failed")
