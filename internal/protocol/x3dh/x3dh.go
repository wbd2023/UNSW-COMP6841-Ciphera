package x3dh

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"

	"ciphera/internal/domain"
	"ciphera/internal/util/memzero"
)

// InitiatorRootKey derives the root key for the initiator using X3DH.
func InitiatorRootKey(
	ourIDPriv domain.X25519Private,
	ourEphPriv domain.X25519Private,
	peerIDPub domain.X25519Public,
	peerSPK domain.X25519Public,
	peerOPK *domain.X25519Public,
) ([]byte, error) {
	dh1, err := dh(ourIDPriv, peerSPK) // DH(IKA, SPKB)
	if err != nil {
		return nil, err
	}
	dh2, err := dh(ourEphPriv, peerIDPub) // DH(EKA, IKB)
	if err != nil {
		return nil, err
	}
	dh3, err := dh(ourEphPriv, peerSPK) // DH(EKA, SPKB)
	if err != nil {
		return nil, err
	}

	dhConcat := make([]byte, 0, 32*4)
	dhConcat = append(dhConcat, dh1[:]...)
	dhConcat = append(dhConcat, dh2[:]...)
	dhConcat = append(dhConcat, dh3[:]...)

	if peerOPK != nil {
		dh4, err := dh(ourEphPriv, *peerOPK) // DH(EKA, OPKB)
		if err != nil {
			return nil, err
		}
		dhConcat = append(dhConcat, dh4[:]...)
	}

	root := hkdfSHA256(dhConcat, nil, []byte("ciphera-x3dh"), 32)
	memzero.Zero(dhConcat)
	return root, nil
}

// VerifySPK checks the signed prekey signature.
func VerifySPK(edPub domain.Ed25519Public, spk domain.X25519Public, sig []byte) bool {
	return ed25519.Verify(edPub.Slice(), spk.Slice(), sig)
}

func dh(priv domain.X25519Private, pub domain.X25519Public) ([32]byte, error) {
	res, err := curve25519.X25519(priv.Slice(), pub.Slice())
	var out [32]byte
	if err != nil {
		return out, err
	}
	copy(out[:], res)
	return out, nil
}

// hkdfSHA256 implements HKDF (RFC 5869) with SHA-256.
func hkdfSHA256(ikm, salt, info []byte, outLen int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	prk := hmacSum(salt, ikm)
	var (
		t   []byte
		okm []byte
		cnt byte = 1
	)
	for len(okm) < outLen {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{cnt})
		t = h.Sum(nil)
		okm = append(okm, t...)
		cnt++
	}
	return okm[:outLen]
}

func hmacSum(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
