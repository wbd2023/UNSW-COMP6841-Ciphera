package domain

type SignedPreKey struct {
	ID  uint32
	Key X25519Public
	Sig []byte
}

type OneTimePreKey struct {
	ID  uint32
	Key X25519Public
}

type PrekeyBundle struct {
	Username      string
	IdentityXPub  X25519Public
	IdentityEdPub Ed25519Public
	SignedPreKey  SignedPreKey
	OneTimeKeys   []OneTimePreKey
}

type PrekeyService interface {
	GenerateAndStore(passphrase string, nOneTime uint16) (SignedPreKey, []OneTimePreKey, error)
	LoadBundle(passphrase, username string) (PrekeyBundle, error)
}
