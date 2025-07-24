package domain

type Identity struct {
	Private [32]byte
	Public  [32]byte
}

type IdentityService interface {
	Generate(passphrase string) (Identity, string /*fingerprint*/, error)
	Fingerprint(passphrase string) (string, error)
}
