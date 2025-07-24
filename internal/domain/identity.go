package domain

type Identity struct {
	// X25519 for Diffie-Hellman
	XPriv X25519Private
	XPub  X25519Public
	// Ed25519 for signatures
	EdPriv Ed25519Private
	EdPub  Ed25519Public
}

type IdentityService interface {
	Generate(passphrase string) (Identity, string /* fingerprint of X25519 pub */, error)
	Fingerprint(passphrase string) (string, error)
}
