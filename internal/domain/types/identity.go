package types

// Identity holds your long-term X25519 and Ed25519 keys.
type Identity struct {
	XPub   X25519Public   `json:"xpub"`
	XPriv  X25519Private  `json:"xpriv"`
	EdPub  Ed25519Public  `json:"edpub"`
	EdPriv Ed25519Private `json:"edpriv"`
}
