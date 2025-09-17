// Package identity manages creation, encryption and loading of the local identity.
//
// It enforces passphrase policy, generates X25519 and Ed25519 key pairs, and
// persists them via the domain.IdentityStore.
package identity
