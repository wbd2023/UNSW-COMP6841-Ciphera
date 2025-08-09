// Package ratchet implements the Double Ratchet algorithm following Signal's design.
//
// The algorithm maintains a root key and two message chains (send and receive).
// Each message advances a KDF chain so that keys are forward secure. When a party
// changes its DH ratchet public key, both sides derive new chain keys from a new
// root derived via DH.
//
// Concurrency: RatchetState is NOT safe for concurrent use. Callers must
// serialise access per conversation.
package ratchet
