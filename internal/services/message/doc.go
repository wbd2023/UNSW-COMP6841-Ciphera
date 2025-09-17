// Package message sends and receives encrypted messages.
//
// It derives message keys from Double Ratchet state, updates per-message
// state, and exchanges ciphertexts via the RelayClient.
package message
