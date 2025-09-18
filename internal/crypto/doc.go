// Package crypto exposes the minimal primitives used by Ciphera.
//
// Contents
//
//   - X25519 key generation, clamping and Diffie–Hellman (GenerateX25519,
//     ClampX25519PrivateKey, DH)
//   - Ed25519 key generation, signing and verification (GenerateEd25519,
//     SignEd25519, VerifyEd25519)
//   - Best-effort memory wiping for sensitive byte slices (Wipe)
//   - Short public-key fingerprints for display/logging (Fingerprint)
//
// # Notes
//
// All functions return fixed-size array types defined in internal/domain to
// avoid accidental reallocations. Callers should treat returned secrets as
// sensitive and rely on Wipe when practical to reduce lifetime in memory.
package crypto
