// Package x3dh implements the X3DH key-agreement used to bootstrap a Double Ratchet
// session between two parties.
//
// # Overview
//
// X3DH lets an initiator derive a shared 32-byte root key with a responder who has
// published a prekey bundle. The bundle contains:
//   - Identity key (X25519)
//   - Signed prekey (X25519) and its Ed25519 signature
//   - Optional one-time prekeys (X25519)
//
// # Flows
//
// Initiator:
//  1. Verify the signed prekey signature.
//  2. Generate an ephemeral X25519 key pair.
//  3. Compute DH values (IKa·SPKb, EKa·IKb, EKa·SPKb[, EKa·OPKb]).
//  4. HKDF over the concatenated DH transcript to produce the root key.
//  5. Return root key, the SPK/OPK identifiers used, and the initiator’s ephemeral public.
//
// Responder:
//  1. Receive the PrekeyMessage (initiator IK, ephemeral EK, SPKID[, OPKID]).
//  2. Look up SPK and optionally consume the OPK.
//  3. Compute the symmetric DH set (SPKb·IKa, IKb·EKa, SPKb·EKa[, OPKb·EKa]).
//  4. HKDF the same transcript to the identical root key.
//
// # Errors
//
// ErrBadSPK is returned when the SPK signature fails verification.
// Other errors wrap lower-level crypto or storage failures.
//
// # Security notes
//
// Only public material is sent over the wire. One-time prekeys, when present,
// improve forward secrecy by ensuring the handshake mixes in a value that is
// deleted after first use.
package x3dh
