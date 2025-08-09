// Package store provides file-based persistence for Ciphera’s core data.
//
// It contains concrete implementations of the domain storage interfaces,
// serialising data as JSON on disk. All methods are concurrency-safe via
// internal locking. Stored files typically live under the user’s configured
// home directory.
//
// The package includes stores for:
//   - Identity keys (IdentityFileStore)
//   - Prekeys (PrekeyFileStore)
//   - Prekey bundles (BundleFileStore)
//   - X3DH sessions (SessionFileStore)
//   - Double Ratchet conversation state (RatchetFileStore)
package store
