package interfaces

import domaintypes "ciphera/internal/domain/types"

// IdentityStore persists your long-term identity keys.
type IdentityStore interface {
	SaveIdentity(passphrase string, id domaintypes.Identity) error
	LoadIdentity(passphrase string) (domaintypes.Identity, error)
}

// PreKeyStore manages signed and one-time pre-keys on disk.
type PreKeyStore interface {
	// Signed pre-key
	SaveSignedPreKey(
		id domaintypes.SignedPreKeyID,
		priv domaintypes.X25519Private,
		pub domaintypes.X25519Public,
		sig []byte,
	) error
	LoadSignedPreKey(
		id domaintypes.SignedPreKeyID,
	) (
		priv domaintypes.X25519Private,
		pub domaintypes.X25519Public,
		sig []byte,
		ok bool,
		err error,
	)

	// One-time pre-keys
	SaveOneTimePreKeys(pairs []domaintypes.OneTimePreKeyPair) error
	ConsumeOneTimePreKey(id domaintypes.OneTimePreKeyID) (
		priv domaintypes.X25519Private,
		pub domaintypes.X25519Public,
		ok bool,
		err error,
	)
	ListOneTimePreKeyPublics() ([]domaintypes.OneTimePreKeyPublic, error)

	// Current signed pre-key selection
	SetCurrentSignedPreKeyID(id domaintypes.SignedPreKeyID) error
	CurrentSignedPreKeyID() (domaintypes.SignedPreKeyID, bool, error)
}

// PreKeyBundleStore caches the last bundle you registered.
type PreKeyBundleStore interface {
	SavePreKeyBundle(bundle domaintypes.PreKeyBundle) error
	LoadPreKeyBundle(username domaintypes.Username) (domaintypes.PreKeyBundle, bool, error)
}

// SessionStore persists established X3DH sessions.
type SessionStore interface {
	SaveSession(peer domaintypes.Username, session domaintypes.Session) error
	LoadSession(peer domaintypes.Username) (domaintypes.Session, bool, error)
}

// RatchetStore keeps per-peer Double-Ratchet state.
type RatchetStore interface {
	SaveConversation(peer domaintypes.ConversationID, conversation domaintypes.Conversation) error
	LoadConversation(peer domaintypes.ConversationID) (domaintypes.Conversation, bool, error)
}
