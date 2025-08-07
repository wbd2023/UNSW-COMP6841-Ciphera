package domain

// IdentityStore persists your long-term identity keys.
type IdentityStore interface {
	SaveIdentity(passphrase string, id Identity) error
	LoadIdentity(passphrase string) (Identity, error)
}

// PrekeyStore manages signed and one-time prekeys on disk.
type PrekeyStore interface {
	// Signed prekey
	SaveSignedPrekey(id string, priv X25519Private, pub X25519Public, sig []byte) error
	LoadSignedPrekey(id string) (priv X25519Private, pub X25519Public, sig []byte, ok bool, err error)

	// One-time prekeys
	SaveOneTimePrekeys(pairs []OneTimePair) error
	ConsumeOneTimePrekey(id string) (priv X25519Private, pub X25519Public, ok bool, err error)
	ListOneTimePrekeyPublics() ([]OneTimePub, error)

	// Current signed prekey selection
	SetCurrentSignedPrekeyID(id string) error
	CurrentSignedPrekeyID() (string, bool, error)
}

// PrekeyBundleStore caches the last bundle you registered.
type PrekeyBundleStore interface {
	SavePrekeyBundle(b PrekeyBundle) error
	LoadPrekeyBundle(username string) (PrekeyBundle, bool, error)
}

// SessionStore persists established X3DH sessions.
type SessionStore interface {
	SaveSession(peer string, sess Session) error
	LoadSession(peer string) (Session, bool, error)
}

// RatchetStore keeps per-peer Double-Ratchet state.
type RatchetStore interface {
	SaveConversation(peer string, conv Conversation) error
	LoadConversation(peer string) (Conversation, bool, error)
}

// PrekeyService generates and assembles your prekey bundles.
type PrekeyService interface {
	GenerateAndStorePrekeys(passphrase string, n int) (X25519Public, []X25519Public, error)
	LoadPrekeyBundle(passphrase, username string) (PrekeyBundle, error)
}

// SessionService establishes or retrieves an X3DH session.
type SessionService interface {
	Initiate(passphrase, peer string) (Session, error)
	Get(peer string) (Session, bool, error)
}

// MessageService encrypts, sends, fetches and decrypts messages.
type MessageService interface {
	Send(passphrase, from, to string, plaintext []byte) error
	Receive(passphrase, me string, limit int) ([]DecryptedMessage, error)
}

// RelayClient is how we talk to the central relay server.
type RelayClient interface {
	RegisterPrekeyBundle(b PrekeyBundle) error
	FetchPrekeyBundle(username string) (PrekeyBundle, error)

	SendMessage(env Envelope) error
	FetchMessages(username string, limit int) ([]Envelope, error)
	AckMessages(username string, count int) error
}
