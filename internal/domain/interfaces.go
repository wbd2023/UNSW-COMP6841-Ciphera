package domain

// IdentityStore persists the local identity encrypted at rest.
type IdentityStore interface {
	Save(passphrase string, id Identity) error
	LoadIdentity(passphrase string) (Identity, error)
}

// PrekeyStore keeps signed and one-time prekey PAIRS locally.
type PrekeyStore interface {
	SaveSignedPrekeyPair(id string, priv X25519Private, pub X25519Public, sig []byte) error
	LoadSignedPrekeyPair(id string) (priv X25519Private, pub X25519Public, sig []byte, ok bool, err error)

	SaveOneTimePairs(pairs []OneTimePair) error
	ConsumeOneTimePair(id string) (priv X25519Private, pub X25519Public, ok bool, err error)

	SetCurrentSPKID(id string) error
	CurrentSPKID() (string, bool, error)
	ListOneTimePublics() ([]OneTimePub, error)
}

// OneTimePair is a local OPK pair.
type OneTimePair struct {
	ID   string
	Priv X25519Private
	Pub  X25519Public
}

// PrekeyBundleStore caches the last uploaded bundle (public material).
type PrekeyBundleStore interface {
	SaveBundle(b PrekeyBundle) error
	LoadBundle(username string) (PrekeyBundle, bool, error)
}

// RelayClient is the transport to the relay.
type RelayClient interface {
	Register(b PrekeyBundle) error
	FetchPrekey(username string) (PrekeyBundle, error)
	SendMessage(env Envelope) error
	FetchMessages(username string, limit int) ([]Envelope, error)
	AckMessages(username string, count int) error
}

// SessionStore persists X3DH sessions.
type SessionStore interface {
	Save(sess Session) error
	Get(peer string) (Session, bool, error)
}

// RatchetStore persists per-peer ratchet state.
type RatchetStore interface {
	Save(conv Conversation) error
	Load(peer string) (Conversation, bool, error)
}

// PrekeyService creates prekey pairs and assembles the public bundle.
type PrekeyService interface {
	GenerateAndStore(passphrase string, n int) (X25519Public, []X25519Public, error)
	LoadBundle(passphrase, username string) (PrekeyBundle, error)
}

// SessionService runs X3DH and returns a Session.
type SessionService interface {
	StartInitiator(passphrase, peer string) (Session, error)
	Get(peer string) (Session, bool, error)
}

// MessageService encrypts, sends, fetches and decrypts messages.
type MessageService interface {
	Send(passphrase, fromUsername, toUsername string, plaintext []byte) error
	Recv(passphrase, me string, limit int) ([]DecryptedMessage, error)
}
