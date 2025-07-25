package domain

type Session struct {
	Peer           string
	RootKey        []byte
	OurIdentity    X25519Public
	PeerIdentity   X25519Public
	PeerEd25519    Ed25519Public
	PeerSPK        X25519Public
	UsedOneTimeKey bool
}

type SessionService interface {
	StartInitiator(passphrase, peerUsername string) (Session, error)
	Get(peer string) (Session, bool, error)
}

type SessionStore interface {
	SaveSession(s Session) error
	LoadSession(peer string) (Session, bool, error)
}
