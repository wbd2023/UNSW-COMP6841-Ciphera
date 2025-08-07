package domain

// X25519Public is a Curve25519 public key.
type X25519Public [32]byte

// Slice returns the key as a []byte.
func (p X25519Public) Slice() []byte { return p[:] }

// X25519Private is a Curve25519 private key.
type X25519Private [32]byte

// Slice returns the key as a []byte.
func (k X25519Private) Slice() []byte { return k[:] }

// Ed25519Public is an Ed25519 signing public key.
type Ed25519Public [32]byte

// Slice returns the key as a []byte.
func (p Ed25519Public) Slice() []byte { return p[:] }

// Ed25519Private is an Ed25519 signing private key.
type Ed25519Private [64]byte

// Slice returns the key as a []byte.
func (k Ed25519Private) Slice() []byte { return k[:] }

// Identity holds your long-term X25519 and Ed25519 keys.
type Identity struct {
	XPub   X25519Public   `json:"xpub"`
	XPriv  X25519Private  `json:"xpriv"`
	EdPub  Ed25519Public  `json:"edpub"`
	EdPriv Ed25519Private `json:"edpriv"`
}

// OneTimePair is the full (private+public) one-time prekey stored locally.
type OneTimePair struct {
	ID   string        `json:"id"`
	Priv X25519Private `json:"priv"`
	Pub  X25519Public  `json:"pub"`
}

// OneTimePub is only the public half (sent in bundles).
type OneTimePub struct {
	ID  string       `json:"id"`
	Pub X25519Public `json:"pub"`
}

// PrekeyBundle is the set of public keys you register with the relay.
// SignedPrekeySig is base64-encoded automatically.
type PrekeyBundle struct {
	Username        string        `json:"username"`
	IdentityKey     X25519Public  `json:"identity_key"`
	SignKey         Ed25519Public `json:"sign_key"`
	SPKID           string        `json:"spk_id"`
	SignedPrekey    X25519Public  `json:"signed_prekey"`
	SignedPrekeySig []byte        `json:"signed_prekey_sig"`
	OneTime         []OneTimePub  `json:"one_time,omitempty"`
}

// PrekeyMessage carries the X3DH handshake parameters in your first
// message envelope.
type PrekeyMessage struct {
	InitiatorIK   X25519Public `json:"initiator_ik"`
	Ephemeral     X25519Public `json:"ephemeral"`
	SPKID         string       `json:"spk_id"`
	OPKID         string       `json:"opk_id,omitempty"`
	TranscriptSHA []byte       `json:"transcript_sha,omitempty"`
}

// RatchetHeader is sent alongside every ciphertext.
type RatchetHeader struct {
	DHPub []byte `json:"dh_pub"`
	PN    uint32 `json:"pn"`
	N     uint32 `json:"n"`
}

// Envelope is the wire-format message you post/get from the relay.
type Envelope struct {
	From      string         `json:"from"`
	To        string         `json:"to"`
	Header    RatchetHeader  `json:"header"`
	Cipher    []byte         `json:"cipher"`
	AD        []byte         `json:"ad,omitempty"`
	Prekey    *PrekeyMessage `json:"prekey,omitempty"`
	Timestamp int64          `json:"timestamp"`
}

// Session holds the X3DH-derived root key and metadata for a peer.
type Session struct {
	Peer        string       `json:"peer"`
	RootKey     []byte       `json:"root_key"`
	PeerSPK     X25519Public `json:"peer_spk"`
	PeerIK      X25519Public `json:"peer_ik"`
	CreatedUTC  int64        `json:"created_utc"`
	SPKID       string       `json:"spk_id"`
	OPKID       string       `json:"opk_id"`
	InitiatorEK X25519Public `json:"initiator_ek"`
}

// Conversation persists the ratchet state for a peer.
type Conversation struct {
	Peer  string       `json:"peer"`
	State RatchetState `json:"state"`
}

// DecryptedMessage is what MessageService.Recv returns.
type DecryptedMessage struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Plaintext []byte `json:"plaintext"`
	Timestamp int64  `json:"timestamp"`
}

// RatchetState contains all fields the Double Ratchet needs to track.
type RatchetState struct {
	RootKey   []byte            `json:"root_key"`
	DHPriv    X25519Private     `json:"dh_priv"`
	DHPub     X25519Public      `json:"dh_pub"`
	PeerDHPub X25519Public      `json:"peer_dh_pub"`
	SendCK    []byte            `json:"send_ck,omitempty"`
	RecvCK    []byte            `json:"recv_ck,omitempty"`
	Ns        uint32            `json:"ns"`
	Nr        uint32            `json:"nr"`
	PN        uint32            `json:"pn"`
	Skipped   map[string][]byte `json:"skipped,omitempty"`
}
