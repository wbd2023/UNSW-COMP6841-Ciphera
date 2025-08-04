package domain

import "encoding/json"

// X25519Public is a Curve25519 public key.
type X25519Public [32]byte

func (p X25519Public) Slice() []byte { return p[:] }

// X25519Private is a Curve25519 private key.
type X25519Private [32]byte

func (k X25519Private) Slice() []byte { return k[:] }

// Ed25519Public is a signing public key.
type Ed25519Public [32]byte

func (p Ed25519Public) Slice() []byte { return p[:] }

// Ed25519Private is a signing private key (ed25519.PrivateKey layout).
type Ed25519Private [64]byte

func (k Ed25519Private) Slice() []byte { return k[:] }

// Identity holds long-term keys stored locally.
type Identity struct {
	XPub   X25519Public
	XPriv  X25519Private
	EdPub  Ed25519Public
	EdPriv Ed25519Private
}

// OneTimePub is a published one-time prekey (public only) with an ID.
type OneTimePub struct {
	ID  string
	Pub X25519Public
}

// PrekeyBundle is served by the relay. IDs allow initiators to reference SPK/OPK.
type PrekeyBundle struct {
	Username        string
	IdentityKey     X25519Public
	SignKey         Ed25519Public
	SPKID           string
	SignedPrekey    X25519Public
	SignedPrekeySig []byte
	OneTime         []OneTimePub // optional
}

// MarshalJSON encodes fixed arrays as arrays for stable JSON.
func (b PrekeyBundle) MarshalJSON() ([]byte, error) {
	type pub = [32]byte
	type alias PrekeyBundle
	type one struct {
		ID  string `json:"id"`
		Pub pub    `json:"pub"`
	}
	aux := struct {
		alias
		IdentityKey pub   `json:"identity_key"`
		SignKey     pub   `json:"sign_key"`
		SignedPK    pub   `json:"signed_prekey"`
		OneTime     []one `json:"one_time,omitempty"`
	}{
		alias:       (alias)(b),
		IdentityKey: b.IdentityKey,
		SignKey:     b.SignKey,
		SignedPK:    b.SignedPrekey,
		OneTime:     make([]one, len(b.OneTime)),
	}
	for i := range b.OneTime {
		aux.OneTime[i] = one{ID: b.OneTime[i].ID, Pub: b.OneTime[i].Pub}
	}
	return json.Marshal(aux)
}

// UnmarshalJSON mirrors MarshalJSON.
func (b *PrekeyBundle) UnmarshalJSON(data []byte) error {
	type pub = [32]byte
	type alias PrekeyBundle
	type one struct {
		ID  string `json:"id"`
		Pub pub    `json:"pub"`
	}
	aux := struct {
		alias
		IdentityKey pub   `json:"identity_key"`
		SignKey     pub   `json:"sign_key"`
		SignedPK    pub   `json:"signed_prekey"`
		OneTime     []one `json:"one_time,omitempty"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*b = (PrekeyBundle)(aux.alias)
	b.IdentityKey = aux.IdentityKey
	b.SignKey = aux.SignKey
	b.SignedPrekey = aux.SignedPK
	b.OneTime = make([]OneTimePub, len(aux.OneTime))
	for i := range aux.OneTime {
		b.OneTime[i] = OneTimePub{ID: aux.OneTime[i].ID, Pub: aux.OneTime[i].Pub}
	}
	return nil
}

// RatchetHeader accompanies each ciphertext.
type RatchetHeader struct {
	DHPub []byte // 32 bytes
	PN    uint32
	N     uint32
}

// PrekeyMessage is attached to the first message from the initiator.
type PrekeyMessage struct {
	InitiatorIK   X25519Public // IK_A
	Ephemeral     X25519Public // EK_A
	SPKID         string
	OPKID         string // optional
	TranscriptSHA []byte `json:",omitempty"` // optional transcript binding
}

// Envelope is the wire message via relay.
type Envelope struct {
	From      string         `json:"from"`
	To        string         `json:"to"`
	Header    RatchetHeader  `json:"header"`
	Cipher    []byte         `json:"cipher"`
	AD        []byte         `json:"ad,omitempty"`
	Prekey    *PrekeyMessage `json:"prekey,omitempty"`
	Timestamp int64          `json:"timestamp"`
}

// Session is produced by X3DH; RootKey seeds Double Ratchet.
type Session struct {
	Peer       string
	RootKey    []byte
	PeerSPK    X25519Public
	PeerIK     X25519Public
	CreatedUTC int64

	// X3DH parameters used by the initiator; echoed in the first PrekeyMessage.
	SPKID       string
	OPKID       string
	InitiatorEK X25519Public
}

// DecryptedMessage is returned by MessageService.Recv.
type DecryptedMessage struct {
	From      string
	To        string
	Plaintext []byte
	Timestamp int64
}

// Conversation stores per-peer ratchet state.
type Conversation struct {
	Peer  string
	State RatchetState
}

// RatchetState holds Double Ratchet state.
type RatchetState struct {
	RootKey []byte
	DHPriv  X25519Private
	DHPub   X25519Public

	PeerDHPub X25519Public

	SendCK []byte
	RecvCK []byte

	Ns, Nr, PN uint32

	Skipped map[string][]byte
}
