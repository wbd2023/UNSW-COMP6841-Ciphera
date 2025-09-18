package types

// RatchetHeader is sent alongside every ciphertext.
type RatchetHeader struct {
	DiffieHellmanPublicKey []byte `json:"dh_pub"`
	PreviousChainLength    uint32 `json:"pn"`
	MessageIndex           uint32 `json:"n"`
}

// RatchetState contains all fields the Double Ratchet needs to track.
type RatchetState struct {
	RootKey                 []byte            `json:"root_key"`
	DiffieHellmanPrivate    X25519Private     `json:"dh_priv"`
	DiffieHellmanPublic     X25519Public      `json:"dh_pub"`
	PeerDiffieHellmanPublic X25519Public      `json:"peer_dh_pub"`
	SendChainKey            []byte            `json:"send_ck,omitempty"`
	ReceiveChainKey         []byte            `json:"recv_ck,omitempty"`
	SendMessageIndex        uint32            `json:"ns"`
	ReceiveMessageIndex     uint32            `json:"nr"`
	PreviousChainLength     uint32            `json:"pn"`
	SkippedKeys             map[string][]byte `json:"skipped_keys"`
}

// Conversation persists the ratchet state for a peer.
type Conversation struct {
	Peer  ConversationID `json:"peer"`
	State RatchetState   `json:"state"`
}
