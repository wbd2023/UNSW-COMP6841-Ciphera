package types

// RatchetHeader is sent alongside every ciphertext.
type RatchetHeader struct {
	DiffieHellmanPublicKey []byte `json:"diffie_hellman_public_key"`
	PreviousChainLength    uint32 `json:"previous_chain_length"`
	MessageIndex           uint32 `json:"message_index"`
}

// RatchetState contains all fields the Double Ratchet needs to track.
type RatchetState struct {
	RootKey                 []byte            `json:"root_key"`
	DiffieHellmanPrivate    X25519Private     `json:"diffie_hellman_private"`
	DiffieHellmanPublic     X25519Public      `json:"diffie_hellman_public"`
	PeerDiffieHellmanPublic X25519Public      `json:"peer_diffie_hellman_public"`
	SendChainKey            []byte            `json:"send_chain_key,omitempty"`
	ReceiveChainKey         []byte            `json:"receive_chain_key,omitempty"`
	SendMessageIndex        uint32            `json:"send_message_index"`
	ReceiveMessageIndex     uint32            `json:"receive_message_index"`
	PreviousChainLength     uint32            `json:"previous_chain_length"`
	SkippedKeys             map[string][]byte `json:"skipped_keys"`
}

// Conversation persists the ratchet state for a peer.
type Conversation struct {
	Peer  ConversationID `json:"peer"`
	State RatchetState   `json:"state"`
}
