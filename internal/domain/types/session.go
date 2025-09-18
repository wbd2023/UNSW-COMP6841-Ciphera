package types

// Session holds the X3DH-derived root key and metadata for a peer.
type Session struct {
	PeerUsername          Username        `json:"peer_username"`
	RootKey               []byte          `json:"root_key"`
	PeerSignedPreKey      X25519Public    `json:"peer_signed_pre_key"`
	PeerIdentityKey       X25519Public    `json:"peer_identity_key"`
	CreatedUTC            int64           `json:"created_utc"`
	SignedPreKeyID        SignedPreKeyID  `json:"signed_pre_key_id"`
	OneTimePreKeyID       OneTimePreKeyID `json:"one_time_pre_key_id"`
	InitiatorEphemeralKey X25519Public    `json:"initiator_ephemeral_key"`
}
