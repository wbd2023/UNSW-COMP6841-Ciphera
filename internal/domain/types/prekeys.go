package types

// OneTimePreKeyPair is the full (private+public) one-time pre-key stored locally.
type OneTimePreKeyPair struct {
	ID   OneTimePreKeyID `json:"id"`
	Priv X25519Private   `json:"priv"`
	Pub  X25519Public    `json:"pub"`
}

// OneTimePreKeyPublic is only the public half (sent in bundles).
type OneTimePreKeyPublic struct {
	ID  OneTimePreKeyID `json:"id"`
	Pub X25519Public    `json:"pub"`
}

// PreKeyBundle is the set of public keys you register with the relay.
// SignedPreKeySignature is base64-encoded automatically.
type PreKeyBundle struct {
	Username              Username              `json:"username"`
	IdentityKey           X25519Public          `json:"identity_key"`
	SigningKey            Ed25519Public         `json:"signing_key"`
	SignedPreKeyID        SignedPreKeyID        `json:"signed_pre_key_id"`
	SignedPreKey          X25519Public          `json:"signed_pre_key"`
	SignedPreKeySignature []byte                `json:"signed_pre_key_signature"`
	OneTimePreKeys        []OneTimePreKeyPublic `json:"one_time_pre_keys,omitempty"`
}

// PreKeyMessage carries the X3DH handshake parameters in your first
// message envelope.
type PreKeyMessage struct {
	InitiatorIdentityKey X25519Public    `json:"initiator_identity_key"`
	EphemeralKey         X25519Public    `json:"ephemeral_key"`
	SignedPreKeyID       SignedPreKeyID  `json:"signed_pre_key_id"`
	OneTimePreKeyID      OneTimePreKeyID `json:"one_time_pre_key_id,omitempty"`
	TranscriptSHA256     []byte          `json:"transcript_sha256,omitempty"`
}
