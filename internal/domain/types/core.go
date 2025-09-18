package types

// Username represents a relay-registered identity.
type Username string

// String returns the string form of the username.
func (u Username) String() string { return string(u) }

// Fingerprint is a short identifier for public keys presented to users.
type Fingerprint string

// String returns the string form of the fingerprint.
func (f Fingerprint) String() string { return string(f) }

// SignedPreKeyID uniquely identifies a signed pre-key.
type SignedPreKeyID string

// String returns the string form of the identifier.
func (id SignedPreKeyID) String() string { return string(id) }

// OneTimePreKeyID uniquely identifies a one-time pre-key.
type OneTimePreKeyID string

// String returns the string form of the identifier.
func (id OneTimePreKeyID) String() string { return string(id) }

// ConversationID identifies a conversation partner.
type ConversationID string

// String returns the string form of the conversation identifier.
func (id ConversationID) String() string { return string(id) }
