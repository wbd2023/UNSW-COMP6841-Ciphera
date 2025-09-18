package domain

import (
	interfaces "ciphera/internal/domain/interfaces"
	types "ciphera/internal/domain/types"
)

// Type aliases expose domain types from the types subpackage for compact imports.
type (
	Username            = types.Username
	Fingerprint         = types.Fingerprint
	SignedPreKeyID      = types.SignedPreKeyID
	OneTimePreKeyID     = types.OneTimePreKeyID
	ConversationID      = types.ConversationID
	Identity            = types.Identity
	OneTimePreKeyPair   = types.OneTimePreKeyPair
	OneTimePreKeyPublic = types.OneTimePreKeyPublic
	PreKeyBundle        = types.PreKeyBundle
	PreKeyMessage       = types.PreKeyMessage
	Envelope            = types.Envelope
	DecryptedMessage    = types.DecryptedMessage
	RatchetHeader       = types.RatchetHeader
	RatchetState        = types.RatchetState
	Conversation        = types.Conversation
	Session             = types.Session
	AccountProfile      = types.AccountProfile
	X25519Public        = types.X25519Public
	X25519Private       = types.X25519Private
	Ed25519Public       = types.Ed25519Public
	Ed25519Private      = types.Ed25519Private
)

// Interface aliases expose domain interfaces from the interfaces subpackage.
type (
	IdentityService   = interfaces.IdentityService
	PreKeyService     = interfaces.PreKeyService
	SessionService    = interfaces.SessionService
	MessageService    = interfaces.MessageService
	RelayClient       = interfaces.RelayClient
	IdentityStore     = interfaces.IdentityStore
	PreKeyStore       = interfaces.PreKeyStore
	PreKeyBundleStore = interfaces.PreKeyBundleStore
	SessionStore      = interfaces.SessionStore
	RatchetStore      = interfaces.RatchetStore
	AccountStore      = interfaces.AccountStore
)
