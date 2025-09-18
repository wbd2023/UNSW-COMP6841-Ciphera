package interfaces

import domaintypes "ciphera/internal/domain/types"

// AccountStore persists per-relay account profiles.
type AccountStore interface {
	SaveAccountProfile(profile domaintypes.AccountProfile) error
	LoadAccountProfile(
		serverURL string,
		username domaintypes.Username,
	) (domaintypes.AccountProfile, bool, error)
}
