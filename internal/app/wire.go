package app

import (
	"net/http"

	"ciphera/internal/domain"
	"ciphera/internal/relay"
	messagesvc "ciphera/internal/services/message"
	prekeysvc "ciphera/internal/services/prekey"
	sessionsvc "ciphera/internal/services/session"
	"ciphera/internal/store"
)

// Wire exposes composed dependencies for the CLI layer.
type Wire struct {
	Identity domain.IdentityStore
	Prekeys  domain.PrekeyStore
	Bundle   domain.PrekeyBundleStore

	Prekey   domain.PrekeyService
	Sessions domain.SessionService
	Ratchets domain.RatchetStore
	Messages domain.MessageService
	Relay    domain.RelayClient
	HTTP     *http.Client
}

// BuildFromConfig composes the app from Config.
func BuildFromConfig(cfg Config) (*Wire, error) {
	// Stores
	fs := store.NewFileStore(cfg.Home) // IdentityStore + PrekeyStore + PrekeyBundleStore
	sessStore := store.NewSessionFileStore(cfg.Home)
	ratchetStore := store.NewRatchetFileStore(cfg.Home)

	// Relay
	rc := relay.NewHTTP(cfg.RelayURL)
	if cfg.HTTP != nil {
		rc.HTTP = cfg.HTTP
	} else {
		rc.HTTP = http.DefaultClient
	}

	// Services
	pk := prekeysvc.New(fs, fs, fs)
	sess := sessionsvc.New(fs, fs, rc, sessStore)
	msg := messagesvc.New(fs, fs, sess, ratchetStore, rc)

	return &Wire{
		Identity: fs,
		Prekeys:  fs,
		Bundle:   fs,

		Prekey:   pk,
		Sessions: sess,
		Ratchets: ratchetStore,
		Messages: msg,
		Relay:    rc,
		HTTP:     rc.HTTP,
	}, nil
}
