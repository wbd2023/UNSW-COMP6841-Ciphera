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

// Wire bundles all stores, services, and clients for the CLI.
type Wire struct {
	Identity domain.IdentityStore
	Prekey   domain.PrekeyService
	Sessions domain.SessionService
	Messages domain.MessageService
	Relay    domain.RelayClient
	HTTP     *http.Client
}

// NewWire constructs the dependency graph from cfg.
func NewWire(cfg Config) (*Wire, error) {
	// File-based stores
	identityStore := store.NewIdentityFileStore(cfg.Home)
	prekeyStore := store.NewPrekeyFileStore(cfg.Home)
	bundleStore := store.NewBundleFileStore(cfg.Home)
	sessionStore := store.NewSessionFileStore(cfg.Home)
	ratchetStore := store.NewRatchetFileStore(cfg.Home)

	// Ensure an HTTP client is available for outbound calls
	httpClient := cfg.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Relay client (uses provided HTTP client)
	rc := relay.NewHTTP(cfg.RelayURL, httpClient)

	// High-level services
	prekeySvc := prekeysvc.New(identityStore, prekeyStore, bundleStore)
	sessionSvc := sessionsvc.New(identityStore, bundleStore, rc, sessionStore)
	messageSvc := messagesvc.New(identityStore, prekeyStore, sessionSvc, ratchetStore, rc)

	return &Wire{
		Identity: identityStore,
		Prekey:   prekeySvc,
		Sessions: sessionSvc,
		Messages: messageSvc,
		Relay:    rc,
		HTTP:     httpClient,
	}, nil
}
