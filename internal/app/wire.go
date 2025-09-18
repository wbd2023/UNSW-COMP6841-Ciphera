package app

import (
	"net/http"

	"ciphera/internal/domain"
	"ciphera/internal/relay"
	identitysvc "ciphera/internal/services/identity"
	messagesvc "ciphera/internal/services/message"
	prekeysvc "ciphera/internal/services/prekey"
	sessionsvc "ciphera/internal/services/session"
	"ciphera/internal/store"
)

// Wire bundles all stores, services, and clients for the CLI.
type Wire struct {
	IdentityService domain.IdentityService
	PreKeyService   domain.PreKeyService
	SessionService  domain.SessionService
	MessageService  domain.MessageService
	RelayClient     domain.RelayClient
	HTTPClient      *http.Client
}

// NewWire constructs the dependency graph from cfg.
func NewWire(cfg Config) (*Wire, error) {
	// File-based stores
	idStore := store.NewIdentityFileStore(cfg.HomeDir)
	prekeyStore := store.NewPrekeyFileStore(cfg.HomeDir)
	bundleStore := store.NewBundleFileStore(cfg.HomeDir)
	sessionStore := store.NewSessionFileStore(cfg.HomeDir)
	ratchetStore := store.NewRatchetFileStore(cfg.HomeDir)
	accountStore := store.NewAccountFileStore(cfg.HomeDir)

	// Ensure an HTTP client is available for outbound calls
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Relay client (uses provided HTTP client)
	relayClient := relay.NewHTTP(cfg.RelayURL, httpClient)

	// High-level services
	idSvc := identitysvc.New(idStore)
	prekeySvc := prekeysvc.New(idStore, prekeyStore, bundleStore, accountStore)
	sessionSvc := sessionsvc.New(idStore, bundleStore, sessionStore, relayClient)
	messageSvc := messagesvc.New(
		idStore,
		prekeyStore,
		ratchetStore,
		sessionSvc,
		relayClient,
		accountStore,
		cfg.RelayURL,
	)

	return &Wire{
		IdentityService: idSvc,
		PreKeyService:   prekeySvc,
		SessionService:  sessionSvc,
		MessageService:  messageSvc,
		RelayClient:     relayClient,
		HTTPClient:      httpClient,
	}, nil
}
