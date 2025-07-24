package app

import "ciphera/internal/domain"

type App struct {
	IDs     domain.IdentityService
	Prekeys domain.PrekeyService
	Relay   domain.RelayClient
}

func New(ids domain.IdentityService, prekeys domain.PrekeyService, relay domain.RelayClient) *App {
	return &App{
		IDs:     ids,
		Prekeys: prekeys,
		Relay:   relay,
	}
}
