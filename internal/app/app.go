package app

import "ciphera/internal/domain"

type App struct {
	IDs domain.IdentityService
}

func New(ids domain.IdentityService) *App {
	return &App{IDs: ids}
}
