package app

import (
	"net/http"
)

// Config holds settings for wiring up the application.
type Config struct {
	Home     string       // path to config directory
	RelayURL string       // base URL of the relay server
	HTTP     *http.Client // HTTP client (with timeouts) to use for network calls
}
