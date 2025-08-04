package app

import "net/http"

// Config holds runtime wiring options for building the app.
type Config struct {
	Home     string       // config directory, e.g. $HOME/.ciphera
	RelayURL string       // relay base URL, e.g. http://127.0.0.1:8080
	HTTP     *http.Client // optional; defaults to http.DefaultClient
}
