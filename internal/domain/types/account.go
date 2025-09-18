package types

// AccountProfile identifies a Ciphera account on a specific relay server.
type AccountProfile struct {
	ServerURL string   `json:"server_url"`
	Username  Username `json:"username"`
	Canary    string   `json:"canary"`
}
