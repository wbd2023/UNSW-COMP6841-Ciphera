// Package relay provides an HTTP RelayClient implementation for ciphera.
package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"ciphera/internal/domain"
)

// HTTP is a RelayClient over HTTP.
type HTTP struct {
	Base   string
	client *http.Client
}

// NewHTTP constructs a new HTTP relay client.
// If client is nil, http.DefaultClient will be used.
func NewHTTP(base string, client *http.Client) *HTTP {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTP{Base: base, client: client}
}

// RegisterPrekeyBundle publishes a PrekeyBundle to POST /register.
func (c *HTTP) RegisterPrekeyBundle(b domain.PrekeyBundle) error {
	return c.post("/register", b, nil)
}

// FetchPrekeyBundle retrieves the bundle for username via GET /prekey/{username}.
func (c *HTTP) FetchPrekeyBundle(username string) (domain.PrekeyBundle, error) {
	var out domain.PrekeyBundle
	if err := c.getJSON("/prekey/"+url.PathEscape(username), &out); err != nil {
		return domain.PrekeyBundle{}, err
	}
	return out, nil
}

// SendMessage posts an Envelope to POST /msg/{to}.
func (c *HTTP) SendMessage(env domain.Envelope) error {
	return c.post("/msg/"+url.PathEscape(env.To), env, nil)
}

// FetchMessages GETs up to limit Envelopes from /msg/{user}?limit=N.
func (c *HTTP) FetchMessages(username string, limit int) ([]domain.Envelope, error) {
	u := c.Base + "/msg/" + url.PathEscape(username)
	if limit > 0 {
		u += "?limit=" + strconv.Itoa(limit)
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("relay get %s: %s", u, resp.Status)
	}
	var envs []domain.Envelope
	return envs, json.NewDecoder(resp.Body).Decode(&envs)
}

// AckMessages sends an acknowledgment to POST /msg/{user}/ack with {count}.
func (c *HTTP) AckMessages(username string, count int) error {
	payload := struct {
		Count int `json:"count"`
	}{Count: count}
	return c.post("/msg/"+url.PathEscape(username)+"/ack", payload, nil)
}

// post is a helper for JSON-encoding a POST to path.
func (c *HTTP) post(path string, in any, out any) error {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(in); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.Base+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("relay post %s: %s", path, resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// getJSON performs a GET and JSON-decodes the response into out.
func (c *HTTP) getJSON(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.Base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("relay get %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Compile-time assertion that HTTP implements domain.RelayClient.
var _ domain.RelayClient = (*HTTP)(nil)
