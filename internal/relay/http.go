package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"ciphera/internal/domain"
)

// HTTP is a RelayClient over HTTP.
//
// Base should be the relay server's base URL, for example:
//
//	http://127.0.0.1:8080
//
// client is the underlying HTTP client used for all requests.
type HTTP struct {
	Base   string
	client *http.Client
}

// NewHTTP constructs a new HTTP relay client.
//
// If client is nil, http.DefaultClient is used.
func NewHTTP(base string, client *http.Client) *HTTP {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTP{Base: base, client: client}
}

// RegisterPreKeyBundle publishes a PreKeyBundle to POST /register.
//
// The server expects a JSON body describing the caller's current prekeys.
func (c *HTTP) RegisterPreKeyBundle(ctx context.Context, bundle domain.PreKeyBundle) error {
	return c.postJSON(ctx, "/register", bundle, nil)
}

// FetchPreKeyBundle retrieves the bundle for username via GET /prekey/{username}.
//
// The response body is JSON and is decoded into a domain.PreKeyBundle.
func (c *HTTP) FetchPreKeyBundle(
	ctx context.Context,
	username domain.Username,
) (domain.PreKeyBundle, error) {
	var out domain.PreKeyBundle
	path := fmt.Sprintf("/prekey/%s", url.PathEscape(username.String()))
	if err := c.getJSON(ctx, path, &out); err != nil {
		return domain.PreKeyBundle{}, err
	}
	return out, nil
}

// SendMessage posts an Envelope to POST /msg/{to}.
//
// The envelope is sent as JSON. A non-2xx status is treated as an error.
func (c *HTTP) SendMessage(ctx context.Context, envelope domain.Envelope) error {
	path := fmt.Sprintf("/msg/%s", url.PathEscape(envelope.To.String()))
	return c.postJSON(ctx, path, envelope, nil)
}

// FetchMessages GETs up to limit envelopes from /msg/{user}?limit=N.
//
// If limit > 0, a query parameter is added to restrict the number of results.
// The response is a JSON array decoded into []domain.Envelope.
func (c *HTTP) FetchMessages(
	ctx context.Context,
	username domain.Username,
	limit int,
) ([]domain.Envelope, error) {
	// Build path using a URL-safe username, then combine with base.
	path := fmt.Sprintf("/msg/%s", url.PathEscape(username.String()))

	fullURL, err := url.JoinPath(c.Base, path)
	if err != nil {
		// Fallback keeps compatibility if Base has trailing slash issues
		// or when running with older Go toolchains.
		fullURL = c.Base + path
	}

	// Parse so we can add query parameters safely.
	u, err := url.Parse(fullURL)
	if err != nil {
		return nil, err
	}
	if limit > 0 {
		q := u.Query()
		q.Set("limit", strconv.Itoa(limit))
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	var envelopes []domain.Envelope
	if err := c.do(req, &envelopes); err != nil {
		return nil, err
	}
	return envelopes, nil
}

// AckMessages sends an acknowledgment to POST /msg/{user}/ack with {count}.
//
// The payload is JSON: {"count": N}. Servers use this to delete or mark
// messages as delivered.
func (c *HTTP) AckMessages(ctx context.Context, username domain.Username, count int) error {
	payload := struct {
		Count int `json:"count"`
	}{Count: count}

	path := fmt.Sprintf("/msg/%s/ack", url.PathEscape(username.String()))
	return c.postJSON(ctx, path, payload, nil)
}

// postJSON encodes in as JSON and POSTs to path, optionally decoding out.
//
// path is joined with the client's Base. A non-2xx status returns an error.
func (c *HTTP) postJSON(
	ctx context.Context,
	path string,
	in any,
	out any,
) error {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(in); err != nil {
		return err
	}

	fullURL, err := url.JoinPath(c.Base, path)
	if err != nil {
		fullURL = c.Base + path
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	return c.do(req, out)
}

// getJSON performs a GET to path and JSON-decodes the response into out.
func (c *HTTP) getJSON(
	ctx context.Context,
	path string,
	out any,
) error {
	fullURL, err := url.JoinPath(c.Base, path)
	if err != nil {
		fullURL = c.Base + path
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

// do executes req, requires a 2xx status, and optionally JSON-decodes into out.
//
// Errors include the HTTP method, full URL, and status text to aid debugging.
// If out is nil, the response body is discarded after the status check.
func (c *HTTP) do(req *http.Request, out any) error {
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if !is2xx(resp.StatusCode) {
		return fmt.Errorf("relay %s %s: %s", req.Method, req.URL.String(), resp.Status)
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// is2xx reports whether code is in the 2xx range.
func is2xx(code int) bool {
	return code >= http.StatusOK && code < http.StatusMultipleChoices
}

// Compile-time assertion that HTTP implements domain.RelayClient.
var _ domain.RelayClient = (*HTTP)(nil)
