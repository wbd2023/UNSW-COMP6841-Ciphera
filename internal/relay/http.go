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

type HTTP struct {
	Base string
	HTTP *http.Client
}

func NewHTTP(base string) *HTTP { return &HTTP{Base: base, HTTP: http.DefaultClient} }

func (c *HTTP) Register(b domain.PrekeyBundle) error {
	return c.post("/register", b, nil)
}

func (c *HTTP) FetchPrekey(username string) (domain.PrekeyBundle, error) {
	var out domain.PrekeyBundle
	if err := c.getJSON("/prekey/"+url.PathEscape(username), &out); err != nil {
		return domain.PrekeyBundle{}, err
	}
	return out, nil
}

func (c *HTTP) SendMessage(env domain.Envelope) error {
	// env.Prekey will be serialised if non-nil
	return c.post("/msg/"+url.PathEscape(env.To), env, nil)
}

func (c *HTTP) FetchMessages(username string, limit int) ([]domain.Envelope, error) {
	u := c.Base + "/msg/" + url.PathEscape(username)
	if limit > 0 {
		u += "?limit=" + strconv.Itoa(limit)
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
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

func (c *HTTP) AckMessages(username string, count int) error {
	return c.post("/msg/"+url.PathEscape(username)+"/ack", struct {
		Count int `json:"count"`
	}{Count: count}, nil)
}

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
	resp, err := c.HTTP.Do(req)
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

func (c *HTTP) getJSON(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.Base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("relay get %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

var _ domain.RelayClient = (*HTTP)(nil)
