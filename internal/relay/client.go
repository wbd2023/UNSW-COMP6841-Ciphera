package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"ciphera/internal/domain"
)

type HTTPClient struct {
	Base string
	HTTP *http.Client
}

func NewHTTP(base string) *HTTPClient {
	return &HTTPClient{
		Base: base,
		HTTP: http.DefaultClient,
	}
}

var _ domain.RelayClient = (*HTTPClient)(nil)

func (c *HTTPClient) Register(bundle domain.PrekeyBundle) error {
	b, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Post(c.Base+"/register", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("register failed: %s", resp.Status)
	}
	return nil
}
