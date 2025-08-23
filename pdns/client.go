package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Client provides access to the PowerDNS Authoritative HTTP API.
type Client struct {
	endpoint *url.URL
	apiKey   string
	http     *http.Client
}

// NewClient creates a new API client. The endpoint should include the
// base path of the API, for example "http://localhost:8081/api/v1".
func NewClient(endpoint, apiKey string, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: u, apiKey: apiKey, http: httpClient}, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	rel := &url.URL{Path: path}
	u := c.endpoint.ResolveReference(rel)
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	return req, nil
}

func (c *Client) do(req *http.Request, v interface{}) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", resp.Status, string(b))
	}
	if v != nil {
		return json.NewDecoder(resp.Body).Decode(v)
	}
	return nil
}
