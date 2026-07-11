package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client provides access to the PowerDNS Authoritative HTTP API.
type Client struct {
	endpoint *url.URL
	apiKey   string
	http     *http.Client
}

// defaultHTTPClient returns an *http.Client with a bounded timeout and a
// redirect policy that never forwards the X-API-Key header to a different host.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Compare hostname (not Host, which includes the port) so a same-host
			// port change such as http -> https:443 is still allowed.
			if len(via) > 0 && req.URL.Hostname() != via[0].URL.Hostname() {
				// Refuse cross-host redirects so the API key is never leaked.
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
}

// NewClient creates a new API client. The endpoint should include the
// base path of the API, for example "http://localhost:8081/api/v1". When
// httpClient is nil the client uses a safe default: a 30s timeout and a
// redirect policy that never forwards the API key to another host.
func NewClient(endpoint, apiKey string, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: u, apiKey: apiKey, http: httpClient}, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	basePath := strings.TrimSuffix(c.endpoint.EscapedPath(), "/")
	var fullPath string
	switch {
	case path == "":
		if basePath == "" {
			fullPath = "/"
		} else {
			fullPath = basePath
		}
	case strings.HasPrefix(path, "/"):
		if basePath == "" {
			fullPath = path
		} else {
			fullPath = basePath + path
		}
	default:
		if basePath == "" {
			fullPath = "/" + path
		} else {
			fullPath = basePath + "/" + path
		}
	}

	u := *c.endpoint
	decodedPath, err := url.PathUnescape(fullPath)
	if err != nil {
		decodedPath = fullPath
	}
	u.Path = decodedPath
	u.RawPath = fullPath

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

func (c *Client) path(segments ...string) string {
	if len(segments) == 0 {
		return "/"
	}
	parts := make([]string, len(segments))
	for i, segment := range segments {
		parts[i] = url.PathEscape(segment)
	}
	return "/" + strings.Join(parts, "/")
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
