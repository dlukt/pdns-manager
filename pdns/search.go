package pdns

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// SearchData searches for data across all zones on the server.
func (c *Client) SearchData(ctx context.Context, serverID string, q string, max int, objectType string) ([]SearchResult, error) {
	path := c.path("servers", serverID, "search-data")

	params := url.Values{}
	params.Set("q", q)
	if max > 0 {
		params.Set("max", fmt.Sprintf("%d", max))
	}
	if objectType != "" {
		params.Set("object_type", objectType)
	}

	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	req.URL.RawQuery = params.Encode()

	var results []SearchResult
	if err := c.do(req, &results); err != nil {
		return nil, err
	}
	return results, nil
}
