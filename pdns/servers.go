package pdns

import (
	"context"
	"net/http"
)

// ListServers returns all configured servers.
func (c *Client) ListServers(ctx context.Context) ([]Server, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/servers", nil)
	if err != nil {
		return nil, err
	}
	var servers []Server
	if err := c.do(req, &servers); err != nil {
		return nil, err
	}
	return servers, nil
}

// GetServer returns details about a specific server.
func (c *Client) GetServer(ctx context.Context, id string) (*Server, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/servers/"+id, nil)
	if err != nil {
		return nil, err
	}
	var server Server
	if err := c.do(req, &server); err != nil {
		return nil, err
	}
	return &server, nil
}
