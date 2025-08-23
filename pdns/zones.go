package pdns

import (
	"context"
	"fmt"
	"net/http"
)

// ListZones returns all zones from the given server.
func (c *Client) ListZones(ctx context.Context, serverID string) ([]Zone, error) {
	path := fmt.Sprintf("/servers/%s/zones", serverID)
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var zones []Zone
	if err := c.do(req, &zones); err != nil {
		return nil, err
	}
	return zones, nil
}

// GetZone retrieves the zone details.
func (c *Client) GetZone(ctx context.Context, serverID, zoneID string) (*Zone, error) {
	path := fmt.Sprintf("/servers/%s/zones/%s", serverID, zoneID)
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var z Zone
	if err := c.do(req, &z); err != nil {
		return nil, err
	}
	return &z, nil
}

// CreateZone creates a new zone on the specified server.
func (c *Client) CreateZone(ctx context.Context, serverID string, zone Zone) (*Zone, error) {
	path := fmt.Sprintf("/servers/%s/zones", serverID)
	req, err := c.newRequest(ctx, http.MethodPost, path, zone)
	if err != nil {
		return nil, err
	}
	var created Zone
	if err := c.do(req, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// DeleteZone removes an existing zone from the server.
func (c *Client) DeleteZone(ctx context.Context, serverID, zoneID string) error {
	path := fmt.Sprintf("/servers/%s/zones/%s", serverID, zoneID)
	req, err := c.newRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// ModifyRRsets applies RRSet changes to the given zone.
func (c *Client) ModifyRRsets(ctx context.Context, serverID, zoneID string, rrsets []RRSet) error {
	payload := map[string]interface{}{"rrsets": rrsets}
	path := fmt.Sprintf("/servers/%s/zones/%s", serverID, zoneID)
	req, err := c.newRequest(ctx, http.MethodPatch, path, payload)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}
