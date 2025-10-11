package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dlukt/pdns-manager/pdns"
)

type stubPDNSClient struct {
	servers        []pdns.Server
	zones          map[string][]pdns.Zone
	errServers     error
	errZones       error
	lastZoneServer string
}

func (s *stubPDNSClient) ListServers(_ context.Context) ([]pdns.Server, error) {
	if s.errServers != nil {
		return nil, s.errServers
	}
	return s.servers, nil
}

func (s *stubPDNSClient) ListZones(_ context.Context, serverID string) ([]pdns.Zone, error) {
	s.lastZoneServer = serverID
	if s.errZones != nil {
		return nil, s.errZones
	}
	return s.zones[serverID], nil
}

func TestListZonesHappyPath(t *testing.T) {
	stub := &stubPDNSClient{
		servers: []pdns.Server{{ID: "srv1", DaemonType: "auth", Version: "1.0"}, {ID: "srv2", DaemonType: "auth", Version: "2.0"}},
		zones: map[string][]pdns.Zone{
			"srv2": {{ID: "example.com.", Name: "example.com.", Kind: "Native", Type: "Zone", Serial: 2025010101}},
		},
	}
	h := &handler{pdnsClient: stub}
	req := httptest.NewRequest(http.MethodGet, "/zones?server=srv2", nil)
	res := httptest.NewRecorder()

	h.listZones(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	body := res.Body.String()
	if !strings.Contains(body, "example.com.") {
		t.Fatalf("response body missing zone: %s", body)
	}
	if stub.lastZoneServer != "srv2" {
		t.Fatalf("expected ListZones to be called with srv2, got %q", stub.lastZoneServer)
	}
}

func TestListZonesServerError(t *testing.T) {
	stub := &stubPDNSClient{errServers: errors.New("boom")}
	h := &handler{pdnsClient: stub}
	req := httptest.NewRequest(http.MethodGet, "/zones", nil)
	res := httptest.NewRecorder()

	h.listZones(res, req)

	if res.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), "failed to load servers") {
		t.Fatalf("expected error message in response, got %q", res.Body.String())
	}
}
