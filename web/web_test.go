package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dlukt/pdns-manager/pdns"
)

type stubPDNSClient struct {
	servers           []pdns.Server
	zones             map[string][]pdns.Zone
	errServers        error
	errZones          error
	lastZoneServer    string
	errCreate         error
	errDelete         error
	createZoneServer  string
	createdZone       pdns.Zone
	deletedZoneServer string
	deletedZoneID     string
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

func (s *stubPDNSClient) CreateZone(_ context.Context, serverID string, zone pdns.Zone) (*pdns.Zone, error) {
	if s.errCreate != nil {
		return nil, s.errCreate
	}
	s.createZoneServer = serverID
	s.createdZone = zone
	return &zone, nil
}

func (s *stubPDNSClient) DeleteZone(_ context.Context, serverID, zoneID string) error {
	if s.errDelete != nil {
		return s.errDelete
	}
	s.deletedZoneServer = serverID
	s.deletedZoneID = zoneID
	return nil
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

func TestPostZoneCreateRedirectsToZones(t *testing.T) {
	stub := &stubPDNSClient{
		servers: []pdns.Server{{ID: "srv1"}},
	}
	h := &handler{pdnsClient: stub, zoneKinds: []string{"Native", "Master", "Slave"}}
	form := url.Values{
		"server_id": {"srv1"},
		"name":      {"example.com."},
		"kind":      {"Native"},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()

	h.postZoneCreate(res, req)

	if res.Code != http.StatusFound {
		t.Fatalf("expected redirect, got status %d", res.Code)
	}
	loc := res.Header().Get("Location")
	if loc == "" {
		t.Fatalf("expected Location header to be set")
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}
	if parsed.Path != "/zones" {
		t.Fatalf("expected redirect to /zones, got %s", parsed.Path)
	}
	if got := parsed.Query().Get("server"); got != "srv1" {
		t.Fatalf("expected server query to be srv1, got %q", got)
	}
	if success := parsed.Query().Get("success"); !strings.Contains(success, "example.com.") {
		t.Fatalf("expected success message to mention zone, got %q", success)
	}
	if stub.createZoneServer != "srv1" {
		t.Fatalf("expected CreateZone to be called with srv1, got %q", stub.createZoneServer)
	}
	if stub.createdZone.Name != "example.com." {
		t.Fatalf("expected created zone name to be example.com., got %q", stub.createdZone.Name)
	}
}

func TestPostZoneDeleteRedirectsToZones(t *testing.T) {
	stub := &stubPDNSClient{}
	h := &handler{pdnsClient: stub}
	req := httptest.NewRequest(http.MethodPost, "/zones/srv1/example.com./delete", nil)
	req.SetPathValue("serverID", "srv1")
	req.SetPathValue("zoneID", "example.com.")
	res := httptest.NewRecorder()

	h.postZoneDelete(res, req)

	if res.Code != http.StatusFound {
		t.Fatalf("expected redirect, got status %d", res.Code)
	}
	loc := res.Header().Get("Location")
	if loc == "" {
		t.Fatalf("expected Location header to be set")
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}
	if parsed.Path != "/zones" {
		t.Fatalf("expected redirect to /zones, got %s", parsed.Path)
	}
	if got := parsed.Query().Get("server"); got != "srv1" {
		t.Fatalf("expected server query to be srv1, got %q", got)
	}
	if success := parsed.Query().Get("success"); !strings.Contains(success, "example.com.") {
		t.Fatalf("expected success message to mention zone, got %q", success)
	}
	if stub.deletedZoneServer != "srv1" || stub.deletedZoneID != "example.com." {
		t.Fatalf("unexpected delete args: server=%q zone=%q", stub.deletedZoneServer, stub.deletedZoneID)
	}
}
