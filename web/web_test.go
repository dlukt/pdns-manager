package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dlukt/pdns-manager/auth"
	"github.com/dlukt/pdns-manager/ent"
	"github.com/dlukt/pdns-manager/pdns"
	"github.com/dlukt/pdns-manager/session"
)

type fakePDNSClient struct {
	servers     []pdns.Server
	listErr     error
	createCalls []createCall
	createErr   error
	deleteCalls []deleteCall
	deleteErr   error
}

type createCall struct {
	serverID string
	zone     pdns.Zone
}

type deleteCall struct {
	serverID string
	zoneID   string
}

func (f *fakePDNSClient) ListServers(_ context.Context) ([]pdns.Server, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	result := make([]pdns.Server, len(f.servers))
	copy(result, f.servers)
	return result, nil
}

func (f *fakePDNSClient) CreateZone(_ context.Context, serverID string, zone pdns.Zone) (*pdns.Zone, error) {
	f.createCalls = append(f.createCalls, createCall{serverID: serverID, zone: zone})
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &zone, nil
}

func (f *fakePDNSClient) DeleteZone(_ context.Context, serverID, zoneID string) error {
	f.deleteCalls = append(f.deleteCalls, deleteCall{serverID: serverID, zoneID: zoneID})
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return nil
}

func newTestHandler(t *testing.T, fake *fakePDNSClient) (http.Handler, *session.Store, string) {
	t.Helper()
	entClient := ent.NewClient()
	authSvc := auth.NewService(entClient, auth.NewLogMailer())
	sessions := session.NewStore([]byte("01234567890123456789012345678901"))
	handler := NewHandler(entClient, authSvc, sessions, fake)
	token, err := sessions.Create("user-id")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	return handler, sessions, token
}

func TestGetZoneNewRendersServers(t *testing.T) {
	fake := &fakePDNSClient{servers: []pdns.Server{{ID: "server-one"}, {ID: "server-two"}}}
	handler, _, token := newTestHandler(t, fake)

	req := httptest.NewRequest(http.MethodGet, "/zones/new", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "server-one") || !strings.Contains(body, "server-two") {
		t.Fatalf("response body did not contain server IDs: %s", body)
	}
}

func TestPostZoneCreateSuccess(t *testing.T) {
	fake := &fakePDNSClient{servers: []pdns.Server{{ID: "server-one"}}}
	handler, _, token := newTestHandler(t, fake)

	form := url.Values{}
	form.Set("server_id", "server-one")
	form.Set("name", "example.org.")
	form.Set("kind", "Native")
	req := httptest.NewRequest(http.MethodPost, "/zones", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	if location := rr.Header().Get("Location"); !strings.HasPrefix(location, "/zones?success=") {
		t.Fatalf("unexpected redirect location: %s", location)
	}
	if len(fake.createCalls) != 1 {
		t.Fatalf("expected one create call, got %d", len(fake.createCalls))
	}
	call := fake.createCalls[0]
	if call.serverID != "server-one" {
		t.Fatalf("expected server-one, got %s", call.serverID)
	}
	if call.zone.Name != "example.org." || call.zone.Kind != "Native" {
		t.Fatalf("unexpected zone payload: %#v", call.zone)
	}
}

func TestPostZoneCreateValidationError(t *testing.T) {
	fake := &fakePDNSClient{servers: []pdns.Server{{ID: "server-one"}}}
	handler, _, token := newTestHandler(t, fake)

	form := url.Values{}
	form.Set("server_id", "server-one")
	form.Set("kind", "Native")
	req := httptest.NewRequest(http.MethodPost, "/zones", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Zone name is required") {
		t.Fatalf("expected validation message, got: %s", rr.Body.String())
	}
	if len(fake.createCalls) != 0 {
		t.Fatalf("expected no create calls, got %d", len(fake.createCalls))
	}
}

func TestPostZoneCreateAPIFailure(t *testing.T) {
	fake := &fakePDNSClient{
		servers:   []pdns.Server{{ID: "server-one"}},
		createErr: errors.New("api failure"),
	}
	handler, _, token := newTestHandler(t, fake)

	form := url.Values{}
	form.Set("server_id", "server-one")
	form.Set("name", "example.org.")
	form.Set("kind", "Native")
	req := httptest.NewRequest(http.MethodPost, "/zones", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "api failure") {
		t.Fatalf("expected api failure message, got: %s", rr.Body.String())
	}
	if len(fake.createCalls) != 1 {
		t.Fatalf("expected one create call, got %d", len(fake.createCalls))
	}
}

func TestPostZoneDeleteSuccess(t *testing.T) {
	fake := &fakePDNSClient{}
	handler, _, token := newTestHandler(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/zones/server-one/example.org./delete", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	if len(fake.deleteCalls) != 1 {
		t.Fatalf("expected one delete call, got %d", len(fake.deleteCalls))
	}
	call := fake.deleteCalls[0]
	if call.serverID != "server-one" || call.zoneID != "example.org." {
		t.Fatalf("unexpected delete payload: %#v", call)
	}
	if location := rr.Header().Get("Location"); !strings.HasPrefix(location, "/zones?success=") {
		t.Fatalf("unexpected redirect location: %s", location)
	}
}

func TestPostZoneDeleteFailure(t *testing.T) {
	fake := &fakePDNSClient{deleteErr: errors.New("delete failed")}
	handler, _, token := newTestHandler(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/zones/server-one/example.org./delete", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	if location := rr.Header().Get("Location"); !strings.HasPrefix(location, "/zones?error=") {
		t.Fatalf("expected error redirect, got %s", location)
	}
}

func TestGetZoneNewListServersError(t *testing.T) {
	fake := &fakePDNSClient{listErr: errors.New("boom")}
	handler, _, token := newTestHandler(t, fake)

	req := httptest.NewRequest(http.MethodGet, "/zones/new", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "failed to load servers") {
		t.Fatalf("expected load servers error, got: %s", rr.Body.String())
	}
}
