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
	zoneDetails       *pdns.Zone
	zoneDetailsErr    error
	zoneDetailsServer string
	zoneDetailsID     string
	searchResults     []pdns.SearchResult
	searchErr         error
	searchServer      string
	searchQuery       string
	searchMax         int
	searchObjectType  string
	errCreate         error
	errDelete         error
	createZoneServer  string
	createdZone       pdns.Zone
	deletedZoneServer string
	deletedZoneID     string
	modifyServer      string
	modifyZoneID      string
	modifiedRRsets    []pdns.RRSet
	modifyErr         error
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

func (s *stubPDNSClient) GetZone(_ context.Context, serverID, zoneID string) (*pdns.Zone, error) {
	s.zoneDetailsServer = serverID
	s.zoneDetailsID = zoneID
	if s.zoneDetailsErr != nil {
		return nil, s.zoneDetailsErr
	}
	return s.zoneDetails, nil
}

func (s *stubPDNSClient) SearchData(_ context.Context, serverID, q string, max int, objectType string) ([]pdns.SearchResult, error) {
	s.searchServer = serverID
	s.searchQuery = q
	s.searchMax = max
	s.searchObjectType = objectType
	if s.searchErr != nil {
		return nil, s.searchErr
	}
	return s.searchResults, nil
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

func (s *stubPDNSClient) ModifyRRsets(_ context.Context, serverID, zoneID string, rrsets []pdns.RRSet) error {
	s.modifyServer = serverID
	s.modifyZoneID = zoneID
	s.modifiedRRsets = rrsets
	if s.modifyErr != nil {
		return s.modifyErr
	}
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

func TestGetSearchCallsSearchData(t *testing.T) {
	stub := &stubPDNSClient{
		servers: []pdns.Server{{ID: "srv1"}, {ID: "srv2"}},
		searchResults: []pdns.SearchResult{{
			Name:    "www.example.com",
			Type:    "A",
			Content: "1.2.3.4",
			Zone:    "example.com.",
			TTL:     300,
		}},
	}
	h := &handler{pdnsClient: stub}
	req := httptest.NewRequest(http.MethodGet, "/search?server=srv2&q=example&max=25&object_type=record", nil)
	res := httptest.NewRecorder()

	h.getSearch(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	if stub.searchServer != "srv2" {
		t.Fatalf("expected SearchData server to be srv2, got %q", stub.searchServer)
	}
	if stub.searchQuery != "example" {
		t.Fatalf("expected SearchData query to be example, got %q", stub.searchQuery)
	}
	if stub.searchMax != 25 {
		t.Fatalf("expected SearchData max to be 25, got %d", stub.searchMax)
	}
	if stub.searchObjectType != "record" {
		t.Fatalf("expected SearchData object type to be record, got %q", stub.searchObjectType)
	}
	body := res.Body.String()
	if !strings.Contains(body, "www.example.com") {
		t.Fatalf("expected search result in response, got %q", body)
	}
}

func TestGetZoneRecordsRendersRRsets(t *testing.T) {
	stub := &stubPDNSClient{
		servers: []pdns.Server{{ID: "srv1"}},
		zoneDetails: &pdns.Zone{
			ID:   "example.com.",
			Name: "example.com.",
			RRsets: []pdns.RRSet{{
				Name: "www.example.com.",
				Type: "A",
				TTL:  3600,
				Records: []pdns.Record{{
					Content:  "1.2.3.4",
					Disabled: false,
				}},
			}},
		},
	}
	h := &handler{pdnsClient: stub}
	req := httptest.NewRequest(http.MethodGet, "/zones/srv1/example.com./", nil)
	req.SetPathValue("serverID", "srv1")
	req.SetPathValue("zoneID", "example.com.")
	res := httptest.NewRecorder()

	h.getZoneRecords(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}
	if stub.zoneDetailsServer != "srv1" {
		t.Fatalf("expected GetZone server to be srv1, got %q", stub.zoneDetailsServer)
	}
	if stub.zoneDetailsID != "example.com." {
		t.Fatalf("expected GetZone zoneID to be example.com., got %q", stub.zoneDetailsID)
	}
	body := res.Body.String()
	if !strings.Contains(body, "www.example.com.") {
		t.Fatalf("expected rrset name in response, got %q", body)
	}
	if !strings.Contains(body, "1.2.3.4") {
		t.Fatalf("expected record content in response, got %q", body)
	}
}

func TestPostZoneRecordAddCreatesRRset(t *testing.T) {
	stub := &stubPDNSClient{
		zoneDetails: &pdns.Zone{
			ID:   "example.com.",
			Name: "example.com.",
		},
	}
	h := &handler{pdnsClient: stub}
	form := url.Values{
		"name":    {"www.example.com"},
		"type":    {"A"},
		"ttl":     {"300"},
		"content": {"1.2.3.4"},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones/srv1/example.com./records", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("serverID", "srv1")
	req.SetPathValue("zoneID", "example.com.")
	res := httptest.NewRecorder()

	h.postZoneRecordAdd(res, req)

	if res.Code != http.StatusFound {
		t.Fatalf("expected redirect, got status %d", res.Code)
	}
	if stub.modifyServer != "srv1" {
		t.Fatalf("expected ModifyRRsets server to be srv1, got %q", stub.modifyServer)
	}
	if stub.modifyZoneID != "example.com." {
		t.Fatalf("expected ModifyRRsets zoneID to be example.com., got %q", stub.modifyZoneID)
	}
	if len(stub.modifiedRRsets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(stub.modifiedRRsets))
	}
	rrset := stub.modifiedRRsets[0]
	if rrset.Changetype != "REPLACE" {
		t.Fatalf("expected changetype REPLACE, got %q", rrset.Changetype)
	}
	if rrset.Name != "www.example.com." {
		t.Fatalf("expected rrset name to be www.example.com., got %q", rrset.Name)
	}
	if rrset.Type != "A" {
		t.Fatalf("expected rrset type A, got %q", rrset.Type)
	}
	if rrset.TTL != 300 {
		t.Fatalf("expected rrset ttl 300, got %d", rrset.TTL)
	}
	if len(rrset.Records) != 1 || rrset.Records[0].Content != "1.2.3.4" {
		t.Fatalf("unexpected rrset records: %+v", rrset.Records)
	}
}

func TestPostZoneRecordAddAppendsToExistingRRset(t *testing.T) {
	stub := &stubPDNSClient{
		zoneDetails: &pdns.Zone{
			ID:   "example.com.",
			Name: "example.com.",
			RRsets: []pdns.RRSet{{
				Name: "www.example.com.",
				Type: "A",
				TTL:  120,
				Records: []pdns.Record{{
					Content:  "1.2.3.4",
					Disabled: false,
				}},
			}},
		},
	}
	h := &handler{pdnsClient: stub}
	form := url.Values{
		"name":    {"www.example.com"},
		"type":    {"A"},
		"ttl":     {""},
		"content": {"5.6.7.8"},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones/srv1/example.com./records", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("serverID", "srv1")
	req.SetPathValue("zoneID", "example.com.")
	res := httptest.NewRecorder()

	h.postZoneRecordAdd(res, req)

	if res.Code != http.StatusFound {
		t.Fatalf("expected redirect, got status %d", res.Code)
	}
	if len(stub.modifiedRRsets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(stub.modifiedRRsets))
	}
	rrset := stub.modifiedRRsets[0]
	if rrset.TTL != 120 {
		t.Fatalf("expected rrset ttl 120, got %d", rrset.TTL)
	}
	if len(rrset.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(rrset.Records))
	}
}

func TestPostZoneRecordDeleteSingleRecord(t *testing.T) {
	stub := &stubPDNSClient{
		zoneDetails: &pdns.Zone{
			ID:   "example.com.",
			Name: "example.com.",
			RRsets: []pdns.RRSet{{
				Name: "www.example.com.",
				Type: "A",
				TTL:  60,
				Records: []pdns.Record{{
					Content:  "1.2.3.4",
					Disabled: false,
				}, {
					Content:  "5.6.7.8",
					Disabled: false,
				}},
			}},
		},
	}
	h := &handler{pdnsClient: stub}
	form := url.Values{
		"name":    {"www.example.com."},
		"type":    {"A"},
		"content": {"5.6.7.8"},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones/srv1/example.com./records/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("serverID", "srv1")
	req.SetPathValue("zoneID", "example.com.")
	res := httptest.NewRecorder()

	h.postZoneRecordDelete(res, req)

	if res.Code != http.StatusFound {
		t.Fatalf("expected redirect, got status %d", res.Code)
	}
	if len(stub.modifiedRRsets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(stub.modifiedRRsets))
	}
	rrset := stub.modifiedRRsets[0]
	if rrset.Changetype != "REPLACE" {
		t.Fatalf("expected changetype REPLACE, got %q", rrset.Changetype)
	}
	if len(rrset.Records) != 1 || rrset.Records[0].Content != "1.2.3.4" {
		t.Fatalf("unexpected remaining records: %+v", rrset.Records)
	}
}

func TestPostZoneRecordUpdateReplacesContent(t *testing.T) {
	stub := &stubPDNSClient{
		zoneDetails: &pdns.Zone{
			ID:   "example.com.",
			Name: "example.com.",
			RRsets: []pdns.RRSet{{
				Name: "www.example.com.",
				Type: "A",
				TTL:  120,
				Records: []pdns.Record{{
					Content:  "1.2.3.4",
					Disabled: false,
				}},
			}},
		},
	}
	h := &handler{pdnsClient: stub}
	form := url.Values{
		"name":      {"www.example.com."},
		"type":      {"A"},
		"old_value": {"1.2.3.4"},
		"new_value": {"5.6.7.8"},
		"ttl":       {"300"},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones/srv1/example.com./records/update", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("serverID", "srv1")
	req.SetPathValue("zoneID", "example.com.")
	res := httptest.NewRecorder()

	h.postZoneRecordUpdate(res, req)

	if res.Code != http.StatusFound {
		t.Fatalf("expected redirect, got status %d", res.Code)
	}
	if len(stub.modifiedRRsets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(stub.modifiedRRsets))
	}
	rrset := stub.modifiedRRsets[0]
	if rrset.TTL != 300 {
		t.Fatalf("expected rrset ttl 300, got %d", rrset.TTL)
	}
	if len(rrset.Records) != 1 || rrset.Records[0].Content != "5.6.7.8" {
		t.Fatalf("unexpected record content: %+v", rrset.Records)
	}
}

func TestPostZoneRecordDeleteRemovesRRset(t *testing.T) {
	stub := &stubPDNSClient{
		zoneDetails: &pdns.Zone{
			ID:   "example.com.",
			Name: "example.com.",
			RRsets: []pdns.RRSet{{
				Name: "www.example.com.",
				Type: "A",
				TTL:  300,
				Records: []pdns.Record{{
					Content:  "1.2.3.4",
					Disabled: false,
				}},
			}},
		},
	}
	h := &handler{pdnsClient: stub}
	form := url.Values{
		"name": {"www.example.com."},
		"type": {"A"},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones/srv1/example.com./records/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("serverID", "srv1")
	req.SetPathValue("zoneID", "example.com.")
	res := httptest.NewRecorder()

	h.postZoneRecordDelete(res, req)

	if res.Code != http.StatusFound {
		t.Fatalf("expected redirect, got status %d", res.Code)
	}
	if len(stub.modifiedRRsets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(stub.modifiedRRsets))
	}
	rrset := stub.modifiedRRsets[0]
	if rrset.Changetype != "DELETE" {
		t.Fatalf("expected changetype DELETE, got %q", rrset.Changetype)
	}
	if rrset.Name != "www.example.com." {
		t.Fatalf("expected rrset name to be www.example.com., got %q", rrset.Name)
	}
}
