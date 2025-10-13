package pdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestListServers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret" {
			t.Fatalf("missing API key")
		}
		w.Header().Set("Content-Type", "application/json")
		data := []Server{{ID: "localhost"}}
		json.NewEncoder(w).Encode(data)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := NewClient(srv.URL, "secret", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()
	servers, err := c.ListServers(ctx)
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(servers) != 1 || servers[0].ID != "localhost" {
		t.Fatalf("unexpected servers: %+v", servers)
	}
}

func TestCreateZone(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/servers/localhost/zones", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method %s", r.Method)
		}
		var z Zone
		if err := json.NewDecoder(r.Body).Decode(&z); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if z.Name != "example.org." {
			t.Fatalf("zone name %s", z.Name)
		}
		z.ID = z.Name
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(z)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := NewClient(srv.URL, "", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()
	zone := Zone{Name: "example.org.", Kind: "Master"}
	res, err := c.CreateZone(ctx, "localhost", zone)
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	if res.ID != "example.org." {
		t.Fatalf("unexpected zone: %+v", res)
	}
}

func TestClientPathEscaping(t *testing.T) {
	serverID := "srv with space"
	zoneID := "example.com/with/slash"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			t.Fatalf("unexpected method %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(struct {
			ID string `json:"id"`
		}{ID: zoneID})
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			expected := "/servers/" + url.PathEscape(serverID) + "/zones"
			if r.URL.EscapedPath() != expected {
				t.Fatalf("unexpected create path %q", r.URL.EscapedPath())
			}
		case http.MethodDelete:
			expected := "/servers/" + url.PathEscape(serverID) + "/zones/" + url.PathEscape(zoneID)
			if r.URL.EscapedPath() != expected {
				t.Fatalf("unexpected delete path %q", r.URL.EscapedPath())
			}
		}
		mux.ServeHTTP(w, r)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.CreateZone(context.Background(), serverID, Zone{Name: zoneID}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	if err := c.DeleteZone(context.Background(), serverID, zoneID); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
}

func TestClientBasePath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/servers", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/v1/servers" {
			t.Fatalf("unexpected path %q", r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]Server{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := NewClient(srv.URL+"/api/v1", "", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.ListServers(context.Background()); err != nil {
		t.Fatalf("ListServers: %v", err)
	}
}
