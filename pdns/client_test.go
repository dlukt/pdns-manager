package pdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
