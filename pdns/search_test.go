package pdns

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_SearchData(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := NewClient(server.URL, "secret", nil)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	mux.HandleFunc("/servers/localhost/search-data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected method GET, got %s", r.Method)
		}
		if r.Header.Get("X-API-Key") != "secret" {
			t.Errorf("expected X-API-Key header")
		}

		q := r.URL.Query().Get("q")
		max := r.URL.Query().Get("max")
		objectType := r.URL.Query().Get("object_type")

		if q != "example" {
			t.Errorf("expected q=example, got %s", q)
		}
		if max != "10" {
			t.Errorf("expected max=10, got %s", max)
		}
		if objectType != "record" {
			t.Errorf("expected object_type=record, got %s", objectType)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[
			{
				"content": "1.2.3.4",
				"disabled": false,
				"name": "www.example.com",
				"object_type": "record",
				"zone_id": "example.com.",
				"zone": "example.com.",
				"type": "A",
				"ttl": 3600
			}
		]`)
	})

	results, err := client.SearchData(context.Background(), "localhost", "example", 10, "record")
	if err != nil {
		t.Fatalf("SearchData failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Name != "www.example.com" {
		t.Errorf("expected name www.example.com, got %s", res.Name)
	}
	if res.Type != "A" {
		t.Errorf("expected type A, got %s", res.Type)
	}
}
