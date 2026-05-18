package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeAPIEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"v1/items", "/api/v1/items"},
		{"/v1/items", "/api/v1/items"},
		{"/api/v1/items", "/api/v1/items"},
		{"items", "/api/v1/items"},
	}
	for _, tc := range cases {
		got := normalizeAPIEndpoint(tc.in)
		if got != tc.want {
			t.Fatalf("normalizeAPIEndpoint(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRunAPIPrettyAndRaw(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/items" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing auth header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"1","name":"n"}],"totalCount":1}`))
	}))
	defer srv.Close()

	oldClient := apiHTTPClient
	apiHTTPClient = srv.Client()
	apiHTTPClient.Timeout = 2 * time.Second
	t.Cleanup(func() { apiHTTPClient = oldClient })

	pretty, err := runAPI([]string{"--method", "GET", "--endpoint", "v1/items"}, srv.URL, "token", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(pretty, "\n  \"items\"") {
		t.Fatalf("expected pretty JSON output, got: %s", pretty)
	}

	raw, err := runAPI([]string{"--method", "GET", "--endpoint", "v1/items", "--json"}, srv.URL, "token", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(raw, "\n  ") {
		t.Fatalf("expected raw compact JSON, got pretty output")
	}
}

func TestRunAPIInvalidParamsJSON(t *testing.T) {
	_, err := runAPI([]string{"--method", "POST", "--endpoint", "v1/items", "--params", "{bad"}, "https://example.com", "token", "")
	if err == nil {
		t.Fatalf("expected error for invalid params JSON")
	}
}

func TestRunAPIPOSTSendsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"name":"cli vault name"}` {
			t.Fatalf("unexpected body: %s", string(body))
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	oldClient := apiHTTPClient
	apiHTTPClient = srv.Client()
	t.Cleanup(func() { apiHTTPClient = oldClient })

	_, err := runAPI([]string{"--method", "POST", "--endpoint", "v1/vaults", "--params", `{"name":"cli vault name"}`}, srv.URL, "token", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
