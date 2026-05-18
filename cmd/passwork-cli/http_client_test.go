package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJoinAPIURL(t *testing.T) {
	cases := []struct {
		base     string
		endpoint string
		want     string
	}{
		{"https://passwork.example.com", "/api/v1/items", "https://passwork.example.com/api/v1/items"},
		{"https://passwork.example.com/", "/api/v1/items", "https://passwork.example.com/api/v1/items"},
		{"https://passwork.example.com/", "api/v1/items", "https://passwork.example.com/api/v1/items"},
	}
	for _, tc := range cases {
		got := joinAPIURL(tc.base, tc.endpoint)
		if got != tc.want {
			t.Fatalf("joinAPIURL(%q, %q)=%q, want %q", tc.base, tc.endpoint, got, tc.want)
		}
	}
}

func TestDoAPIRequestHeadersAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing Authorization header")
		}
		if r.Header.Get("Passwork-MasterKeyHash") != "mph123" {
			t.Fatalf("missing mph header")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("missing content-type header")
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"name":"x"}` {
			t.Fatalf("unexpected body: %s", string(b))
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	oldClient := apiHTTPClient
	apiHTTPClient = srv.Client()
	apiHTTPClient.Timeout = 2 * time.Second
	t.Cleanup(func() { apiHTTPClient = oldClient })

	code, body, err := doAPIRequest(http.MethodPost, srv.URL, "/api/v1/test", "token", "mph123", []byte(`{"name":"x"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusCreated {
		t.Fatalf("code=%d, want %d", code, http.StatusCreated)
	}
	if body != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestAPIErrorMessageFallback(t *testing.T) {
	msg := apiErrorMessage("plain error")
	if msg != "plain error" {
		t.Fatalf("unexpected message: %s", msg)
	}
}
