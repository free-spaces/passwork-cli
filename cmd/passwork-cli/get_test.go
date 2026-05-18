package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunGetCSERequiresMasterKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/items/item-1" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"vaultMasterKeyEncrypted":"encrypted-vault-key"}`))
	}))
	defer srv.Close()

	oldClient := apiHTTPClient
	apiHTTPClient = srv.Client()
	t.Cleanup(func() { apiHTTPClient = oldClient })

	_, err := runGet([]string{"--password-id", "item-1"}, srv.URL, "token", "", nil)
	if err == nil {
		t.Fatalf("expected CSE master key error")
	}
	if !strings.Contains(err.Error(), "PASSWORK_MASTER_KEY") {
		t.Fatalf("expected PASSWORK_MASTER_KEY error, got: %v", err)
	}
}
