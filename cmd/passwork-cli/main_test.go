package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseGlobalFlags(t *testing.T) {
	args, noSSL, err := parseGlobalFlags([]string{"api", "--no-ssl-verify", "--method", "GET"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !noSSL {
		t.Fatalf("expected noSSL=true")
	}
	if len(args) != 3 || args[0] != "api" || args[1] != "--method" || args[2] != "GET" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestParseGlobalFlagsBoolValue(t *testing.T) {
	_, noSSL, err := parseGlobalFlags([]string{"api", "--no-ssl-verify=false"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if noSSL {
		t.Fatalf("expected noSSL=false")
	}
}

func TestParseGlobalFlagsInvalidValue(t *testing.T) {
	_, _, err := parseGlobalFlags([]string{"api", "--no-ssl-verify=maybe"})
	if err == nil {
		t.Fatalf("expected error for invalid bool")
	}
}

func TestValidateMasterKeyAndHash(t *testing.T) {
	src := strings.Repeat("a", 64)
	encoded := base64.StdEncoding.EncodeToString([]byte(src))
	mph, decoded, err := validateMasterKeyAndHash(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decoded) != 64 {
		t.Fatalf("decoded len=%d, want 64", len(decoded))
	}
	sum := sha256.Sum256([]byte(encoded))
	want := hex.EncodeToString(sum[:])
	if mph != want {
		t.Fatalf("mph=%q, want %q", mph, want)
	}
}

func TestValidateMasterKeyAndHashInvalidBase64(t *testing.T) {
	_, _, err := validateMasterKeyAndHash("%%%")
	if err == nil {
		t.Fatalf("expected error for invalid base64")
	}
}
