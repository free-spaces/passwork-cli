package main

import "testing"

func TestEncryptDecryptWithAESMasterKeyRoundTrip(t *testing.T) {
	key := []byte("test-master-key")
	plain := []byte("secret value")

	encrypted, err := encryptWithAESMasterKey(plain, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := decryptWithAESMasterKey(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(plain) {
		t.Fatalf("decrypted=%q, want %q", string(decrypted), string(plain))
	}
}
