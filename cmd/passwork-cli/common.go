package main

import (
	"fmt"
	"strings"
)

func getString(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return s, true
}

func mustGetString(m map[string]any, key string) (string, error) {
	s, ok := getString(m, key)
	if !ok || s == "" {
		return "", fmt.Errorf("missing or invalid %q", key)
	}
	return s, nil
}

func decodeItemFieldsBase64(item map[string]any) {
	if item == nil {
		return
	}

	if raw, ok := getString(item, "passwordEncrypted"); ok && raw != "" {
		decoded, err := decodeBase64(raw)
		if err == nil {
			item["passwordEncrypted"] = decoded
		}
	}

	customsVal, ok := item["customs"]
	if !ok || customsVal == nil {
		return
	}
	customsSlice, ok := customsVal.([]any)
	if !ok {
		return
	}
	for i := range customsSlice {
		entry, ok := customsSlice[i].(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"name", "type", "value"} {
			raw, ok := getString(entry, key)
			if !ok || raw == "" {
				continue
			}
			decoded, err := decodeBase64(raw)
			if err == nil {
				entry[key] = decoded
			}
		}
	}
}

func decodeItemFieldsCSE(item map[string]any, userPrivateKeyPEM []byte) error {
	if len(userPrivateKeyPEM) == 0 {
		return fmt.Errorf("user private key is required for CSE item")
	}

	privKey, err := ParsePrivateKeyPEM(userPrivateKeyPEM)
	if err != nil {
		return err
	}

	vaultMasterKeyEncrypted, err := mustGetString(item, "vaultMasterKeyEncrypted")
	if err != nil {
		return err
	}
	vaultMasterKey, err := DecryptVaultMasterKey(vaultMasterKeyEncrypted, privKey)
	if err != nil {
		return err
	}

	itemKeyEncrypted, err := mustGetString(item, "keyEncrypted")
	if err != nil {
		return err
	}
	itemMasterKey, err := decryptWithAESMasterKey(itemKeyEncrypted, vaultMasterKey)
	if err != nil {
		return err
	}

	if raw, ok := getString(item, "passwordEncrypted"); ok && raw != "" {
		decrypted, err := decryptWithAESMasterKey(raw, itemMasterKey)
		if err != nil {
			return fmt.Errorf("decrypt passwordEncrypted: %w", err)
		}
		item["passwordEncrypted"] = string(decrypted)
	}

	customsVal, ok := item["customs"]
	if !ok || customsVal == nil {
		return nil
	}
	customsSlice, ok := customsVal.([]any)
	if !ok {
		return nil
	}
	for i := range customsSlice {
		entry, ok := customsSlice[i].(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"name", "type", "value"} {
			raw, ok := getString(entry, key)
			if !ok || raw == "" {
				continue
			}
			decrypted, err := decryptWithAESMasterKey(raw, itemMasterKey)
			if err == nil {
				entry[key] = string(decrypted)
			}
		}
	}

	return nil
}

func collectPasswordEnvVars(item map[string]any) map[string]string {
	env := make(map[string]string)
	if item == nil {
		return env
	}

	if name, ok := getString(item, "name"); ok && name != "" {
		if pwd, ok := getString(item, "passwordEncrypted"); ok && pwd != "" {
			env[sanitizeEnvKey(name)] = pwd
		}
	}

	customs, ok := item["customs"].([]any)
	if !ok {
		return env
	}
	for _, c := range customs {
		entry, ok := c.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := getString(entry, "type")
		if strings.ToLower(typ) != "password" {
			continue
		}
		name, nameOK := getString(entry, "name")
		value, valueOK := getString(entry, "value")
		if !nameOK || !valueOK || name == "" {
			continue
		}
		env[sanitizeEnvKey(name)] = value
	}

	return env
}

func isCSERecord(item map[string]any) bool {
	v, ok := getString(item, "vaultMasterKeyEncrypted")
	return ok && v != ""
}
