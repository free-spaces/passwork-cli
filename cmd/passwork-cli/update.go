package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func runUpdate(args []string, pwkURL, pwkAccess, mph string, userPrivateKeyPEM []byte) error {
	var endpoint string
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	passwordID := fs.String("password-id", "", "Password record ID")
	shortcutID := fs.String("shortcut-id", "", "Shortcut ID")
	name := fs.String("name", "", "Set name")
	login := fs.String("login", "", "Set login")
	password := fs.String("password", "", "Set password")
	urlVal := fs.String("url", "", "Set URL")
	description := fs.String("description", "", "Set description")
	tagsStr := fs.String("tags", "", "Set tags (comma-separated)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: passwork-cli update --password-id <ID> [options]\n")
		fmt.Fprintf(os.Stderr, "       passwork-cli update --shortcut-id <ID> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Update one or more fields. At least one of --name, --login, --password, --url, --description, --tags is required.\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli update --password-id <item-id> --name \"New Name\"\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli update --password-id <item-id> --login user@example.com --password secret\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli update --password-id <item-id> --password 'pwd with ! and $'\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli update --password-id <item-id> --tags \"tag1,tag2\"\n")
	}
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fs.Usage()
			os.Exit(0)
		}
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *passwordID != "":
		endpoint = "/api/v1/items/" + *passwordID
	case *shortcutID != "":
		endpoint = "/api/v1/shortcuts/" + *shortcutID
	default:
		return fmt.Errorf("password-id or shortcut-id is required")
	}

	body := make(map[string]any)
	if *name != "" {
		body["name"] = *name
	}
	if *login != "" {
		body["login"] = *login
	}
	if *urlVal != "" {
		body["url"] = *urlVal
	}
	if *description != "" {
		body["description"] = *description
	}
	if *tagsStr != "" {
		parts := strings.Split(*tagsStr, ",")
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}
		body["tags"] = parts
	}

	hasPassword := *password != ""

	if len(body) == 0 && !hasPassword {
		return fmt.Errorf("at least one of --name, --login, --password, --url, --description, --tags is required")
	}

	code, resp, err := doAPIRequest("GET", pwkURL, endpoint, pwkAccess, mph, nil)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, apiErrorMessage(resp))
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(resp), &data); err != nil {
		return fmt.Errorf("parse record: %w", err)
	}

	isCSE := isCSERecord(data)
	if isCSE && hasPassword {
		if len(userPrivateKeyPEM) == 0 {
			return fmt.Errorf("client-side encrypted item/shortcut: userMasterKey is required to update password")
		}
		privKey, err := ParsePrivateKeyPEM(userPrivateKeyPEM)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
		vaultMasterKeyEncrypted, err := mustGetString(data, "vaultMasterKeyEncrypted")
		if err != nil {
			return err
		}
		vaultMasterKey, err := DecryptVaultMasterKey(vaultMasterKeyEncrypted, privKey)
		if err != nil {
			return fmt.Errorf("vault key: %w", err)
		}
		itemKeyEncrypted, err := mustGetString(data, "keyEncrypted")
		if err != nil {
			return err
		}
		itemMasterKey, err := decryptWithAESMasterKey(itemKeyEncrypted, vaultMasterKey)
		if err != nil {
			return fmt.Errorf("item key: %w", err)
		}
		encrypted, err := encryptWithAESMasterKey([]byte(*password), itemMasterKey)
		if err != nil {
			return fmt.Errorf("encrypt password: %w", err)
		}
		body["passwordEncrypted"] = encrypted
	} else if hasPassword {
		body["password"] = *password
	}

	if len(body) == 0 {
		return fmt.Errorf("nothing to update")
	}

	rawBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal body: %w", err)
	}
	code, resp, err = doAPIRequest("PATCH", pwkURL, endpoint, pwkAccess, mph, rawBody)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, apiErrorMessage(resp))
	}
	fmt.Fprintln(os.Stdout, "updated")
	return nil
}
