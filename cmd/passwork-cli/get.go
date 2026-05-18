package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func getFieldValue(data map[string]any, field string) (*string, error) {
	switch field {
	case "url":
		return stringField(data["url"])
	case "login":
		return stringField(data["login"])
	case "password":
		return stringField(data["passwordEncrypted"])
	default:
		customsVal, ok := data["customs"]
		if !ok || customsVal == nil {
			return nil, fmt.Errorf("field %q not found: no customs", field)
		}
		customsSlice, ok := customsVal.([]any)
		if !ok || len(customsSlice) == 0 {
			return nil, fmt.Errorf("field %q not found: customs empty", field)
		}
		for i := range customsSlice {
			item, ok := customsSlice[i].(map[string]any)
			if !ok {
				continue
			}
			name, _ := item["name"].(string)
			if name != field {
				continue
			}
			return stringField(item["value"])
		}
		return nil, fmt.Errorf("field %q not found in customs", field)
	}
}

func stringField(v any) (*string, error) {
	if v == nil {
		return nil, fmt.Errorf("field value is empty")
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("field value is not a string")
	}
	out := s
	return &out, nil
}

func runGet(args []string, pwk_url, pwk_access, mph string, userPrivateKeyPEM []byte) (string, error) {
	var pwk_endpoint string
	getCmd := flag.NewFlagSet("get", flag.ExitOnError)
	passwordID := getCmd.String("password-id", "", "Password record ID")
	shortcutID := getCmd.String("shortcut-id", "", "Shortcut ID")
	field := getCmd.String("field", "", "Output only this field: password, url, login, or custom field name")
	getCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: passwork-cli get --password-id <ID>\n")
		fmt.Fprintf(os.Stderr, "Usage: passwork-cli get --password-id <ID> [--field <name>]\n")
		fmt.Fprintf(os.Stderr, "Usage: passwork-cli get --shortcut-id <ID>\n")
		fmt.Fprintf(os.Stderr, "       passwork-cli get --shortcut-id <ID> [--field <name>]\n\n")
		fmt.Fprintf(os.Stderr, "Fetch an item or shortcut by ID. Output full JSON or a single field.\n\n")
		getCmd.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli get --password-id <item-id>\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli get --password-id <item-id> --field password\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli get --shortcut-id <shortcut-id> --field login\n")
	}
	for _, a := range args {
		if a == "-h" || a == "--help" {
			getCmd.Usage()
			os.Exit(0)
		}
	}
	getCmd.Parse(args)
	switch {
	case *passwordID != "":
		pwk_endpoint = "/api/v1/items/" + *passwordID
	case *shortcutID != "":
		pwk_endpoint = "/api/v1/shortcuts/" + *shortcutID
	default:
		return "", fmt.Errorf("password-id or shortcut-id is required")
	}
	code, pwk_response, err := doAPIRequest("GET", pwk_url, pwk_endpoint, pwk_access, mph, nil)
	if err != nil {
		return "", err
	}
	if code < 200 || code >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", code, apiErrorMessage(pwk_response))
	}
	var pwk_data_map map[string]any
	err = json.Unmarshal([]byte(pwk_response), &pwk_data_map)
	if err != nil {
		return "", err
	}

	isCSE := isCSERecord(pwk_data_map)
	if isCSE {
		if len(userPrivateKeyPEM) == 0 {
			return "", fmt.Errorf("client-side encrypted item/shortcut: PASSWORK_MASTER_KEY is required")
		}
		if err := decodeItemFieldsCSE(pwk_data_map, userPrivateKeyPEM); err != nil {
			return "", err
		}
	} else {
		decodeItemFieldsBase64(pwk_data_map)
	}

	if *field != "" {
		v, err := getFieldValue(pwk_data_map, *field)
		if err != nil {
			return "", err
		}
		if v != nil {
			return *v, nil
		}
	}

	pwk_data_str, err := json.MarshalIndent(pwk_data_map, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pwk_data_str), nil
}
