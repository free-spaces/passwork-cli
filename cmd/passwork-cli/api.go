package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func normalizeAPIEndpoint(raw string) string {
	e := strings.TrimSpace(raw)
	e = strings.TrimPrefix(e, "https://")
	e = strings.TrimPrefix(e, "http://")
	if !strings.HasPrefix(e, "/") {
		e = "/" + e
	}
	if strings.HasPrefix(e, "/api/") {
		return e
	}
	if strings.HasPrefix(e, "/v1/") {
		return "/api" + e
	}
	if strings.HasPrefix(e, "/v2/") {
		return "/api" + e
	}
	return "/api/v1" + e
}

func runAPI(args []string, pwkURL, pwkAccess, mph string) (string, error) {
	fs := flag.NewFlagSet("api", flag.ExitOnError)
	method := fs.String("method", "GET", "HTTP method: GET, POST, PATCH, DELETE, PUT")
	endpoint := fs.String("endpoint", "", "Endpoint path, for example /api/v1/items or v1/items")
	params := fs.String("params", "", "JSON body for request")
	rawJSON := fs.Bool("json", false, "Output raw response as-is (no pretty formatting)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: passwork-cli api --method <GET|POST|PATCH|DELETE|PUT> --endpoint <path> [--params '<json>']\n\n")
		fmt.Fprintf(os.Stderr, "API request mode. By default, JSON response is pretty-printed.\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli api --method GET --endpoint \"/api/v1/items/<item-id>\"\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli api --method POST --endpoint \"v1/vaults/<vault-id>\" --params '{\"name\":\"cli vault name\"}'\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli --no-ssl-verify api --method GET --endpoint \"v1/users/keys\"\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli api --method GET --endpoint \"v1/items\" --json\n")
	}
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fs.Usage()
			os.Exit(0)
		}
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}

	if *endpoint == "" {
		return "", fmt.Errorf("api: --endpoint is required")
	}

	httpMethod := strings.ToUpper(strings.TrimSpace(*method))
	switch httpMethod {
	case http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodPut:
	default:
		return "", fmt.Errorf("api: unsupported method %q", *method)
	}

	var rawBody []byte
	if strings.TrimSpace(*params) != "" {
		var body any
		if err := json.Unmarshal([]byte(*params), &body); err != nil {
			return "", fmt.Errorf("api: invalid --params JSON: %w", err)
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return "", fmt.Errorf("api: marshal --params: %w", err)
		}
		rawBody = raw
	}

	code, bodyStr, err := doAPIRequest(httpMethod, pwkURL, normalizeAPIEndpoint(*endpoint), pwkAccess, mph, rawBody)
	if err != nil {
		return "", fmt.Errorf("api: %w", err)
	}
	if code >= 200 && code < 300 {
		if *rawJSON {
			return bodyStr, nil
		}
		var payload any
		if err := json.Unmarshal([]byte(bodyStr), &payload); err == nil {
			formatted, err := json.MarshalIndent(payload, "", "  ")
			if err == nil {
				return string(formatted), nil
			}
		}
		return bodyStr, nil
	}
	return "", fmt.Errorf("HTTP %d: %s", code, apiErrorMessage(bodyStr))
}
