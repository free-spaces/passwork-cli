package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var version = "dev"

func parseGlobalFlags(args []string) ([]string, bool, error) {
	clean := make([]string, 0, len(args))
	noSSLVerify := false
	for _, a := range args {
		switch {
		case a == "--no-ssl-verify":
			noSSLVerify = true
		case strings.HasPrefix(a, "--no-ssl-verify="):
			v := strings.TrimPrefix(a, "--no-ssl-verify=")
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, false, fmt.Errorf("invalid value for --no-ssl-verify: %q", v)
			}
			noSSLVerify = b
		default:
			clean = append(clean, a)
		}
	}
	return clean, noSSLVerify, nil
}

func validateMasterKeyAndHash(encoded string) (mph string, decoded []byte, err error) {
	decoded, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("master key base64: %w", err)
	}
	if len(decoded) != 64 {
		return "", nil, fmt.Errorf("master key must be 64 bytes after decode, got %d", len(decoded))
	}
	h := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(h[:]), decoded, nil
}

func fetchUserPrivateEncrypted(pwkURL, pwkAccess, mph string) (string, error) {
	code, body, err := doAPIRequest("GET", pwkURL, "/api/v1/users/keys", pwkAccess, mph, nil)
	if err != nil {
		return "", err
	}
	if code < 200 || code >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", code, apiErrorMessage(body))
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return "", fmt.Errorf("users/keys response: %w", err)
	}
	keysVal, ok := data["keys"]
	if !ok || keysVal == nil {
		return "", fmt.Errorf("users/keys: missing keys")
	}
	keysMap, ok := keysVal.(map[string]any)
	if !ok {
		return "", fmt.Errorf("users/keys: keys is not an object")
	}
	privVal, ok := keysMap["privateEncrypted"]
	if !ok || privVal == nil {
		return "", fmt.Errorf("users/keys: missing privateEncrypted")
	}
	privStr, ok := privVal.(string)
	if !ok {
		return "", fmt.Errorf("users/keys: privateEncrypted is not a string")
	}
	return privStr, nil
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func printRootHelp(w io.Writer) {
	fmt.Fprintf(w, "Passwork CLI — fetch and decrypt items/shortcuts, run commands with credentials in env.\n\n")
	fmt.Fprintf(w, "Usage:\n  passwork-cli <command> [flags]\n\n")
	fmt.Fprintf(w, "Commands:\n")
	fmt.Fprintf(w, "  get       Fetch item or shortcut by ID; output JSON or a single field.\n")
	fmt.Fprintf(w, "  exec      Fetch item/shortcut, inject passwords/shortcuts into env, run a command.\n")
	fmt.Fprintf(w, "  update    Update one or more fields of an item or shortcut.\n")
	fmt.Fprintf(w, "  api       Make raw API request (GET/POST/PATCH/DELETE/PUT).\n")
	fmt.Fprintf(w, "  crypto    Encrypt/decrypt values (AES, Passwork format) for automation without API.\n\n")
	fmt.Fprintf(w, "  version   Print CLI version.\n\n")
	fmt.Fprintf(w, "Environment:\n")
	fmt.Fprintf(w, "  PASSWORK_URL            Passwork API base URL (e.g. https://passwork.example.com)\n")
	fmt.Fprintf(w, "  PASSWORK_ACCESS_TOKEN   API access token (required for API commands)\n")
	fmt.Fprintf(w, "  PASSWORK_MASTER_KEY     (optional) user master key for client-side encryption\n\n")
	fmt.Fprintf(w, "Global flags:\n")
	fmt.Fprintf(w, "  --no-ssl-verify  Disable SSL certificate verification for API calls.\n\n")
	fmt.Fprintf(w, "Use \"passwork-cli <command> --help\" for command-specific flags and examples.\n")
}

func main() {
	args, noSSLVerify, err := parseGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	configureHTTPClient(noSSLVerify)

	apiAccessToken := os.Getenv("PASSWORK_ACCESS_TOKEN")
	userMasterKey := os.Getenv("PASSWORK_MASTER_KEY")
	apiBaseURL := os.Getenv("PASSWORK_URL")

	first := ""
	if len(args) >= 1 {
		first = args[0]
	}
	if first == "--version" || first == "version" {
		fmt.Println(version)
		os.Exit(0)
	}
	subHelp := len(args) >= 2 && (args[1] == "-h" || args[1] == "--help")
	needAPI := len(args) >= 1 && first != "crypto" && first != "version" && first != "--version" && first != "-h" && first != "--help" && !subHelp
	if needAPI {
		if apiAccessToken == "" {
			fmt.Fprintln(os.Stderr, "PASSWORK_ACCESS_TOKEN is not set")
			os.Exit(1)
		}
		if apiBaseURL == "" {
			fmt.Fprintln(os.Stderr, "PASSWORK_URL is not set")
			os.Exit(1)
		}
	}

	var mph string
	var userMasterKeyDecoded []byte
	var userPrivateEncrypted string
	var userPrivateKeyPEM []byte
	if needAPI && userMasterKey != "" {
		mph, userMasterKeyDecoded, err = validateMasterKeyAndHash(userMasterKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		userPrivateEncrypted, err = fetchUserPrivateEncrypted(apiBaseURL, apiAccessToken, mph)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		userPrivateKeyPEM, err = decryptWithAESMasterKey(userPrivateEncrypted, []byte(userMasterKey))
		if err != nil {
			fmt.Fprintln(os.Stderr, "decrypt user private key:", err)
			os.Exit(1)
		}
		clearBytes(userMasterKeyDecoded)
		userMasterKey = ""
	}

	if len(args) < 1 {
		printRootHelp(os.Stderr)
		os.Exit(1)
	}
	first = args[0]
	if first == "-h" || first == "--help" {
		printRootHelp(os.Stdout)
		os.Exit(0)
	}

	switch first {
	case "get":
		pwk_response, err := runGet(args[1:], apiBaseURL, apiAccessToken, mph, userPrivateKeyPEM)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(pwk_response)
	case "exec":
		pwkResponse, err := runExec(args[1:], apiBaseURL, apiAccessToken, mph, userPrivateKeyPEM)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(pwkResponse)
	case "update":
		if err := runUpdate(args[1:], apiBaseURL, apiAccessToken, mph, userPrivateKeyPEM); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "api":
		resp, err := runAPI(args[1:], apiBaseURL, apiAccessToken, mph)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(resp)
	case "crypto":
		if err := runCrypto(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", first)
		os.Exit(1)
	}
}
