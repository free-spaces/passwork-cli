package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func sanitizeEnvKey(name string) string {
	var b strings.Builder
	b.WriteString("pwk_")
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('_')
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func shellCommandPrefix(goos string) (string, []string) {
	if goos == "windows" {
		return "cmd", []string{"/C"}
	}
	return "sh", []string{"-c"}
}

func buildExecCommand(command string, extraArgs []string, useShell bool, goos string) (*exec.Cmd, error) {
	if command == "" {
		return nil, fmt.Errorf("exec: --cmd is required")
	}
	if useShell {
		prog, prefix := shellCommandPrefix(goos)
		args := append(prefix, command)
		return exec.Command(prog, args...), nil
	}
	if len(extraArgs) > 0 {
		return exec.Command(command, extraArgs...), nil
	}
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil, fmt.Errorf("exec: --cmd is empty")
	}
	return exec.Command(parts[0], parts[1:]...), nil
}

func runExec(args []string, pwk_url, pwk_access, mph string, userPrivateKeyPEM []byte) (string, error) {
	var pwk_endpoint string
	envVars := make(map[string]string)
	envSlice := os.Environ()
	getCmd := flag.NewFlagSet("exec", flag.ExitOnError)
	passwordID := getCmd.String("password-id", "", "Password record ID")
	shortcutID := getCmd.String("shortcut-id", "", "Shortcut ID")
	execCmd := getCmd.String("cmd", "", "Command to run: path + args, or with --shell the full shell command")
	execShell := getCmd.Bool("shell", false, "Run --cmd via sh -c (env expansion, pipes, etc.)")
	getCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: passwork-cli exec --password-id <ID> --cmd \"<command>\" [--shell]\n")
		fmt.Fprintf(os.Stderr, "       passwork-cli exec --shortcut-id <ID> --cmd \"<command>\" [--shell]\n\n")
		fmt.Fprintf(os.Stderr, "Fetch item/shortcut, inject passwords/shortcuts into env (pwk_*), run command.\n\n")
		getCmd.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli exec --password-id <item-id> --cmd \"./deploy.sh\"\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli exec --password-id <item-id> --cmd \"env\"\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli exec --password-id <item-id> --cmd \"echo \\$pwk_pwd\" --shell\n")
		fmt.Fprintf(os.Stderr, "  passwork-cli exec --password-id <item-id> --cmd /bin/echo -- \"value with spaces\"\n")
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
		return "", fmt.Errorf("password-id or shortcut-id and cmd are required")
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

	for k, v := range collectPasswordEnvVars(pwk_data_map) {
		envVars[k] = v
	}

	for k, v := range envVars {
		envSlice = append(envSlice, k+"="+v)
	}

	cmd, err := buildExecCommand(*execCmd, getCmd.Args(), *execShell, runtime.GOOS)
	if err != nil {
		return "", err
	}
	cmd.Env = envSlice
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	for k := range envVars {
		envVars[k] = ""
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return "", err
	}
	os.Exit(0)
	return "", nil
}
