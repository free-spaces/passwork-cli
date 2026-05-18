package main

import "testing"

func TestBuildExecCommandWithExtraArgs(t *testing.T) {
	cmd, err := buildExecCommand("/bin/echo", []string{"value with spaces"}, false, "linux")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmd.Args) != 2 || cmd.Args[0] != "/bin/echo" || cmd.Args[1] != "value with spaces" {
		t.Fatalf("unexpected args: %#v", cmd.Args)
	}
}

func TestBuildExecCommandLegacyFieldsMode(t *testing.T) {
	cmd, err := buildExecCommand("echo hello", nil, false, "linux")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmd.Args) != 2 || cmd.Args[0] != "echo" || cmd.Args[1] != "hello" {
		t.Fatalf("unexpected args: %#v", cmd.Args)
	}
}

func TestBuildExecCommandShell(t *testing.T) {
	cmd, err := buildExecCommand("echo $pwk_pwd", nil, true, "linux")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmd.Args) != 3 || cmd.Args[0] != "sh" || cmd.Args[1] != "-c" || cmd.Args[2] != "echo $pwk_pwd" {
		t.Fatalf("unexpected shell args: %#v", cmd.Args)
	}
}
