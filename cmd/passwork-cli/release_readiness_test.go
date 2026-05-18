package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicDocsDoNotContainPrivateExampleIDsOrStaleLinks(t *testing.T) {
	root := "../.."
	forbidden := []string{
		"691f" + "14790bee5ffe18089395",
		"698c" + "4b196b12c60d2a056865",
		"6859" + "972f244fc0b1df052868",
		"KUBERNETES" + ".md",
		"scripts/" + "test-exec.sh",
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".md", ".yaml", ".yml", ".sh":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		for _, value := range forbidden {
			if strings.Contains(content, value) {
				t.Fatalf("%s contains forbidden public example value %q", path, value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk public files: %v", err)
	}
}

func TestVersionDefaultIsSet(t *testing.T) {
	if version == "" {
		t.Fatalf("version must not be empty")
	}
}
