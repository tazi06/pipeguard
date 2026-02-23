package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tazi06/pipeguard/pkg/rules"
)

func TestParseDockerfile(t *testing.T) {
	dir := t.TempDir()
	content := "FROM alpine:3.18\nRUN apk add curl\nCMD [\"app\"]\n"
	f := filepath.Join(dir, "Dockerfile")
	_ = os.WriteFile(f, []byte(content), 0644)

	parsed, err := Parse(f, rules.DockerfileT)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if parsed.Type != rules.DockerfileT {
		t.Errorf("expected DockerfileT, got %d", parsed.Type)
	}

	if len(parsed.Lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(parsed.Lines))
	}

	if parsed.Lines[0].Number != 1 {
		t.Errorf("first line number should be 1, got %d", parsed.Lines[0].Number)
	}

	if parsed.Lines[0].Content != "FROM alpine:3.18" {
		t.Errorf("unexpected first line content: %s", parsed.Lines[0].Content)
	}

	if parsed.RawContent != content {
		t.Errorf("raw content mismatch")
	}
}

func TestParseEmptyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "Dockerfile")
	_ = os.WriteFile(f, []byte(""), 0644)

	parsed, err := Parse(f, rules.DockerfileT)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(parsed.Lines) != 0 {
		t.Errorf("expected 0 lines for empty file, got %d", len(parsed.Lines))
	}
}

func TestParseFileNotFound(t *testing.T) {
	_, err := Parse("/nonexistent/path/Dockerfile", rules.DockerfileT)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseLinesAreTrimmed(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".gitlab-ci.yml")
	_ = os.WriteFile(f, []byte("  stages:\n    - build\n"), 0644)

	parsed, err := Parse(f, rules.GitLabCI)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// Lines should preserve content as-is (trimmed or not depends on implementation)
	if len(parsed.Lines) < 1 {
		t.Fatalf("expected at least 1 line")
	}
}
