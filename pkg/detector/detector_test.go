package detector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectGitLabCI(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".gitlab-ci.yml")
	_ = os.WriteFile(f, []byte("stages:\n  - build\n"), 0644)

	files, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Type != 0 { // GitLabCI
		t.Errorf("expected GitLabCI type, got %d", files[0].Type)
	}
}

func TestDetectDockerfile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "Dockerfile")
	_ = os.WriteFile(f, []byte("FROM alpine:3.18\n"), 0644)

	files, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Type != 3 { // DockerfileT
		t.Errorf("expected DockerfileT type, got %d", files[0].Type)
	}
}

func TestDetectJenkinsfile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "Jenkinsfile")
	_ = os.WriteFile(f, []byte("pipeline { agent any }\n"), 0644)

	files, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Type != 2 { // JenkinsfileT
		t.Errorf("expected JenkinsfileT type, got %d", files[0].Type)
	}
}

func TestDetectGitHubActions(t *testing.T) {
	dir := t.TempDir()
	ghDir := filepath.Join(dir, ".github", "workflows")
	_ = os.MkdirAll(ghDir, 0755)
	f := filepath.Join(ghDir, "ci.yml")
	_ = os.WriteFile(f, []byte("name: CI\non: push\n"), 0644)

	files, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Type != 1 { // GitHubActions
		t.Errorf("expected GitHubActions type, got %d", files[0].Type)
	}
}

func TestDetectSkipsGitDir(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	_ = os.MkdirAll(gitDir, 0755)
	_ = os.WriteFile(filepath.Join(gitDir, "Dockerfile"), []byte("FROM alpine\n"), 0644)

	files, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if len(files) != 0 {
		t.Errorf("expected 0 files (should skip .git), got %d", len(files))
	}
}

func TestDetectEmptyDir(t *testing.T) {
	dir := t.TempDir()

	files, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if len(files) != 0 {
		t.Errorf("expected 0 files for empty dir, got %d", len(files))
	}
}

func TestDetectSingleFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "Dockerfile")
	os.WriteFile(f, []byte("FROM alpine:3.18\n"), 0644)

	files, err := Detect(f)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
}

func TestDetectMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte("stages:\n"), 0644)
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine\n"), 0644)
	os.WriteFile(filepath.Join(dir, "Jenkinsfile"), []byte("pipeline {}\n"), 0644)

	files, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	if len(files) != 3 {
		t.Errorf("expected 3 files, got %d", len(files))
	}
}
