// Package detector walks a directory tree and identifies pipeline,
// Dockerfile, and Jenkinsfile files that PipeGuard can scan.
package detector

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/tazi06/pipeguard/pkg/rules"
)

// DetectedFile represents a file found during directory scanning.
type DetectedFile struct {
	Path string         // Absolute or relative file path
	Type rules.FileType // Detected file type
}

// Detect walks the given root directory and returns all scannable files.
// It identifies GitLab CI, GitHub Actions, Jenkinsfile, and Dockerfile files
// based on their naming conventions.
func Detect(root string) ([]DetectedFile, error) {
	var files []DetectedFile

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}

		// Skip hidden directories (except .github)
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") && name != ".github" {
				return filepath.SkipDir
			}
			// Skip common non-relevant directories
			switch name {
			case "node_modules", "vendor", ".git", "__pycache__", ".terraform":
				return filepath.SkipDir
			}
			return nil
		}

		if ft, ok := identifyFile(path, d.Name()); ok {
			files = append(files, DetectedFile{Path: path, Type: ft})
		}
		return nil
	})

	return files, err
}

// identifyFile determines the file type from its name and path.
func identifyFile(path, name string) (rules.FileType, bool) {
	// GitLab CI
	if name == ".gitlab-ci.yml" || name == ".gitlab-ci.yaml" {
		return rules.GitLabCI, true
	}

	// GitHub Actions: .github/workflows/*.yml
	if (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) &&
		strings.Contains(path, filepath.Join(".github", "workflows")) {
		return rules.GitHubActions, true
	}

	// Jenkinsfile: exact match or Jenkinsfile.*
	if name == "Jenkinsfile" || strings.HasPrefix(name, "Jenkinsfile.") {
		return rules.JenkinsfileT, true
	}

	// Dockerfile: exact match or Dockerfile.*
	if name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.") {
		return rules.DockerfileT, true
	}

	return 0, false
}
