// Package parser provides file content parsing for different pipeline
// and container file types.
package parser

import (
	"bufio"
	"os"
	"strings"

	"github.com/tazi06/pipeguard/pkg/rules"
)

// ParsedLine represents a single line from a parsed file.
type ParsedLine struct {
	Number  int    // 1-based line number
	Content string // Raw line content (trimmed)
	Raw     string // Original line content (untrimmed)
}

// ParsedFile holds the complete parsed representation of a scanned file.
type ParsedFile struct {
	Path       string         // File path
	Type       rules.FileType // Detected file type
	Lines      []ParsedLine   // All lines in the file
	RawContent string         // Entire file as a single string
}

// Parse reads a file and returns its parsed representation.
func Parse(path string, fileType rules.FileType) (*ParsedFile, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	raw := string(content)
	var lines []ParsedLine

	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lines = append(lines, ParsedLine{
			Number:  lineNum,
			Content: strings.TrimSpace(line),
			Raw:     line,
		})
	}

	return &ParsedFile{
		Path:       path,
		Type:       fileType,
		Lines:      lines,
		RawContent: raw,
	}, nil
}
