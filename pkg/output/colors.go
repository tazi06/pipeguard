// Package output provides ANSI color constants for terminal rendering.
// Colors are automatically disabled when stdout is not a terminal.
package output

import (
	"os"

	"golang.org/x/term"
)

// ANSI color codes for terminal output.
var (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Red       = "\033[31m"
	BoldRed   = "\033[1;31m"
	Green     = "\033[32m"
	BoldGreen = "\033[1;32m"
	Yellow    = "\033[33m"
	BoldYellow = "\033[1;33m"
	Blue      = "\033[34m"
	BoldBlue  = "\033[1;34m"
	Cyan      = "\033[36m"
	White     = "\033[37m"
	Gray      = "\033[90m"
)

func init() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		DisableColors()
	}
}

// DisableColors strips all ANSI codes for non-terminal output.
func DisableColors() {
	Reset = ""
	Bold = ""
	Dim = ""
	Red = ""
	BoldRed = ""
	Green = ""
	BoldGreen = ""
	Yellow = ""
	BoldYellow = ""
	Blue = ""
	BoldBlue = ""
	Cyan = ""
	White = ""
	Gray = ""
}

// SeverityColor returns the appropriate ANSI color for a severity level.
func SeverityColor(sev string) string {
	switch sev {
	case "CRITICAL":
		return BoldRed
	case "HIGH":
		return BoldYellow
	case "MEDIUM":
		return Cyan
	case "LOW":
		return White
	case "INFO":
		return Gray
	default:
		return White
	}
}
