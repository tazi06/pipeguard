package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/tazi06/pipeguard/pkg/rules"
	"github.com/tazi06/pipeguard/pkg/scorer"
)

const version = "0.1.0"

// TerminalFormatter outputs colored, human-readable scan results.
type TerminalFormatter struct {
	Writer  io.Writer
	ShowFix bool
}

// NewTerminalFormatter creates a terminal output formatter.
func NewTerminalFormatter(w io.Writer, showFix bool) *TerminalFormatter {
	return &TerminalFormatter{Writer: w, ShowFix: showFix}
}

// FormatReport outputs the complete scan report to the terminal.
func (t *TerminalFormatter) FormatReport(results []FileResult) {
	t.printBanner()

	if len(results) == 0 {
		fmt.Fprintf(t.Writer, "\n  %sNo scannable files found.%s\n", Gray, Reset)
		fmt.Fprintf(t.Writer, "  %sSupported: .gitlab-ci.yml, GitHub Actions, Jenkinsfile, Dockerfile%s\n\n", Gray, Reset)
		return
	}

	totalViolations := 0
	totalFixable := 0
	totalCritical, totalHigh, totalMedium, totalLow := 0, 0, 0, 0

	for _, result := range results {
		t.printFileResult(result)
		totalViolations += len(result.Violations)
		totalFixable += result.FixableCount

		for _, v := range result.Violations {
			switch v.Rule.Severity {
			case rules.Critical:
				totalCritical++
			case rules.High:
				totalHigh++
			case rules.Medium:
				totalMedium++
			case rules.Low:
				totalLow++
			}
		}
	}

	t.printSummary(results, totalViolations, totalFixable, totalCritical, totalHigh, totalMedium, totalLow)
}

// FileResult holds output data for a single scanned file.
type FileResult struct {
	Path         string
	FileType     rules.FileType
	Violations   []rules.Violation
	Score        scorer.Score
	FixableCount int
}

func (t *TerminalFormatter) printBanner() {
	line := strings.Repeat("\u2500", 65)
	fmt.Fprintf(t.Writer, "\n")
	fmt.Fprintf(t.Writer, "  %s%s\u250c%s\u2510%s\n", BoldBlue, Bold, line, Reset)
	fmt.Fprintf(t.Writer, "  %s%s\u2502%s  %s%sPIPEGUARD v%s%s  %s\u2014 Pipeline Security & Quality Scanner%s       %s%s\u2502%s\n",
		BoldBlue, Bold, Reset, BoldBlue, Bold, version, Reset, Gray, Reset, BoldBlue, Bold, Reset)
	fmt.Fprintf(t.Writer, "  %s%s\u2502%s  %sby yhakkache \u2022 pipeguard.dev%s                                  %s%s\u2502%s\n",
		BoldBlue, Bold, Reset, Gray, Reset, BoldBlue, Bold, Reset)
	fmt.Fprintf(t.Writer, "  %s%s\u2514%s\u2518%s\n", BoldBlue, Bold, line, Reset)
}

func (t *TerminalFormatter) printFileResult(result FileResult) {
	fmt.Fprintf(t.Writer, "\n  %s%s\u250c\u2500 SCAN \u2500\u2500%s %s%s%s", BoldBlue, Bold, Reset, Bold, result.Path, Reset)

	if len(result.Violations) == 0 {
		fmt.Fprintf(t.Writer, "  %s\u2713 no violations%s\n", BoldGreen, Reset)
		return
	}

	fmt.Fprintf(t.Writer, "  %s\u2717 %d violations%s\n", BoldRed, len(result.Violations), Reset)
	fmt.Fprintf(t.Writer, "  %s%s\u2502%s\n", BoldBlue, Bold, Reset)

	for i, v := range result.Violations {
		t.printViolation(v, i == len(result.Violations)-1)
	}
}

func (t *TerminalFormatter) printViolation(v rules.Violation, isLast bool) {
	sevColor := SeverityColor(v.Rule.Severity.String())
	sevIcon := severityIcon(v.Rule.Severity)
	connector := "\u251c"
	if isLast {
		connector = "\u2514"
	}

	// Main violation line
	fmt.Fprintf(t.Writer, "  %s%s%s%s  %s%s%s  %s%-5s%s  %s",
		BoldBlue, Bold, connector, Reset,
		sevColor, sevIcon, Reset,
		Bold, v.Rule.ID, Reset,
		v.Rule.Description)
	fmt.Fprintf(t.Writer, "  %s-%dpts%s\n", Gray, v.Rule.Points, Reset)

	// Sub-connector for details
	subConn := "\u2502"
	if isLast {
		subConn = " "
	}

	// Line info
	if v.Line > 0 && v.Content != "" {
		content := v.Content
		if len(content) > 55 {
			content = content[:52] + "..."
		}
		fmt.Fprintf(t.Writer, "  %s%s%s%s         %sLine %d%s \u2502 %s%s%s\n",
			BoldBlue, Bold, subConn, Reset,
			Dim, v.Line, Reset,
			Gray, content, Reset)
	}

	// Why
	fmt.Fprintf(t.Writer, "  %s%s%s%s         %s\u21b3 %s%s\n",
		BoldBlue, Bold, subConn, Reset,
		Gray, v.Rule.Why, Reset)

	// Fix suggestion
	if t.ShowFix && v.Rule.FixDesc != "" {
		fixColor := Green
		fixLabel := "FIX"
		if v.Rule.FixType == rules.FullFix {
			fixLabel = "FIX [AUTO]"
		} else if v.Rule.FixType == rules.PartialFix {
			fixLabel = "FIX [PARTIAL]"
		}
		fmt.Fprintf(t.Writer, "  %s%s%s%s         %s%s:%s %s%s%s\n",
			BoldBlue, Bold, subConn, Reset,
			fixColor, fixLabel, Reset,
			fixColor, v.Rule.FixDesc, Reset)
	}

	fmt.Fprintf(t.Writer, "  %s%s%s%s\n", BoldBlue, Bold, subConn, Reset)
}

func (t *TerminalFormatter) printSummary(results []FileResult, totalViolations, totalFixable, critical, high, medium, low int) {
	line := strings.Repeat("\u2500", 65)

	fmt.Fprintf(t.Writer, "\n  %s%s\u250c%s\u2510%s\n", Bold, White, line, Reset)
	fmt.Fprintf(t.Writer, "  %s%s\u2502  %-63s\u2502%s\n", Bold, White, "RESULTS", Reset)
	fmt.Fprintf(t.Writer, "  %s%s\u251c%s\u2524%s\n", Bold, White, line, Reset)

	// Files scanned
	fmt.Fprintf(t.Writer, "  %s%s\u2502%s  %-18s%s%d%s\n",
		Bold, White, Reset,
		"Files scanned", Bold, len(results), Reset)

	// Violations with breakdown
	if totalViolations > 0 {
		parts := []string{}
		if critical > 0 {
			parts = append(parts, fmt.Sprintf("%s%d critical%s", BoldRed, critical, Reset))
		}
		if high > 0 {
			parts = append(parts, fmt.Sprintf("%s%d high%s", BoldYellow, high, Reset))
		}
		if medium > 0 {
			parts = append(parts, fmt.Sprintf("%s%d medium%s", Cyan, medium, Reset))
		}
		if low > 0 {
			parts = append(parts, fmt.Sprintf("%s%d low%s", White, low, Reset))
		}
		fmt.Fprintf(t.Writer, "  %s%s\u2502%s  %-18s%s%d%s  (%s)\n",
			Bold, White, Reset,
			"Violations", BoldRed, totalViolations, Reset, strings.Join(parts, " \u00b7 "))
		fmt.Fprintf(t.Writer, "  %s%s\u2502%s  %-18s%s%d/%d%s\n",
			Bold, White, Reset,
			"Auto-fixable", Green, totalFixable, totalViolations, Reset)
	} else {
		fmt.Fprintf(t.Writer, "  %s%s\u2502%s  %-18s%s%s0 \u2014 All clear!%s\n",
			Bold, White, Reset,
			"Violations", BoldGreen, Bold, Reset)
	}

	fmt.Fprintf(t.Writer, "  %s%s\u251c%s\u2524%s\n", Bold, White, line, Reset)

	// Per-file scores
	for _, result := range results {
		hasSecViolations := false
		hasQualViolations := false
		for _, v := range result.Violations {
			if v.Rule.GetScoreType() == rules.SecurityScore {
				hasSecViolations = true
			} else {
				hasQualViolations = true
			}
		}

		secColor := scoreColor(result.Score.SecurityScore)
		qualColor := scoreColor(result.Score.QualityScore)

		// File name - truncate if too long
		displayPath := result.Path
		if len(displayPath) > 28 {
			displayPath = "..." + displayPath[len(displayPath)-25:]
		}

		if hasSecViolations || len(result.Violations) == 0 {
			fmt.Fprintf(t.Writer, "  %s%s\u2502%s  %s%-28s%s  %sSEC %3d/100%s  %s%s \u2014 %s%s\n",
				Bold, White, Reset,
				Bold, displayPath, Reset,
				secColor, result.Score.SecurityScore, Reset,
				secColor, result.Score.SecurityLevel.Tag, result.Score.SecurityLevel.Name, Reset)
		}
		if hasQualViolations || len(result.Violations) == 0 {
			padLen := len(displayPath)
			if padLen > 28 {
				padLen = 28
			}
			fmt.Fprintf(t.Writer, "  %s%s\u2502%s  %-28s  %sQLT %3d/100%s  %s%s \u2014 %s%s\n",
				Bold, White, Reset,
				strings.Repeat(" ", padLen),
				qualColor, result.Score.QualityScore, Reset,
				qualColor, result.Score.QualityLevel.Tag, result.Score.QualityLevel.Name, Reset)
		}
	}

	fmt.Fprintf(t.Writer, "  %s%s\u2514%s\u2518%s\n", Bold, White, line, Reset)

	// Hints
	if totalFixable > 0 && !t.ShowFix {
		fmt.Fprintf(t.Writer, "\n  %sRun: pipeguard scan . --fix  to see fix suggestions%s\n", Gray, Reset)
	}
	if t.ShowFix && totalFixable > 0 {
		fmt.Fprintf(t.Writer, "\n  %sRun: pipeguard scan . --fix --apply  to auto-fix %d issues%s\n",
			Gray, totalFixable, Reset)
	}

	fmt.Fprintln(t.Writer)
}

func severityIcon(sev rules.Severity) string {
	switch sev {
	case rules.Critical:
		return "\u25cf"
	case rules.High:
		return "\u25b2"
	case rules.Medium:
		return "\u25a0"
	case rules.Low:
		return "\u25cb"
	default:
		return "\u00b7"
	}
}

func scoreColor(score int) string {
	switch {
	case score >= 95:
		return BoldGreen
	case score >= 80:
		return Green
	case score >= 60:
		return Yellow
	case score >= 40:
		return BoldYellow
	default:
		return BoldRed
	}
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
