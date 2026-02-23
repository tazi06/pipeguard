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
	Writer io.Writer
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
		fmt.Fprintf(t.Writer, "\n%sNo scannable files found.%s\n", Gray, Reset)
		fmt.Fprintf(t.Writer, "%sSupported: .gitlab-ci.yml, GitHub Actions, Jenkinsfile, Dockerfile%s\n\n", Gray, Reset)
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
	Path       string
	FileType   rules.FileType
	Violations []rules.Violation
	Score      scorer.Score
	FixableCount int
}

func (t *TerminalFormatter) printBanner() {
	separator := strings.Repeat("=", 68)
	fmt.Fprintf(t.Writer, "\n%s%sPIPEGUARD v%s%s — Pipeline Security & Quality Scanner by yhakkache\n",
		BoldBlue, Bold, version, Reset)
	fmt.Fprintf(t.Writer, "%s%s%s\n", Gray, separator, Reset)
}

func (t *TerminalFormatter) printFileResult(result FileResult) {
	fmt.Fprintf(t.Writer, "\n%s[SCAN]%s %s%s%s", BoldBlue, Reset, Bold, result.Path, Reset)

	if len(result.Violations) == 0 {
		fmt.Fprintf(t.Writer, " %s(no violations)%s\n", BoldGreen, Reset)
		return
	}

	fmt.Fprintf(t.Writer, " %s(%d violations found)%s\n\n",
		BoldRed, len(result.Violations), Reset)

	for _, v := range result.Violations {
		t.printViolation(v)
	}
}

func (t *TerminalFormatter) printViolation(v rules.Violation) {
	sevColor := SeverityColor(v.Rule.Severity.String())
	sevPad := padRight(v.Rule.Severity.String(), 10)

	// Main violation line
	fmt.Fprintf(t.Writer, "  %s%-10s%s %s%-5s%s %s",
		sevColor, sevPad, Reset,
		Bold, v.Rule.ID, Reset,
		v.Rule.Description)

	// Points deduction
	fmt.Fprintf(t.Writer, "%s  -%dpts%s\n", Gray, v.Rule.Points, Reset)

	// Line info
	if v.Line > 0 && v.Content != "" {
		content := v.Content
		if len(content) > 60 {
			content = content[:57] + "..."
		}
		fmt.Fprintf(t.Writer, "  %s%s Line %d | %s%s\n",
			strings.Repeat(" ", 10), Gray, v.Line, content, Reset)
	}

	// Why
	fmt.Fprintf(t.Writer, "  %s%s %s%s\n",
		strings.Repeat(" ", 10), Gray, v.Rule.Why, Reset)

	// Fix suggestion
	if t.ShowFix && v.Rule.FixDesc != "" {
		fixColor := Green
		fixLabel := "Fix"
		if v.Rule.FixType == rules.FullFix {
			fixLabel = "Fix [FIXABLE]"
		} else if v.Rule.FixType == rules.PartialFix {
			fixLabel = "Fix [PARTIAL]"
		}
		fmt.Fprintf(t.Writer, "  %s%s %s%s: %s%s\n",
			strings.Repeat(" ", 10), fixColor, fixLabel, Reset, Green, v.Rule.FixDesc)
		fmt.Fprintf(t.Writer, "%s", Reset)
	}

	fmt.Fprintln(t.Writer)
}

func (t *TerminalFormatter) printSummary(results []FileResult, totalViolations, totalFixable, critical, high, medium, low int) {
	separator := strings.Repeat("-", 68)
	fmt.Fprintf(t.Writer, "%s%s%s\n", Gray, separator, Reset)
	fmt.Fprintf(t.Writer, "%s%sRESULTS%s\n", Bold, White, Reset)
	fmt.Fprintf(t.Writer, "%s%s%s\n", Gray, separator, Reset)

	fmt.Fprintf(t.Writer, "  Files scanned:    %s%d%s\n", Bold, len(results), Reset)

	violationDetail := fmt.Sprintf("%d", totalViolations)
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
		violationDetail = fmt.Sprintf("%d (%s)", totalViolations, strings.Join(parts, ", "))
	}
	fmt.Fprintf(t.Writer, "  Violations:       %s\n", violationDetail)
	fmt.Fprintf(t.Writer, "  Auto-fixable:     %s%d/%d%s\n", Green, totalFixable, totalViolations, Reset)

	fmt.Fprintln(t.Writer)

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

		if hasSecViolations || len(result.Violations) == 0 {
			fmt.Fprintf(t.Writer, "  %s%-20s%s %sSECURITY  %3d/100%s    %s%s — %s%s\n",
				Bold, result.Path, Reset,
				secColor, result.Score.SecurityScore, Reset,
				secColor, result.Score.SecurityLevel.Tag, result.Score.SecurityLevel.Name, Reset)
		}
		if hasQualViolations || len(result.Violations) == 0 {
			fmt.Fprintf(t.Writer, "  %s%-20s%s %sQUALITY   %3d/100%s    %s%s — %s%s\n",
				Bold, strings.Repeat(" ", len(result.Path)), Reset,
				qualColor, result.Score.QualityScore, Reset,
				qualColor, result.Score.QualityLevel.Tag, result.Score.QualityLevel.Name, Reset)
		}
	}

	fmt.Fprintf(t.Writer, "%s%s%s\n", Gray, separator, Reset)

	if totalFixable > 0 && !t.ShowFix {
		fmt.Fprintf(t.Writer, "  %sRun: pipeguard scan . --fix  to see fix suggestions%s\n", Gray, Reset)
	}
	if t.ShowFix && totalFixable > 0 {
		fmt.Fprintf(t.Writer, "  %sRun: pipeguard scan . --fix --apply  to auto-fix %d issues%s\n",
			Gray, totalFixable, Reset)
	}

	fmt.Fprintln(t.Writer)
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
