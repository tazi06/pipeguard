package output

import (
	"encoding/json"
	"io"

	"github.com/tazi06/pipeguard/pkg/rules"
	"github.com/tazi06/pipeguard/pkg/scorer"
)

// JSONReport is the top-level JSON output structure.
type JSONReport struct {
	Tool    string           `json:"tool"`
	Version string           `json:"version"`
	Files   []JSONFileResult `json:"files"`
	Summary JSONSummary      `json:"summary"`
}

// JSONFileResult holds per-file results in JSON format.
type JSONFileResult struct {
	Path          string          `json:"path"`
	Type          string          `json:"type"`
	Violations    []JSONViolation `json:"violations"`
	SecurityScore int             `json:"security_score"`
	QualityScore  int             `json:"quality_score"`
	SecurityLevel string          `json:"security_level"`
	QualityLevel  string          `json:"quality_level"`
}

// JSONViolation represents a single violation in JSON format.
type JSONViolation struct {
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Points      int    `json:"points"`
	Description string `json:"description"`
	Why         string `json:"why"`
	Line        int    `json:"line,omitempty"`
	Content     string `json:"content,omitempty"`
	FixType     string `json:"fix_type"`
	FixDesc     string `json:"fix_description,omitempty"`
}

// JSONSummary holds aggregate metrics.
type JSONSummary struct {
	FilesScanned    int `json:"files_scanned"`
	TotalViolations int `json:"total_violations"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	Fixable         int `json:"fixable"`
}

// JSONFormatter outputs results in JSON format.
type JSONFormatter struct {
	Writer io.Writer
}

// NewJSONFormatter creates a JSON output formatter.
func NewJSONFormatter(w io.Writer) *JSONFormatter {
	return &JSONFormatter{Writer: w}
}

// FormatReport outputs the complete scan report as JSON.
func (j *JSONFormatter) FormatReport(results []FileResult) {
	report := JSONReport{
		Tool:    "pipeguard",
		Version: version,
	}

	totalViolations := 0
	totalFixable := 0
	critical, high, medium, low := 0, 0, 0, 0

	for _, result := range results {
		fr := JSONFileResult{
			Path:          result.Path,
			Type:          result.FileType.String(),
			SecurityScore: result.Score.SecurityScore,
			QualityScore:  result.Score.QualityScore,
			SecurityLevel: result.Score.SecurityLevel.Name,
			QualityLevel:  result.Score.QualityLevel.Name,
		}

		for _, v := range result.Violations {
			jv := JSONViolation{
				RuleID:      v.Rule.ID,
				Category:    string(v.Rule.Category),
				Severity:    v.Rule.Severity.String(),
				Points:      v.Rule.Points,
				Description: v.Rule.Description,
				Why:         v.Rule.Why,
				Line:        v.Line,
				Content:     v.Content,
				FixType:     v.Rule.FixType.String(),
				FixDesc:     v.Rule.FixDesc,
			}
			fr.Violations = append(fr.Violations, jv)

			switch v.Rule.Severity {
			case rules.Critical:
				critical++
			case rules.High:
				high++
			case rules.Medium:
				medium++
			case rules.Low:
				low++
			}
			if v.Rule.FixType == rules.FullFix || v.Rule.FixType == rules.PartialFix {
				totalFixable++
			}
		}

		totalViolations += len(result.Violations)
		report.Files = append(report.Files, fr)
	}

	report.Summary = JSONSummary{
		FilesScanned:    len(results),
		TotalViolations: totalViolations,
		Critical:        critical,
		High:            high,
		Medium:          medium,
		Low:             low,
		Fixable:         totalFixable,
	}

	enc := json.NewEncoder(j.Writer)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
}

// FormatSingle outputs results for a single check (used by other tools).
func FormatViolationsJSON(violations []rules.Violation, score scorer.Score) ([]byte, error) {
	type result struct {
		Violations    []JSONViolation `json:"violations"`
		SecurityScore int             `json:"security_score"`
		QualityScore  int             `json:"quality_score"`
	}

	r := result{
		SecurityScore: score.SecurityScore,
		QualityScore:  score.QualityScore,
	}

	for _, v := range violations {
		r.Violations = append(r.Violations, JSONViolation{
			RuleID:      v.Rule.ID,
			Category:    string(v.Rule.Category),
			Severity:    v.Rule.Severity.String(),
			Points:      v.Rule.Points,
			Description: v.Rule.Description,
			Line:        v.Line,
			Content:     v.Content,
		})
	}

	return json.MarshalIndent(r, "", "  ")
}
