package output

import (
	"encoding/json"
	"io"

	"github.com/tazi06/pipeguard/pkg/rules"
)

// SARIF v2.1.0 output format for CI/CD integration (GitHub Security tab, GitLab SAST).

// SARIFReport is the top-level SARIF structure.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool    SARIFTool    `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver (PipeGuard).
type SARIFDriver struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	InformationURI  string          `json:"informationUri"`
	Rules           []SARIFRuleDef  `json:"rules"`
}

// SARIFRuleDef defines a rule in SARIF format.
type SARIFRuleDef struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription SARIFMessage      `json:"shortDescription"`
	FullDescription  SARIFMessage      `json:"fullDescription"`
	DefaultConfig    SARIFRuleConfig   `json:"defaultConfiguration"`
	HelpURI          string            `json:"helpUri,omitempty"`
}

// SARIFRuleConfig holds rule default configuration.
type SARIFRuleConfig struct {
	Level string `json:"level"`
}

// SARIFResult represents a single finding.
type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations,omitempty"`
}

// SARIFMessage holds a text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes where a finding was detected.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation holds file and line information.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifact `json:"artifactLocation"`
	Region           *SARIFRegion  `json:"region,omitempty"`
}

// SARIFArtifact identifies the file.
type SARIFArtifact struct {
	URI string `json:"uri"`
}

// SARIFRegion identifies the line in the file.
type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

// SARIFFormatter outputs results in SARIF v2.1.0 format.
type SARIFFormatter struct {
	Writer io.Writer
}

// NewSARIFFormatter creates a SARIF output formatter.
func NewSARIFFormatter(w io.Writer) *SARIFFormatter {
	return &SARIFFormatter{Writer: w}
}

// FormatReport outputs the complete scan report in SARIF format.
func (s *SARIFFormatter) FormatReport(results []FileResult) {
	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:           "PipeGuard",
				Version:        version,
				InformationURI: "https://pipeguard.dev",
			},
		},
	}

	// Collect unique rules and results
	ruleMap := make(map[string]bool)

	for _, result := range results {
		for _, v := range result.Violations {
			// Add rule definition if not already added
			if !ruleMap[v.Rule.ID] {
				ruleMap[v.Rule.ID] = true
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, SARIFRuleDef{
					ID:               v.Rule.ID,
					Name:             v.Rule.ID,
					ShortDescription: SARIFMessage{Text: v.Rule.Description},
					FullDescription:  SARIFMessage{Text: v.Rule.Why},
					DefaultConfig:    SARIFRuleConfig{Level: sarifLevel(v.Rule.Severity)},
				})
			}

			// Add result
			sarifResult := SARIFResult{
				RuleID:  v.Rule.ID,
				Level:   sarifLevel(v.Rule.Severity),
				Message: SARIFMessage{Text: v.Rule.Description + ": " + v.Rule.Why},
			}

			if v.Line > 0 {
				sarifResult.Locations = []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifact{URI: result.Path},
						Region:           &SARIFRegion{StartLine: v.Line},
					},
				}}
			} else {
				sarifResult.Locations = []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifact{URI: result.Path},
					},
				}}
			}

			run.Results = append(run.Results, sarifResult)
		}
	}

	report.Runs = []SARIFRun{run}

	enc := json.NewEncoder(s.Writer)
	enc.SetIndent("", "  ")
	enc.Encode(report)
}

// sarifLevel converts PipeGuard severity to SARIF level.
func sarifLevel(sev rules.Severity) string {
	switch sev {
	case rules.Critical, rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	case rules.Low, rules.Info:
		return "note"
	default:
		return "note"
	}
}
