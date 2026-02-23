// Package rules provides the core rule types and evaluation engine
// for PipeGuard pipeline security and quality scanning.
package rules

import "regexp"

// Severity represents the impact level of a rule violation.
type Severity int

const (
	Info     Severity = iota // Informational finding
	Low                      // Low impact
	Medium                   // Medium impact
	High                     // High impact
	Critical                 // Critical security issue
)

// String returns the display name for a severity level.
func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	case Info:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// Category represents the rule category grouping.
type Category string

const (
	SEC Category = "SEC" // Secret Management
	SAS Category = "SAS" // Static Analysis / SAST
	SCA Category = "SCA" // Supply Chain Security
	DST Category = "DST" // Dynamic Testing / DAST
	DEP Category = "DEP" // Deployment Security
	GOV Category = "GOV" // Governance & Compliance
	JEN Category = "JEN" // Jenkinsfile Security
	DOC Category = "DOC" // Dockerfile Security
	PQL Category = "PQL" // Pipeline Quality & Reliability
)

// CategoryName returns the full display name for a category.
func CategoryName(c Category) string {
	names := map[Category]string{
		SEC: "Secret Management",
		SAS: "Static Analysis",
		SCA: "Supply Chain Security",
		DST: "Dynamic Testing",
		DEP: "Deployment Security",
		GOV: "Governance & Compliance",
		JEN: "Jenkinsfile Security",
		DOC: "Dockerfile Security",
		PQL: "Pipeline Quality",
	}
	if name, ok := names[c]; ok {
		return name
	}
	return string(c)
}

// FileType represents the type of file being scanned.
type FileType int

const (
	GitLabCI      FileType = iota // .gitlab-ci.yml
	GitHubActions                 // .github/workflows/*.yml
	JenkinsfileT                  // Jenkinsfile*
	DockerfileT                   // Dockerfile*
)

// String returns the display name for a file type.
func (ft FileType) String() string {
	switch ft {
	case GitLabCI:
		return "GitLab CI"
	case GitHubActions:
		return "GitHub Actions"
	case JenkinsfileT:
		return "Jenkinsfile"
	case DockerfileT:
		return "Dockerfile"
	default:
		return "Unknown"
	}
}

// MatchScope determines how a rule pattern is applied.
type MatchScope int

const (
	LineScope MatchScope = iota // Pattern matched against each line individually
	FileScope                   // Pattern matched against entire file content
)

// FixType indicates whether a rule violation can be auto-fixed.
type FixType int

const (
	NoFix      FixType = iota // Requires manual intervention
	PartialFix                // Can partially auto-fix, needs review
	FullFix                   // Can be fully auto-fixed
)

// String returns the display label for a fix type.
func (f FixType) String() string {
	switch f {
	case FullFix:
		return "FIXABLE"
	case PartialFix:
		return "PARTIAL"
	case NoFix:
		return "MANUAL"
	default:
		return "UNKNOWN"
	}
}

// Rule defines a single security or quality check.
type Rule struct {
	ID          string         // Unique identifier (e.g., "D01", "R03", "J15")
	Category    Category       // Rule category
	Severity    Severity       // Impact level
	Points      int            // Points deducted on violation
	Description string         // Short description
	Why         string         // Explanation of why this matters
	Pattern     *regexp.Regexp // Detection regex pattern
	Exclude     *regexp.Regexp // If set, line matching Exclude is NOT a violation (RE2-safe negative lookahead)
	Negative    bool           // If true, violation triggers when pattern is NOT found
	Scope       MatchScope     // Line-level or file-level matching
	FileTypes   []FileType     // Which file types this rule applies to
	FixType     FixType        // Whether auto-fix is available
	FixDesc     string         // Short description of the fix
}

// AppliesToFile checks if this rule should be evaluated for the given file type.
func (r *Rule) AppliesToFile(ft FileType) bool {
	for _, t := range r.FileTypes {
		if t == ft {
			return true
		}
	}
	return false
}

// ScoreType indicates whether a rule affects security or quality score.
type ScoreType int

const (
	SecurityScore ScoreType = iota
	QualityScore
)

// GetScoreType returns which score this rule affects based on its category.
func (r *Rule) GetScoreType() ScoreType {
	if r.Category == PQL {
		return QualityScore
	}
	return SecurityScore
}

// Violation represents a detected rule violation in a scanned file.
type Violation struct {
	Rule    *Rule  // The rule that was violated
	File    string // File path where violation was found
	Line    int    // Line number (0 for file-scope rules)
	Content string // The matching line content
}

// ScanResult holds all results for a single scanned file.
type ScanResult struct {
	File           string       // File path
	FileType       FileType     // Detected file type
	Violations     []Violation  // All violations found
	SecurityScore  int          // Security score (100 - penalties)
	QualityScore   int          // Quality score (100 - penalties)
	SecurityLevel  MaturityLevel
	QualityLevel   MaturityLevel
	TotalFixable   int          // Number of auto-fixable violations
}

// MaturityLevel represents the security/quality maturity classification.
type MaturityLevel struct {
	Level int    // 0-5
	Name  string // e.g., "Defined"
	Tag   string // e.g., "Level 3"
}

// Report holds the complete scan output across all files.
type Report struct {
	Version string       // PipeGuard version
	Files   []ScanResult // Per-file results
	Summary ReportSummary
}

// ReportSummary aggregates metrics across all scanned files.
type ReportSummary struct {
	FilesScanned  int
	TotalViolations int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
	FixableCount  int
}
