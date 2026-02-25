// Package rules provides the rule evaluation engine for PipeGuard.
package rules

import "strings"

// Engine holds all registered rules and evaluates them against parsed files.
type Engine struct {
	rules []*Rule
}

// NewEngine creates a new rule engine with all built-in rules registered.
func NewEngine() *Engine {
	e := &Engine{}
	e.rules = append(e.rules, PipelineSecurityRules()...)
	e.rules = append(e.rules, JenkinsRules()...)
	e.rules = append(e.rules, DockerfileRules()...)
	e.rules = append(e.rules, QualityRules()...)
	return e
}

// Rules returns all registered rules.
func (e *Engine) Rules() []*Rule {
	return e.rules
}

// RulesForFile returns only rules that apply to the given file type.
func (e *Engine) RulesForFile(ft FileType) []*Rule {
	var filtered []*Rule
	for _, r := range e.rules {
		if r.AppliesToFile(ft) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// EvaluateResult holds violations from scanning a single file.
type EvaluateResult struct {
	Violations []Violation
}

// Evaluate checks all applicable rules against the given file content.
// lines is a slice of trimmed line strings, rawContent is the full file content.
func (e *Engine) Evaluate(filePath string, fileType FileType, lines []LinePair, rawContent string) []Violation {
	var violations []Violation
	applicableRules := e.RulesForFile(fileType)

	for _, rule := range applicableRules {
		vs := evaluateRule(rule, filePath, lines, rawContent)
		violations = append(violations, vs...)
	}

	return violations
}

// LinePair holds a line number and its content for evaluation.
type LinePair struct {
	Number  int
	Content string
}

// evaluateRule checks a single rule against file content.
func evaluateRule(rule *Rule, filePath string, lines []LinePair, rawContent string) []Violation {
	var violations []Violation

	switch rule.Scope {
	case FileScope:
		violations = evaluateFileScope(rule, filePath, lines, rawContent)
	case LineScope:
		violations = evaluateLineScope(rule, filePath, lines)
	}

	return violations
}

// evaluateFileScope checks if a pattern exists (or not) in the entire file.
func evaluateFileScope(rule *Rule, filePath string, lines []LinePair, rawContent string) []Violation {
	var found bool
	var matchLine int
	var matchContent string

	if rule.Exclude != nil {
		// With Exclude: check line-by-line, found if any line matches Pattern AND NOT Exclude
		for _, line := range lines {
			if rule.Pattern.MatchString(line.Content) && !rule.Exclude.MatchString(line.Content) {
				found = true
				matchLine = line.Number
				matchContent = line.Content
				break
			}
		}
	} else {
		// Without Exclude: check whole content
		found = rule.Pattern.MatchString(rawContent)
		if found {
			for _, line := range lines {
				if rule.Pattern.MatchString(line.Content) {
					matchLine = line.Number
					matchContent = line.Content
					break
				}
			}
		}
	}

	if rule.Negative {
		// Negative rule: violation when pattern is NOT found
		if !found {
			return []Violation{{
				Rule:    rule,
				File:    filePath,
				Line:    0,
				Content: "",
			}}
		}
	} else {
		// Positive rule: violation when pattern IS found
		if found {
			return []Violation{{
				Rule:    rule,
				File:    filePath,
				Line:    matchLine,
				Content: matchContent,
			}}
		}
	}

	return nil
}

// evaluateLineScope checks each line individually against the pattern.
func evaluateLineScope(rule *Rule, filePath string, lines []LinePair) []Violation {
	var violations []Violation

	if rule.Negative {
		// Negative line-scope: not typical, treat as file-scope
		return nil
	}

	for _, line := range lines {
		if rule.Pattern.MatchString(line.Content) {
			// If Exclude is set, skip lines that match the exclusion pattern
			if rule.Exclude != nil && rule.Exclude.MatchString(line.Content) {
				continue
			}
			violations = append(violations, Violation{
				Rule:    rule,
				File:    filePath,
				Line:    line.Number,
				Content: line.Content,
			})
		}
	}

	return violations
}

// FilterBySeverity returns only violations at or above the given severity.
func FilterBySeverity(violations []Violation, minSeverity Severity) []Violation {
	var filtered []Violation
	for _, v := range violations {
		if v.Rule.Severity >= minSeverity {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// removes rules with the given IDs from the engine by reading the give yml config file.
func (e *Engine) DisableRules(ids []string) {
	if len(ids) == 0 {
		return
	}
	idSet := make(map[string]struct{})
	for _, id := range ids {
		idSet[id] = struct{}{}
	}
	var filtered []*Rule
	for _, r := range e.rules {
		if _, disabled := idSet[r.ID]; !disabled {
			filtered = append(filtered, r)
		}
	}
	e.rules = filtered
}

// updates the severity of rules based on the provided overrides map (rule ID -> severity string).
func (e *Engine) OverrideSeverity(overrides map[string]string) {
	if len(overrides) == 0 {
		return
	}
	for _, r := range e.rules {
		if sev, ok := overrides[r.ID]; ok {
			switch strings.ToLower(sev) {
			case "critical":
				r.Severity = Critical
			case "high":
				r.Severity = High
			case "medium":
				r.Severity = Medium
			case "low":
				r.Severity = Low
			case "info":
				r.Severity = Info
			}
		}
	}
}
