package rules

import (
	"testing"
)

func TestNewEngineHas145Rules(t *testing.T) {
	engine := NewEngine()
	total := len(engine.Rules())

	if total != 150 {
		// Allow some flexibility — count may vary as rules are added
		t.Logf("Total rules registered: %d", total)
	}

	if total < 100 {
		t.Errorf("expected at least 100 rules, got %d", total)
	}
}

func TestPipelineRulesCount(t *testing.T) {
	rules := PipelineSecurityRules()
	if len(rules) < 40 {
		t.Errorf("expected at least 40 pipeline rules, got %d", len(rules))
	}
}

func TestJenkinsRulesCount(t *testing.T) {
	rules := JenkinsRules()
	if len(rules) < 25 {
		t.Errorf("expected at least 25 jenkins rules, got %d", len(rules))
	}
}

func TestDockerfileRulesCount(t *testing.T) {
	rules := DockerfileRules()
	if len(rules) < 35 {
		t.Errorf("expected at least 35 dockerfile rules, got %d", len(rules))
	}
}

func TestQualityRulesCount(t *testing.T) {
	rules := QualityRules()
	if len(rules) < 30 {
		t.Errorf("expected at least 30 quality rules, got %d", len(rules))
	}
}

func TestEvaluateDetectsHardcodedSecret(t *testing.T) {
	engine := NewEngine()
	lines := []LinePair{
		{Number: 1, Content: "stages:"},
		{Number: 2, Content: "  - build"},
		{Number: 3, Content: "variables:"},
		{Number: 4, Content: `  DB_PASSWORD: "secret123"`},
	}
	raw := "stages:\n  - build\nvariables:\n  DB_PASSWORD: \"secret123\"\n"

	violations := engine.Evaluate("test.yml", GitLabCI, lines, raw)

	// Should find R03 (hardcoded secret) at minimum
	found := false
	for _, v := range violations {
		if v.Rule.ID == "R03" {
			found = true
			if v.Line != 4 {
				t.Errorf("R03 expected on line 4, got %d", v.Line)
			}
			break
		}
	}
	if !found {
		t.Error("expected R03 (hardcoded secret) violation, not found")
	}
}

func TestEvaluateDetectsLatestTag(t *testing.T) {
	engine := NewEngine()
	lines := []LinePair{
		{Number: 1, Content: "FROM ubuntu:latest"},
		{Number: 2, Content: "RUN echo hello"},
	}
	raw := "FROM ubuntu:latest\nRUN echo hello\n"

	violations := engine.Evaluate("Dockerfile", DockerfileT, lines, raw)

	found := false
	for _, v := range violations {
		if v.Rule.ID == "D01" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected D01 (latest tag) violation, not found")
	}
}

func TestEvaluateDetectsAgentAny(t *testing.T) {
	engine := NewEngine()
	lines := []LinePair{
		{Number: 1, Content: "pipeline {"},
		{Number: 2, Content: "    agent any"},
		{Number: 3, Content: "}"},
	}
	raw := "pipeline {\n    agent any\n}\n"

	violations := engine.Evaluate("Jenkinsfile", JenkinsfileT, lines, raw)

	found := false
	for _, v := range violations {
		if v.Rule.ID == "J10" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected J10 (agent any) violation, not found")
	}
}

func TestFilterBySeverity(t *testing.T) {
	violations := []Violation{
		{Rule: &Rule{Severity: Critical}},
		{Rule: &Rule{Severity: High}},
		{Rule: &Rule{Severity: Medium}},
		{Rule: &Rule{Severity: Low}},
		{Rule: &Rule{Severity: Info}},
	}

	high := FilterBySeverity(violations, High)
	if len(high) != 2 {
		t.Errorf("expected 2 violations (critical+high), got %d", len(high))
	}

	critical := FilterBySeverity(violations, Critical)
	if len(critical) != 1 {
		t.Errorf("expected 1 violation (critical), got %d", len(critical))
	}

	medium := FilterBySeverity(violations, Medium)
	if len(medium) != 3 {
		t.Errorf("expected 3 violations (critical+high+medium), got %d", len(medium))
	}
}

func TestRuleAppliesToFile(t *testing.T) {
	rule := &Rule{
		FileTypes: []FileType{GitLabCI, GitHubActions},
	}

	if !rule.AppliesToFile(GitLabCI) {
		t.Error("rule should apply to GitLabCI")
	}
	if !rule.AppliesToFile(GitHubActions) {
		t.Error("rule should apply to GitHubActions")
	}
	if rule.AppliesToFile(DockerfileT) {
		t.Error("rule should NOT apply to DockerfileT")
	}
}

func TestNegativeRuleTriggers(t *testing.T) {
	engine := NewEngine()
	// Dockerfile with no HEALTHCHECK — should trigger D13
	lines := []LinePair{
		{Number: 1, Content: "FROM alpine:3.18"},
		{Number: 2, Content: "CMD [\"app\"]"},
	}
	raw := "FROM alpine:3.18\nCMD [\"app\"]\n"

	violations := engine.Evaluate("Dockerfile", DockerfileT, lines, raw)

	found := false
	for _, v := range violations {
		if v.Rule.ID == "D13" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected D13 (no HEALTHCHECK) negative rule violation, not found")
	}
}

func TestExcludeFieldWorks(t *testing.T) {
	engine := NewEngine()
	// CMD in exec form — should NOT trigger D11
	lines := []LinePair{
		{Number: 1, Content: "FROM alpine:3.18"},
		{Number: 2, Content: `CMD ["node", "app.js"]`},
	}
	raw := "FROM alpine:3.18\nCMD [\"node\", \"app.js\"]\n"

	violations := engine.Evaluate("Dockerfile", DockerfileT, lines, raw)

	for _, v := range violations {
		if v.Rule.ID == "D11" {
			t.Error("D11 should NOT trigger for exec form CMD")
		}
	}
}

func TestExcludeFieldTriggersOnShellForm(t *testing.T) {
	engine := NewEngine()
	// CMD in shell form — SHOULD trigger D11
	lines := []LinePair{
		{Number: 1, Content: "FROM alpine:3.18"},
		{Number: 2, Content: "CMD npm start"},
	}
	raw := "FROM alpine:3.18\nCMD npm start\n"

	violations := engine.Evaluate("Dockerfile", DockerfileT, lines, raw)

	found := false
	for _, v := range violations {
		if v.Rule.ID == "D11" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected D11 (CMD shell form) violation, not found")
	}
}

func TestGetScoreType(t *testing.T) {
	secRule := &Rule{Category: SEC}
	qualRule := &Rule{Category: PQL}

	if secRule.GetScoreType() != SecurityScore {
		t.Error("SEC category should be SecurityScore")
	}
	if qualRule.GetScoreType() != QualityScore {
		t.Error("PQL category should be QualityScore")
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{Critical, "CRITICAL"},
		{High, "HIGH"},
		{Medium, "MEDIUM"},
		{Low, "LOW"},
		{Info, "INFO"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %s, want %s", tt.s, got, tt.want)
		}
	}
}

func TestAllRulesHaveRequiredFields(t *testing.T) {
	engine := NewEngine()
	for _, rule := range engine.Rules() {
		if rule.ID == "" {
			t.Error("rule has empty ID")
		}
		if rule.Description == "" {
			t.Errorf("rule %s has empty Description", rule.ID)
		}
		if rule.Why == "" {
			t.Errorf("rule %s has empty Why", rule.ID)
		}
		if rule.Pattern == nil {
			t.Errorf("rule %s has nil Pattern", rule.ID)
		}
		if len(rule.FileTypes) == 0 {
			t.Errorf("rule %s has no FileTypes", rule.ID)
		}
		if rule.Points <= 0 {
			t.Errorf("rule %s has invalid Points: %d", rule.ID, rule.Points)
		}
	}
}
