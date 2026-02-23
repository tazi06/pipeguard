package scorer

import (
	"testing"

	"github.com/tazi06/pipeguard/pkg/rules"
)

func TestCalculateEmptyViolations(t *testing.T) {
	score := Calculate(nil)
	if score.SecurityScore != 100 {
		t.Errorf("expected security score 100 with no violations, got %d", score.SecurityScore)
	}
	if score.QualityScore != 100 {
		t.Errorf("expected quality score 100 with no violations, got %d", score.QualityScore)
	}
}

func TestCalculateSecurityDeduction(t *testing.T) {
	violations := []rules.Violation{
		{Rule: &rules.Rule{Category: rules.SEC, Severity: rules.Critical, Points: 5}},
		{Rule: &rules.Rule{Category: rules.SEC, Severity: rules.High, Points: 3}},
	}

	// Critical: 5*3=15, High: 3*2=6 → penalty 21 → score 79
	score := Calculate(violations)
	if score.SecurityScore != 79 {
		t.Errorf("expected security score 79 (100-15-6), got %d", score.SecurityScore)
	}
	if score.QualityScore != 100 {
		t.Errorf("expected quality score 100 (no PQL violations), got %d", score.QualityScore)
	}
	// Critical present → max Level 2
	if score.SecurityLevel.Level != 2 {
		t.Errorf("expected security level 2 (capped by critical), got %d", score.SecurityLevel.Level)
	}
}

func TestCalculateQualityDeduction(t *testing.T) {
	violations := []rules.Violation{
		{Rule: &rules.Rule{Category: rules.PQL, Severity: rules.Medium, Points: 3}},
		{Rule: &rules.Rule{Category: rules.PQL, Severity: rules.Low, Points: 2}},
	}

	// Medium: 3*1=3, Low: 2*1=2 → penalty 5 → score 95
	score := Calculate(violations)
	if score.SecurityScore != 100 {
		t.Errorf("expected security score 100, got %d", score.SecurityScore)
	}
	if score.QualityScore != 95 {
		t.Errorf("expected quality score 95 (100-3-2), got %d", score.QualityScore)
	}
}

func TestScoreNeverBelowZero(t *testing.T) {
	var violations []rules.Violation
	for i := 0; i < 30; i++ {
		violations = append(violations, rules.Violation{
			Rule: &rules.Rule{Category: rules.SEC, Points: 5},
		})
	}

	score := Calculate(violations)
	if score.SecurityScore < 0 {
		t.Errorf("security score should not be negative, got %d", score.SecurityScore)
	}
}

func TestGetMaturityLevel(t *testing.T) {
	tests := []struct {
		score int
		level int
		name  string
	}{
		{0, 0, "None"},
		{15, 0, "None"},
		{20, 1, "Basic"},
		{39, 1, "Basic"},
		{40, 2, "Developing"},
		{59, 2, "Developing"},
		{60, 3, "Defined"},
		{74, 3, "Defined"},
		{80, 4, "Managed"},
		{89, 4, "Managed"},
		{95, 5, "Optimized"},
		{100, 5, "Optimized"},
	}

	for _, tt := range tests {
		ml := GetMaturityLevel(tt.score)
		if ml.Level != tt.level {
			t.Errorf("score %d: expected level %d, got %d", tt.score, tt.level, ml.Level)
		}
		if ml.Name != tt.name {
			t.Errorf("score %d: expected name %s, got %s", tt.score, tt.name, ml.Name)
		}
	}
}

func TestCountBySeverity(t *testing.T) {
	violations := []rules.Violation{
		{Rule: &rules.Rule{Severity: rules.Critical}},
		{Rule: &rules.Rule{Severity: rules.Critical}},
		{Rule: &rules.Rule{Severity: rules.High}},
		{Rule: &rules.Rule{Severity: rules.Medium}},
		{Rule: &rules.Rule{Severity: rules.Low}},
	}

	critical, high, medium, low, info := CountBySeverity(violations)
	if critical != 2 {
		t.Errorf("expected 2 critical, got %d", critical)
	}
	if high != 1 {
		t.Errorf("expected 1 high, got %d", high)
	}
	if medium != 1 {
		t.Errorf("expected 1 medium, got %d", medium)
	}
	if low != 1 {
		t.Errorf("expected 1 low, got %d", low)
	}
	if info != 0 {
		t.Errorf("expected 0 info, got %d", info)
	}
}

func TestCountFixable(t *testing.T) {
	violations := []rules.Violation{
		{Rule: &rules.Rule{FixType: rules.FullFix}},
		{Rule: &rules.Rule{FixType: rules.PartialFix}},
		{Rule: &rules.Rule{FixType: rules.NoFix}},
		{Rule: &rules.Rule{FixType: rules.FullFix}},
	}

	count := CountFixable(violations)
	if count != 3 {
		t.Errorf("expected 3 fixable (full+partial), got %d", count)
	}
}
