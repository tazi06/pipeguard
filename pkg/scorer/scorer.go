// Package scorer calculates security and quality scores from violations
// and maps them to maturity levels.
package scorer

import "github.com/tazi06/pipeguard/pkg/rules"

// Score holds the calculated scores for a scanned file.
type Score struct {
	SecurityScore  int
	QualityScore   int
	SecurityLevel  rules.MaturityLevel
	QualityLevel   rules.MaturityLevel
	SecurityMax    int
	QualityMax     int
}

// Calculate computes security and quality scores from a list of violations.
// Each score starts at 100 and is reduced by the points of each violation.
func Calculate(violations []rules.Violation) Score {
	secPenalty := 0
	qualPenalty := 0

	for _, v := range violations {
		switch v.Rule.GetScoreType() {
		case rules.SecurityScore:
			secPenalty += v.Rule.Points
		case rules.QualityScore:
			qualPenalty += v.Rule.Points
		}
	}

	secScore := 100 - secPenalty
	if secScore < 0 {
		secScore = 0
	}

	qualScore := 100 - qualPenalty
	if qualScore < 0 {
		qualScore = 0
	}

	return Score{
		SecurityScore: secScore,
		QualityScore:  qualScore,
		SecurityLevel: GetMaturityLevel(secScore),
		QualityLevel:  GetMaturityLevel(qualScore),
		SecurityMax:   100,
		QualityMax:    100,
	}
}

// GetMaturityLevel maps a score (0-100) to a maturity level (0-5).
func GetMaturityLevel(score int) rules.MaturityLevel {
	switch {
	case score >= 95:
		return rules.MaturityLevel{Level: 5, Name: "Optimized", Tag: "Level 5"}
	case score >= 80:
		return rules.MaturityLevel{Level: 4, Name: "Managed", Tag: "Level 4"}
	case score >= 60:
		return rules.MaturityLevel{Level: 3, Name: "Defined", Tag: "Level 3"}
	case score >= 40:
		return rules.MaturityLevel{Level: 2, Name: "Developing", Tag: "Level 2"}
	case score >= 20:
		return rules.MaturityLevel{Level: 1, Name: "Basic", Tag: "Level 1"}
	default:
		return rules.MaturityLevel{Level: 0, Name: "None", Tag: "Level 0"}
	}
}

// CountBySeverity counts violations by severity level.
func CountBySeverity(violations []rules.Violation) (critical, high, medium, low, info int) {
	for _, v := range violations {
		switch v.Rule.Severity {
		case rules.Critical:
			critical++
		case rules.High:
			high++
		case rules.Medium:
			medium++
		case rules.Low:
			low++
		case rules.Info:
			info++
		}
	}
	return
}

// CountFixable returns the number of auto-fixable violations.
func CountFixable(violations []rules.Violation) int {
	count := 0
	for _, v := range violations {
		if v.Rule.FixType == rules.FullFix || v.Rule.FixType == rules.PartialFix {
			count++
		}
	}
	return count
}

// HasSecurityRules checks if any violations affect the security score.
func HasSecurityRules(violations []rules.Violation) bool {
	for _, v := range violations {
		if v.Rule.GetScoreType() == rules.SecurityScore {
			return true
		}
	}
	return false
}

// HasQualityRules checks if any violations affect the quality score.
func HasQualityRules(violations []rules.Violation) bool {
	for _, v := range violations {
		if v.Rule.GetScoreType() == rules.QualityScore {
			return true
		}
	}
	return false
}
