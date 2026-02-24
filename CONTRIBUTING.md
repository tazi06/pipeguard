# Contributing to PipeGuard

Thank you for your interest in contributing to PipeGuard! Every contribution matters — whether it's a new rule, a bug fix, documentation, or just reporting an issue.

## Quick Start

```bash
# Fork and clone
git clone https://github.com/<your-username>/pipeguard.git
cd pipeguard

# Build
go build -o pipeguard ./cmd/pipeguard/

# Run tests (must pass before submitting)
go test ./... -race

# Try it
./pipeguard scan examples/
```

**Requirements:** Go 1.24+

## Project Structure

```
cmd/pipeguard/          → CLI entry point (Cobra)
pkg/
  detector/             → File discovery (walks directory tree)
  parser/               → File content parsing
  rules/
    types.go            → Rule, Violation, Severity types
    engine.go           → Rule evaluation engine
    pipeline_rules.go   → R01-R45: GitLab CI / GitHub Actions rules
    dockerfile_rules.go → D01-D40: Dockerfile rules
    jenkins_rules.go    → J01-J30: Jenkinsfile rules
    quality_rules.go    → Q01-Q35: Pipeline quality rules
  scorer/               → Dual scoring (Security + Quality)
  output/
    terminal.go         → Terminal formatter (box-drawing UI)
    json.go             → JSON output
    sarif.go            → SARIF v2.1.0 output
    colors.go           → ANSI color codes
examples/               → Test files (intentionally bad pipelines)
```

## How to Contribute

### 1. Add a New Rule (Most Common Contribution)

This is the easiest way to contribute. Each rule is a Go struct in one of the `*_rules.go` files.

**Example — adding rule R46:**

```go
// In pkg/rules/pipeline_rules.go, add to PipelineSecurityRules():
{
    ID:          "R46",
    Category:    GOV,
    Severity:    Medium,
    Points:      1,
    Description: "No dependency review on pull requests",
    Why:         "New dependencies added in PRs bypass security review without automated checks",
    Pattern:     regexp.MustCompile(`dependency.review|dependency-review-action`),
    Negative:    true,                    // Triggers when pattern is NOT found
    Scope:       FileScope,               // Checks entire file, not per-line
    FileTypes:   []FileType{GitHubActions},
    FixType:     FullFix,
    FixDesc:     "Add github/dependency-review-action to PR workflows",
},
```

**Rule checklist:**
- [ ] Unique ID (R46, D41, J31, Q36)
- [ ] Correct Category (SEC, SAS, SCA, DST, DEP, GOV, JEN, DOC, PQL)
- [ ] Realistic Severity and Points (see [scoring docs](https://docs.pipeguard.dev/scoring.html))
- [ ] Clear `Description` (< 60 chars)
- [ ] Actionable `Why` (explains real-world impact)
- [ ] Tested regex `Pattern`
- [ ] `FixDesc` with concrete fix action
- [ ] Update rule count in test: `TestNewEngineHas145Rules` → `146`

### 2. Fix a Bug

1. Check [open issues](https://github.com/tazi06/pipeguard/issues)
2. Comment "I'll work on this" to avoid duplicate effort
3. Write a failing test first, then fix

### 3. Improve Documentation

- Docs site source: managed separately (see [docs.pipeguard.dev](https://docs.pipeguard.dev))
- README, code comments, and GoDoc are in this repo
- Typo fixes and clarifications are always welcome

### 4. Add Output Format

Currently: terminal, JSON, SARIF. Want to add HTML, JUnit XML, or CSV? Look at `pkg/output/json.go` as a template.

## Coding Standards

- **Go conventions**: `gofmt`, `golangci-lint`
- **Tests required**: Every new rule or feature must have tests
- **No external runtime deps**: PipeGuard runs with zero network, zero config
- **Regex only**: Rules use Go `regexp` (RE2) — no YAML parsing, no AST
- **Comments**: Every exported function needs a GoDoc comment

## Submitting a Pull Request

1. **Fork** the repo and create a branch: `git checkout -b feat/rule-R46`
2. **Make changes** and ensure `go test ./... -race` passes
3. **Commit** with conventional commits:
   - `feat: add rule R46 — dependency review on PRs`
   - `fix: R03 false positive on base64 encoded strings`
   - `docs: improve scoring explanation in README`
4. **Push** and open a PR against `main`
5. **Fill out the PR template** — describe what and why

## Commit Convention

```
feat:  New feature or rule
fix:   Bug fix
docs:  Documentation only
test:  Adding or fixing tests
ci:    CI/CD changes
chore: Maintenance (deps, formatting)
```

## Development Tips

```bash
# Run specific test
go test ./pkg/rules/ -run TestEvaluateDetectsHardcodedSecret -v

# Test your rule against example files
./pipeguard scan examples/ --severity low | grep "R46"

# Check JSON output structure
./pipeguard scan examples/ -f json | jq '.files[0].violations[] | select(.rule_id == "R46")'

# Lint before pushing
golangci-lint run ./...
```

## Severity Guide

| Severity | When to Use | Points |
|----------|-------------|--------|
| CRITICAL | Direct security breach if exploited | 2-3 |
| HIGH | Significant risk, needs fixing soon | 1-3 |
| MEDIUM | Best practice violation, moderate risk | 1-2 |
| LOW | Nice to have, minor improvement | 1-2 |

**Multipliers**: CRITICAL ×3, HIGH ×2, MEDIUM/LOW ×1

## Questions?

- Open a [Discussion](https://github.com/tazi06/pipeguard/discussions) or [Issue](https://github.com/tazi06/pipeguard/issues)
- Tag `@yhakkache` for architecture questions

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0 License](LICENSE).
