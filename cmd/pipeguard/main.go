// PipeGuard — Pipeline Security & Quality Scanner by yhakkache
// https://pipeguard.dev | https://github.com/tazi06/pipeguard
// AGPL-3.0 License
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tazi06/pipeguard/pkg/detector"
	"github.com/tazi06/pipeguard/pkg/output"
	"github.com/tazi06/pipeguard/pkg/parser"
	"github.com/tazi06/pipeguard/pkg/rules"
	"github.com/tazi06/pipeguard/pkg/scorer"
)

var (
	version = "0.1.0"

	// CLI flags
	formatFlag    string
	severityFlag  string
	fixFlag       bool
	noColorFlag   bool
	outputFile    string
	rulesFormat   string
	rulesCategory string
	rulesSeverity string
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "pipeguard",
		Short:   "Pipeline Security & Quality Scanner",
		Long:    "PipeGuard scans your CI/CD pipelines, Dockerfiles, and Jenkinsfiles\nfor security vulnerabilities and quality issues.\n\n145 built-in rules | Deterministic auto-fix | Zero network\nhttps://pipeguard.dev",
		Version: version,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	scanCmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan directory for pipeline security and quality issues",
		Long:  "Scan the specified directory (or current directory) for .gitlab-ci.yml,\nGitHub Actions workflows, Jenkinsfiles, and Dockerfiles.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runScan,
	}

	scanCmd.Flags().StringVarP(&formatFlag, "format", "f", "terminal", "Output format: terminal, json, sarif, html")
	scanCmd.Flags().StringVarP(&severityFlag, "severity", "s", "", "Filter by minimum severity: critical, high, medium, low")
	scanCmd.Flags().BoolVar(&fixFlag, "fix", false, "Show fix suggestions for violations")
	scanCmd.Flags().BoolVar(&noColorFlag, "no-color", false, "Disable colored output")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")

	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Lists all the rules",
		RunE:  getRules,
	}

	rulesCmd.Flags().StringVarP(&rulesFormat, "format", "f", "table", "Output Format: table,json")
	rulesCmd.Flags().StringVar(&rulesCategory, "category", "", "Filter by category (SEC, SAS, SCA, DST, DEP, GOV, JEN, DOC, PQL)")
	rulesCmd.Flags().StringVarP(&rulesSeverity, "severity", "s", "", "Filter by severity (critical, high, medium, low, info)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.SetVersionTemplate(fmt.Sprintf("PipeGuard v%s — Pipeline Security & Quality Scanner by yhakkache\n", version))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Determine scan path
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Check path exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", absPath)
	}

	// Handle --no-color flag
	if noColorFlag {
		output.DisableColors()
	}

	// Parse severity filter
	var minSeverity rules.Severity
	if severityFlag != "" {
		switch strings.ToLower(severityFlag) {
		case "critical":
			minSeverity = rules.Critical
		case "high":
			minSeverity = rules.High
		case "medium":
			minSeverity = rules.Medium
		case "low":
			minSeverity = rules.Low
		default:
			return fmt.Errorf("invalid severity: %s (use: critical, high, medium, low)", severityFlag)
		}
	}

	// Step 1: Detect files
	files, err := detector.Detect(absPath)
	if err != nil {
		return fmt.Errorf("detection error: %w", err)
	}

	// Step 2: Initialize rule engine
	engine := rules.NewEngine()

	// Step 3: Parse and evaluate each file
	var results []output.FileResult

	for _, file := range files {
		// Parse file content
		parsed, err := parser.Parse(file.Path, file.Type)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot read %s: %v\n", file.Path, err)
			continue
		}

		// Convert to engine format
		var lines []rules.LinePair
		for _, l := range parsed.Lines {
			lines = append(lines, rules.LinePair{
				Number:  l.Number,
				Content: l.Content,
			})
		}

		// Evaluate rules
		violations := engine.Evaluate(file.Path, file.Type, lines, parsed.RawContent)

		// Apply severity filter
		if severityFlag != "" {
			violations = rules.FilterBySeverity(violations, minSeverity)
		}

		// Calculate scores
		score := scorer.Calculate(violations)

		// Make path relative for display
		relPath, err := filepath.Rel(absPath, file.Path)
		if err != nil {
			relPath = file.Path
		}

		results = append(results, output.FileResult{
			Path:         relPath,
			FileType:     file.Type,
			Violations:   violations,
			Score:        score,
			FixableCount: scorer.CountFixable(violations),
		})
	}

	// Step 4: Output results
	writer := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		writer = f
		// Disable colors when writing to file
		output.DisableColors()
	}

	switch strings.ToLower(formatFlag) {
	case "json":
		formatter := output.NewJSONFormatter(writer)
		formatter.FormatReport(results)
	case "sarif":
		formatter := output.NewSARIFFormatter(writer)
		formatter.FormatReport(results)
	case "terminal", "":
		formatter := output.NewTerminalFormatter(writer, fixFlag)
		formatter.FormatReport(results)
	case "html":
		formatter := output.NewHTMLFormatter(writer)
		formatter.FormatReport(results)
	default:
		return fmt.Errorf("unsupported format: %s (use: terminal, json, sarif, html)", formatFlag)
	}

	// Exit code: non-zero if critical or high violations found
	for _, r := range results {
		for _, v := range r.Violations {
			if v.Rule.Severity >= rules.High {
				os.Exit(1)
			}
		}
	}

	return nil
}

// getRules handles the "rules" command, listing all rules with optional filtering and formatting
func getRules(cmd *cobra.Command, args []string) error {
	engine := rules.NewEngine()
	allRules := engine.Rules()
	filtered := filteredRules(allRules)
	switch strings.ToLower(rulesFormat) {
	case "json":
		return rulesJSONFormat(filtered)
	case "table", "":
		rulesTableFormat(filtered)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s (use: table, json)", rulesFormat)
	}
}

// filters rules based on category and severity flags, then sorts by ID
func filteredRules(all []*rules.Rule) []*rules.Rule {
	var result []*rules.Rule
	for _, r := range all {
		if rulesCategory != "" &&
			!strings.EqualFold(string(r.Category), rulesCategory) {
			continue
		}
		if rulesSeverity != "" {
			if !severityMatches(r.Severity, rulesSeverity) {
				continue
			}
		}
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

// checks if the rule severity matches the filter
func severityMatches(ruleSeverity rules.Severity, filter string) bool {
	switch strings.ToLower(filter) {
	case "critical":
		return ruleSeverity == rules.Critical
	case "high":
		return ruleSeverity == rules.High
	case "medium":
		return ruleSeverity == rules.Medium
	case "low":
		return ruleSeverity == rules.Low
	case "info":
		return ruleSeverity == rules.Info
	default:
		return false
	}
}

// prints the all rules in a formatted table
func rulesTableFormat(rulesList []*rules.Rule) {
	fmt.Printf("%-6s %-10s %-6s %s\n", "ID", "SEVERITY", "CAT", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 80))

	for _, r := range rulesList {
		fmt.Printf("%-6s %-10s %-6s %s\n",
			r.ID,
			r.Severity.String(),
			r.Category,
			r.Description,
		)
	}

	if len(rulesList) == 0 {
		fmt.Println("No rules matched the filter.")
	}

}

// prints the all rules in JSON format
func rulesJSONFormat(rulesList []*rules.Rule) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", " ")
	return encoder.Encode(rulesList)
}
