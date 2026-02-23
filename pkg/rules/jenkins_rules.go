package rules

import "regexp"

// JenkinsRules returns all J01-J30 Jenkinsfile security rules.
func JenkinsRules() []*Rule {
	jenkinsFiles := []FileType{JenkinsfileT}

	return []*Rule{
		// === Credentials & Secrets (J01-J05) ===
		{
			ID: "J01", Category: JEN, Severity: Critical, Points: 4,
			Description: "Shell command with Groovy string interpolation",
			Why:         "sh \"${var}\" exposes credentials to process listing and shell history — use single quotes",
			Pattern:     regexp.MustCompile(`sh\s+"[^"]*\$\{`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Change sh \"${var}\" to sh '${var}' with withCredentials block",
		},
		{
			ID: "J02", Category: JEN, Severity: Critical, Points: 4,
			Description: "No withCredentials block for secret usage",
			Why:         "Direct env variable access for secrets bypasses Jenkins credential masking",
			Pattern:     regexp.MustCompile(`(?i)withCredentials`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: PartialFix, FixDesc: "Wrap secret usage in withCredentials([...]) { } block",
		},
		{
			ID: "J03", Category: JEN, Severity: High, Points: 3,
			Description: "Hardcoded credentials in Jenkinsfile",
			Why:         "Credentials visible to anyone with source code access and stored in version control",
			Pattern:     regexp.MustCompile(`(?i)(password|secret|token|api_key)\s*=\s*['"][^'"]{4,}`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: NoFix, FixDesc: "Store in Jenkins Credentials and use withCredentials",
		},
		{
			ID: "J04", Category: JEN, Severity: High, Points: 3,
			Description: "Echo or println leaking secrets",
			Why:         "Printing secrets to console log exposes them to anyone with build log access",
			Pattern:     regexp.MustCompile(`(?i)(echo|println)\s*.*\$\{.*(SECRET|PASSWORD|TOKEN|KEY|CRED)`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Remove echo/println statements containing credential variables",
		},
		{
			ID: "J05", Category: JEN, Severity: Medium, Points: 3,
			Description: "writeFile with secret content",
			Why:         "Writing secrets to files on disk leaves them accessible after build completes",
			Pattern:     regexp.MustCompile(`(?i)writeFile.*(?:secret|password|token|key|cred)`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: NoFix, FixDesc: "Use Jenkins credentials binding instead of file-based secrets",
		},

		// === Sandbox & Code Execution (J06-J10) ===
		{
			ID: "J06", Category: JEN, Severity: Critical, Points: 4,
			Description: "Groovy sandbox bypass attempt",
			Why:         "@Grab, evaluate(), GroovyShell allow arbitrary code execution outside sandbox",
			Pattern:     regexp.MustCompile(`(?i)(@Grab|@GrabResolver|evaluate\s*\(|Eval\.me|GroovyShell|new\s+File\s*\()`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: NoFix, FixDesc: "Remove sandbox bypass constructs — use approved script methods",
		},
		{
			ID: "J07", Category: JEN, Severity: High, Points: 3,
			Description: "No timeout on pipeline or stages",
			Why:         "Hung pipeline consumes executor for hours — blocking other builds",
			Pattern:     regexp.MustCompile(`(?i)timeout\s*\(\s*time:`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add timeout(time: 30, unit: 'MINUTES') to pipeline options",
		},
		{
			ID: "J08", Category: JEN, Severity: Medium, Points: 3,
			Description: "No build discarder for log rotation",
			Why:         "Without log rotation, Jenkins disk fills up with thousands of old build logs",
			Pattern:     regexp.MustCompile(`(?i)buildDiscarder|logRotator`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add buildDiscarder(logRotator(numToKeepStr: '10')) to options",
		},
		{
			ID: "J09", Category: JEN, Severity: High, Points: 3,
			Description: "Pipeline replay not disabled",
			Why:         "Replay allows anyone to modify and re-run pipeline code — bypassing SCM controls",
			Pattern:     regexp.MustCompile(`(?i)disableReplay\(\)|disableConcurrentBuilds\(\)`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add disableReplay() to pipeline options block",
		},
		{
			ID: "J10", Category: JEN, Severity: High, Points: 3,
			Description: "Using agent any without restriction",
			Why:         "agent any runs on any available node — including production or sensitive nodes",
			Pattern:     regexp.MustCompile(`agent\s+any`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Replace agent any with agent { label 'build-node' }",
		},

		// === Shared Libraries & Dependencies (J11-J15) ===
		{
			ID: "J11", Category: JEN, Severity: Critical, Points: 4,
			Description: "Shared library loaded without version pinning",
			Why:         "Library@main means any push to main changes all pipelines instantly — supply chain risk",
			Pattern:     regexp.MustCompile(`@Library\s*\(\s*['"][^'"]*@(main|master|latest)['"]\s*\)`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Pin shared library to specific version tag: @Library('lib@v1.2.3')",
		},
		{
			ID: "J12", Category: JEN, Severity: Medium, Points: 3,
			Description: "No input validation for pipeline parameters",
			Why:         "Unvalidated user input in sh commands enables command injection",
			Pattern:     regexp.MustCompile(`(?i)sh\s+.*\$\{params\.\w+\}`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: PartialFix, FixDesc: "Validate and sanitize all params before use in shell commands",
		},
		{
			ID: "J13", Category: JEN, Severity: Medium, Points: 2,
			Description: "No post-build cleanup",
			Why:         "Without cleanWs() or deleteDir(), build artifacts accumulate and fill disk",
			Pattern:     regexp.MustCompile(`(?i)(cleanWs\(\)|deleteDir\(\))`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add cleanWs() in post { always { } } block",
		},
		{
			ID: "J14", Category: JEN, Severity: High, Points: 3,
			Description: "Running on master/built-in node",
			Why:         "Master node has access to all secrets and configs — builds must run on agent nodes",
			Pattern:     regexp.MustCompile(`(?i)node\s*\(\s*['"]?(master|built-in)['"]?\s*\)`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Use agent { label 'build-node' } instead of master node",
		},
		{
			ID: "J15", Category: JEN, Severity: Medium, Points: 3,
			Description: "No post-failure handling",
			Why:         "Without post { failure {} }, pipeline fails silently — no alerts, no cleanup",
			Pattern:     regexp.MustCompile(`(?i)post\s*\{[^}]*failure\s*\{`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add post { failure { notify } always { cleanup } }",
		},

		// === Security Controls (J16-J20) ===
		{
			ID: "J16", Category: JEN, Severity: Critical, Points: 4,
			Description: "bat command with string interpolation",
			Why:         "Same risk as sh with interpolation — credentials exposed in Windows batch commands",
			Pattern:     regexp.MustCompile(`bat\s+"[^"]*\$\{`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Use bat with single quotes and withCredentials block",
		},
		{
			ID: "J17", Category: JEN, Severity: High, Points: 3,
			Description: "Docker agent using latest tag",
			Why:         "agent { docker { image 'node:latest' } } — non-reproducible builds",
			Pattern:     regexp.MustCompile(`(?i)(image|docker)\s*['"]?\w+:latest`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Pin Docker agent image to specific version",
		},
		{
			ID: "J18", Category: JEN, Severity: Medium, Points: 3,
			Description: "No input submitter restriction",
			Why:         "input without submitter allows any user to approve production deploys",
			Pattern:     regexp.MustCompile(`(?i)input\s*\(`),
			Exclude:     regexp.MustCompile(`(?i)submitter`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add submitter: 'admin,deployers' to input step",
		},
		{
			ID: "J19", Category: JEN, Severity: Medium, Points: 2,
			Description: "Archiving sensitive artifacts",
			Why:         "archiveArtifacts on secret files exposes them to anyone with build access",
			Pattern:     regexp.MustCompile(`(?i)archiveArtifacts.*(?:\.key|\.pem|\.env|secret|password|credential)`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: NoFix, FixDesc: "Exclude sensitive files from archiveArtifacts pattern",
		},
		{
			ID: "J20", Category: JEN, Severity: High, Points: 3,
			Description: "Building fork PRs without restriction",
			Why:         "Fork PRs run attacker-controlled code on your Jenkins — secrets extraction trivial",
			Pattern:     regexp.MustCompile(`(?i)(buildForkPRs|trustForks|forkPullRequest)`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: NoFix, FixDesc: "Disable fork PR builds or use sandbox with no credentials",
		},

		// === Best Practices (J21-J25) ===
		{
			ID: "J21", Category: JEN, Severity: Medium, Points: 3,
			Description: "No retry on deployment stages",
			Why:         "Transient network errors fail deploy permanently — retry recovers automatically",
			Pattern:     regexp.MustCompile(`(?i)retry\s*\(`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add retry(2) on deployment and external service stages",
		},
		{
			ID: "J22", Category: JEN, Severity: Medium, Points: 2,
			Description: "No resource locking for deployments",
			Why:         "Concurrent deploys to same environment cause race conditions and partial updates",
			Pattern:     regexp.MustCompile(`(?i)lock\s*\(\s*resource:`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add lock(resource: 'deploy-prod') around deployment stage",
		},
		{
			ID: "J23", Category: JEN, Severity: Low, Points: 2,
			Description: "No durability hint for pipeline performance",
			Why:         "Default durability writes every step to disk — PERFORMANCE_OPTIMIZED is faster",
			Pattern:     regexp.MustCompile(`(?i)durabilityHint`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add durabilityHint('PERFORMANCE_OPTIMIZED') to options",
		},
		{
			ID: "J24", Category: JEN, Severity: Medium, Points: 2,
			Description: "No parallel execution for independent stages",
			Why:         "Sequential stages that could run in parallel waste CI time and resources",
			Pattern:     regexp.MustCompile(`(?i)parallel\s*\{`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: PartialFix, FixDesc: "Run independent stages in parallel {} block",
		},
		{
			ID: "J25", Category: JEN, Severity: Medium, Points: 3,
			Description: "No error handling with catchError or try-catch",
			Why:         "Uncaught errors abort entire pipeline — catchError allows graceful handling",
			Pattern:     regexp.MustCompile(`(?i)(catchError|try\s*\{|catch\s*\()`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: PartialFix, FixDesc: "Use catchError or try-catch for non-critical stages",
		},

		// === Advanced Security (J26-J30) ===
		{
			ID: "J26", Category: JEN, Severity: High, Points: 4,
			Description: "Using script block in declarative pipeline",
			Why:         "script {} blocks bypass declarative safety — prefer declarative steps",
			Pattern:     regexp.MustCompile(`(?i)script\s*\{`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: PartialFix, FixDesc: "Minimize script blocks — use declarative pipeline steps where possible",
		},
		{
			ID: "J27", Category: JEN, Severity: Medium, Points: 3,
			Description: "No notification on pipeline status change",
			Why:         "Silent pipeline failures mean broken builds go unnoticed for hours",
			Pattern:     regexp.MustCompile(`(?i)(slackSend|emailext|mail\s*\(|notify|hipchat)`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: FullFix, FixDesc: "Add slackSend or emailext in post { failure { } } block",
		},
		{
			ID: "J28", Category: JEN, Severity: High, Points: 3,
			Description: "Unstash or stash containing secrets",
			Why:         "Stashed files persist between stages — secrets in stash accessible across builds",
			Pattern:     regexp.MustCompile(`(?i)(stash|unstash).*(?:secret|password|token|key|cred|\.env)`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: NoFix, FixDesc: "Never stash sensitive files — use withCredentials per stage",
		},
		{
			ID: "J29", Category: JEN, Severity: Medium, Points: 2,
			Description: "No when condition for stage execution",
			Why:         "Stages run unconditionally even when not needed — wasting resources",
			Pattern:     regexp.MustCompile(`(?i)when\s*\{`),
			Negative:    true, Scope: FileScope, FileTypes: jenkinsFiles,
			FixType: PartialFix, FixDesc: "Add when { branch 'main' } conditions for deployment stages",
		},
		{
			ID: "J30", Category: JEN, Severity: Medium, Points: 3,
			Description: "No JNLP agent security restriction",
			Why:         "Unrestricted agent connections allow rogue nodes to join Jenkins cluster",
			Pattern:     regexp.MustCompile(`(?i)(jnlp|inbound-agent|remoting)`),
			Negative:    false, Scope: LineScope, FileTypes: jenkinsFiles,
			FixType: NoFix, FixDesc: "Restrict agent connections with security realm and TCP port settings",
		},
	}
}
