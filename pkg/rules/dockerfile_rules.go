package rules

import "regexp"

// DockerfileRules returns all D01-D40 Dockerfile security and best practice rules.
func DockerfileRules() []*Rule {
	dockerFiles := []FileType{DockerfileT}

	return []*Rule{
		// === Base Image Security (D01-D05) ===
		{
			ID: "D01", Category: DOC, Severity: Critical, Points: 3,
			Description: "Using FROM with :latest tag",
			Why:         "Builds become non-reproducible — working pipeline today may break tomorrow when base image updates",
			Pattern:     regexp.MustCompile(`(?i)^FROM\s+\S+:latest\b`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Pin to specific version: FROM ubuntu:22.04",
		},
		{
			ID: "D02", Category: DOC, Severity: High, Points: 3,
			Description: "FROM without any tag or digest",
			Why:         "No tag defaults to :latest implicitly — same non-reproducibility risk as D01",
			Pattern:     regexp.MustCompile(`^FROM\s+([a-zA-Z0-9._/-]+)\s*$`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add explicit version tag: FROM node:20-alpine",
		},
		{
			ID: "D03", Category: DOC, Severity: High, Points: 3,
			Description: "No non-root USER instruction",
			Why:         "Container runs as root by default — if attacker escapes app, they own the container",
			Pattern:     regexp.MustCompile(`(?i)^USER\s+\S+`),
			Exclude:     regexp.MustCompile(`(?i)^USER\s+root\b`),
			Negative:    true, Scope: FileScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add USER 1001 before CMD instruction",
		},
		{
			ID: "D04", Category: DOC, Severity: Medium, Points: 2,
			Description: "Using ADD instead of COPY",
			Why:         "ADD auto-extracts archives and supports URLs — hidden behavior. COPY is explicit and safer",
			Pattern:     regexp.MustCompile(`^ADD\s+\S+`),
			Exclude:     regexp.MustCompile(`^ADD\s+https?://`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Replace ADD with COPY unless archive extraction is needed",
		},
		{
			ID: "D05", Category: DOC, Severity: High, Points: 3,
			Description: "Using large base image instead of slim/alpine/distroless",
			Why:         "ubuntu/debian images contain 100+ packages you do not need — larger attack surface",
			Pattern:     regexp.MustCompile(`(?i)^FROM\s+(ubuntu|debian|centos|fedora|amazonlinux)\b`),
			Exclude:     regexp.MustCompile(`(?i)(slim|minimal|distroless)`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "Use alpine, slim, or distroless variant: FROM node:20-alpine",
		},

		// === Secrets & Sensitive Data (D06-D10) ===
		{
			ID: "D06", Category: DOC, Severity: Critical, Points: 5,
			Description: "Secret in ENV or ARG instruction",
			Why:         "ENV/ARG values are stored in image layers — anyone with docker history sees them",
			Pattern:     regexp.MustCompile(`(?i)^(ENV|ARG)\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)\s*=`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: NoFix, FixDesc: "Use --secret mount or runtime environment variables instead",
		},
		{
			ID: "D07", Category: DOC, Severity: High, Points: 3,
			Description: "COPY of sensitive files into image",
			Why:         "SSH keys, .env files, and certificates baked into image are extractable by anyone",
			Pattern:     regexp.MustCompile(`(?i)COPY\s+.*(\.(env|key|pem)|id_rsa|\.ssh|credentials|\.npmrc|\.pypirc)`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: NoFix, FixDesc: "Use Docker secrets or mount at runtime — never COPY credentials",
		},
		{
			ID: "D08", Category: DOC, Severity: Medium, Points: 2,
			Description: "Git clone with embedded credentials",
			Why:         "git clone https://user:token@github.com stores credentials in image layer",
			Pattern:     regexp.MustCompile(`(?i)git\s+clone\s+https?://[^@]+@`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: NoFix, FixDesc: "Use SSH agent forwarding or build-time --secret mount",
		},
		{
			ID: "D09", Category: DOC, Severity: Medium, Points: 2,
			Description: "ssh-keygen or SSH key generation in Dockerfile",
			Why:         "Generated SSH keys are baked into image — every container instance has same key",
			Pattern:     regexp.MustCompile(`(?i)ssh-keygen`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: NoFix, FixDesc: "Generate SSH keys at runtime or mount from secret manager",
		},
		{
			ID: "D10", Category: DOC, Severity: High, Points: 3,
			Description: "Curl piped to shell (pipe install pattern)",
			Why:         "curl | bash executes remote code without verification — supply chain attack vector",
			Pattern:     regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(ba)?sh`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "Download, verify checksum, then execute separately",
		},

		// === Build Instructions (D11-D15) ===
		{
			ID: "D11", Category: DOC, Severity: Medium, Points: 2,
			Description: "CMD in shell form instead of exec form",
			Why:         "Shell form runs via /bin/sh -c — PID 1 is shell, not your app. Signals not forwarded",
			Pattern:     regexp.MustCompile(`^CMD\s+\S`),
			Exclude:     regexp.MustCompile(`^CMD\s+\[`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Use exec form: CMD [\"npm\", \"start\"]",
		},
		{
			ID: "D12", Category: DOC, Severity: Medium, Points: 2,
			Description: "ENTRYPOINT in shell form",
			Why:         "Same signal-forwarding issue as CMD shell form — container cannot gracefully stop",
			Pattern:     regexp.MustCompile(`^ENTRYPOINT\s+\S`),
			Exclude:     regexp.MustCompile(`^ENTRYPOINT\s+\[`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Use exec form: ENTRYPOINT [\"./app\"]",
		},
		{
			ID: "D13", Category: DOC, Severity: Medium, Points: 2,
			Description: "No HEALTHCHECK instruction",
			Why:         "Without HEALTHCHECK, Docker/K8s cannot detect if your app is actually responding",
			Pattern:     regexp.MustCompile(`(?i)^HEALTHCHECK\s`),
			Negative:    true, Scope: FileScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1",
		},
		{
			ID: "D14", Category: DOC, Severity: Low, Points: 1,
			Description: "No WORKDIR instruction",
			Why:         "Without WORKDIR, files are added to / root — messy and potential permission issues",
			Pattern:     regexp.MustCompile(`(?i)^WORKDIR\s`),
			Negative:    true, Scope: FileScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add WORKDIR /app before COPY and RUN instructions",
		},
		{
			ID: "D15", Category: DOC, Severity: Low, Points: 1,
			Description: "No EXPOSE instruction",
			Why:         "EXPOSE documents which ports the container listens on — missing = poor documentation",
			Pattern:     regexp.MustCompile(`(?i)^EXPOSE\s`),
			Negative:    true, Scope: FileScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add EXPOSE 8080 to document container port",
		},

		// === Package Management (D16-D20) ===
		{
			ID: "D16", Category: DOC, Severity: High, Points: 3,
			Description: "apt-get install without --no-install-recommends",
			Why:         "Recommended packages add 50-200MB of unnecessary packages — bigger attack surface",
			Pattern:     regexp.MustCompile(`apt-get\s+install`),
			Exclude:     regexp.MustCompile(`--no-install-recommends`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add --no-install-recommends to apt-get install",
		},
		{
			ID: "D17", Category: DOC, Severity: Medium, Points: 2,
			Description: "apt-get upgrade or dist-upgrade in Dockerfile",
			Why:         "Upgrading all packages makes builds non-reproducible and can break dependencies",
			Pattern:     regexp.MustCompile(`apt-get\s+(upgrade|dist-upgrade)`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Remove apt-get upgrade — pin specific package versions instead",
		},
		{
			ID: "D18", Category: DOC, Severity: Medium, Points: 2,
			Description: "apk add without --no-cache",
			Why:         "Without --no-cache, apk index is stored in image layer — unnecessary size",
			Pattern:     regexp.MustCompile(`apk\s+add`),
			Exclude:     regexp.MustCompile(`--no-cache`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add --no-cache to apk add: RUN apk add --no-cache curl",
		},
		{
			ID: "D19", Category: DOC, Severity: Medium, Points: 2,
			Description: "pip install without --no-cache-dir",
			Why:         "pip cache stored in image layer — wastes 50-100MB per Python image",
			Pattern:     regexp.MustCompile(`pip\s+install`),
			Exclude:     regexp.MustCompile(`--no-cache-dir`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add --no-cache-dir to pip install",
		},
		{
			ID: "D20", Category: DOC, Severity: Medium, Points: 2,
			Description: "pip install without version pinning",
			Why:         "pip install flask gets different versions over time — non-reproducible builds",
			Pattern:     regexp.MustCompile(`pip\s+install\s+[a-zA-Z][a-zA-Z0-9-]+(\s|$)`),
			Exclude:     regexp.MustCompile(`(==|-r\s|requirements)`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "Pin versions: pip install flask==3.0.0 or use requirements.txt",
		},

		// === Multi-Stage & Layer Optimization (D21-D25) ===
		{
			ID: "D21", Category: DOC, Severity: High, Points: 3,
			Description: "No multi-stage build",
			Why:         "Single-stage images include build tools (gcc, npm) in production — huge and insecure",
			Pattern:     regexp.MustCompile(`(?i)FROM\s+\S+\s+AS\s+`),
			Negative:    true, Scope: FileScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "Use multi-stage: FROM node AS build ... FROM alpine as final",
		},
		{
			ID: "D22", Category: DOC, Severity: Medium, Points: 2,
			Description: "COPY . . without .dockerignore",
			Why:         "Copies .git, node_modules, .env, secrets — everything into image",
			Pattern:     regexp.MustCompile(`COPY\s+\.\s+\.`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "Create .dockerignore with: .git, node_modules, .env, *.md",
		},
		{
			ID: "D23", Category: DOC, Severity: Medium, Points: 2,
			Description: "Multiple consecutive RUN instructions",
			Why:         "Each RUN creates a new layer — combining reduces image size and build time",
			Pattern:     regexp.MustCompile(`(?m)^RUN\s+.*\n^RUN\s+`),
			Negative:    false, Scope: FileScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "Combine RUN commands with && on single layer",
		},
		{
			ID: "D24", Category: DOC, Severity: Medium, Points: 2,
			Description: "Package install without cleanup in same layer",
			Why:         "apt-get install + rm in separate RUN means cache is in first layer — still in image",
			Pattern:     regexp.MustCompile(`apt-get\s+install`),
			Exclude:     regexp.MustCompile(`rm\s+-rf.*/var/lib/apt`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add && rm -rf /var/lib/apt/lists/* in same RUN layer",
		},
		{
			ID: "D25", Category: DOC, Severity: Medium, Points: 2,
			Description: "COPY before package.json (bad cache order)",
			Why:         "COPY . . before COPY package*.json means any source change re-installs all deps",
			Pattern:     regexp.MustCompile(`(?is)COPY\s+\.\s+.*COPY\s+package`),
			Negative:    false, Scope: FileScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "COPY package*.json first, RUN install, then COPY . .",
		},

		// === Security Hardening (D26-D30) ===
		{
			ID: "D26", Category: DOC, Severity: High, Points: 3,
			Description: "SETUID/SETGID binaries not removed",
			Why:         "SETUID binaries allow privilege escalation inside container",
			Pattern:     regexp.MustCompile(`(?i)(chmod\s+[ugo]*\+s|SETUID|setuid)`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "Remove SETUID bits: RUN find / -perm /6000 -exec chmod a-s {} +",
		},
		{
			ID: "D27", Category: DOC, Severity: Critical, Points: 3,
			Description: "chmod 777 — world-writable permissions",
			Why:         "World-writable files allow any process to modify them — privilege escalation path",
			Pattern:     regexp.MustCompile(`chmod\s+777`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Use specific permissions: chmod 755 for dirs, chmod 644 for files",
		},
		{
			ID: "D28", Category: DOC, Severity: High, Points: 3,
			Description: "Using sudo in Dockerfile",
			Why:         "If you need sudo, you are running as wrong user — fix the USER instruction instead",
			Pattern:     regexp.MustCompile(`(?i)\bsudo\b`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Remove sudo — run commands as root before USER, then switch to non-root",
		},
		{
			ID: "D29", Category: DOC, Severity: Medium, Points: 2,
			Description: "No checksum verification for downloaded files",
			Why:         "Downloaded binaries without checksum verification can be tampered with",
			Pattern:     regexp.MustCompile(`(?i)(curl|wget)\s+.*https?://`),
			Exclude:     regexp.MustCompile(`(?i)(sha256sum|md5sum|gpg|checksum)`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "Verify downloads: curl -o file URL && sha256sum -c checksum.txt",
		},
		{
			ID: "D30", Category: DOC, Severity: Medium, Points: 2,
			Description: "No init process (PID 1 signal handling)",
			Why:         "Without tini/dumb-init, zombie processes accumulate and signals are not forwarded",
			Pattern:     regexp.MustCompile(`(?i)(tini|dumb-init|--init)`),
			Negative:    true, Scope: FileScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Install tini: ENTRYPOINT [\"tini\", \"--\"] CMD [\"./app\"]",
		},

		// === Best Practices (D31-D35) ===
		{
			ID: "D31", Category: DOC, Severity: Low, Points: 1,
			Description: "No LABEL instruction for metadata",
			Why:         "Labels document image maintainer, version, description — essential for registry management",
			Pattern:     regexp.MustCompile(`(?i)^LABEL\s`),
			Negative:    true, Scope: FileScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add LABEL maintainer=\"you\" version=\"1.0\" description=\"...\"",
		},
		{
			ID: "D32", Category: DOC, Severity: Medium, Points: 2,
			Description: "Multiple CMD instructions",
			Why:         "Only the last CMD takes effect — multiple CMD is a misconfiguration",
			Pattern:     regexp.MustCompile(`(?i)^CMD\s`),
			Negative:    false, Scope: FileScope, FileTypes: dockerFiles,
			FixType:     FullFix, FixDesc: "Keep only one CMD instruction at the end of Dockerfile",
		},
		{
			ID: "D33", Category: DOC, Severity: Medium, Points: 2,
			Description: "Multiple ENTRYPOINT instructions",
			Why:         "Only the last ENTRYPOINT takes effect — multiple is a misconfiguration",
			Pattern:     regexp.MustCompile(`(?i)^ENTRYPOINT\s`),
			Negative:    false, Scope: FileScope, FileTypes: dockerFiles,
			FixType:     FullFix, FixDesc: "Keep only one ENTRYPOINT instruction",
		},
		{
			ID: "D34", Category: DOC, Severity: Low, Points: 1,
			Description: "No .dockerignore file referenced",
			Why:         "Without .dockerignore, build context includes .git, node_modules, test fixtures",
			Pattern:     regexp.MustCompile(`(?i)(\.dockerignore|dockerignore)`),
			Negative:    true, Scope: FileScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Create .dockerignore with .git, node_modules, .env, *.md",
		},
		{
			ID: "D35", Category: DOC, Severity: Low, Points: 1,
			Description: "No Hadolint or Dockerfile linting configured",
			Why:         "Hadolint catches Dockerfile issues before build — like ESLint for Dockerfiles",
			Pattern:     regexp.MustCompile(`(?i)(hadolint|\.hadolint|dockerfile-lint|dockerfilelint)`),
			Negative:    true, Scope: FileScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add .hadolint.yaml and run hadolint Dockerfile in CI",
		},

		// === Advanced (D36-D40) ===
		{
			ID: "D36", Category: DOC, Severity: Medium, Points: 2,
			Description: "Using VOLUME for application data",
			Why:         "VOLUME in Dockerfile creates anonymous volumes — hard to manage and backup",
			Pattern:     regexp.MustCompile(`(?i)^VOLUME\s`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: PartialFix, FixDesc: "Remove VOLUME from Dockerfile — define volumes in docker-compose or K8s",
		},
		{
			ID: "D37", Category: DOC, Severity: High, Points: 3,
			Description: "Running as root at end of Dockerfile",
			Why:         "USER root followed by CMD means container runs as root in production",
			Pattern:     regexp.MustCompile(`(?i)^USER\s+root\b`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Add USER 1001 after root operations, before CMD",
		},
		{
			ID: "D38", Category: DOC, Severity: Medium, Points: 2,
			Description: "SHELL override without justification",
			Why:         "Overriding default shell can break build tooling and introduce unexpected behavior",
			Pattern:     regexp.MustCompile(`(?i)^SHELL\s`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: NoFix, FixDesc: "Only override SHELL if you need PowerShell on Windows or specific shell features",
		},
		{
			ID: "D39", Category: DOC, Severity: Medium, Points: 2,
			Description: "ADD with URL source",
			Why:         "ADD from URL does not verify download integrity — use curl + checksum instead",
			Pattern:     regexp.MustCompile(`(?i)^ADD\s+https?://`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: FullFix, FixDesc: "Replace ADD URL with: RUN curl -o file URL && sha256sum -c ...",
		},
		{
			ID: "D40", Category: DOC, Severity: High, Points: 3,
			Description: "Using --privileged or dangerous capabilities",
			Why:         "Privileged containers have full host access — container escape is trivial",
			Pattern:     regexp.MustCompile(`(?i)(--privileged|cap_add.*ALL|SYS_ADMIN|seccomp.*unconfined)`),
			Negative:    false, Scope: LineScope, FileTypes: dockerFiles,
			FixType: NoFix, FixDesc: "Drop all capabilities and add only what is needed",
		},
	}
}

// countPattern is a helper for rules that check occurrence count (like D32, D33).
// The engine handles these via special FileScope logic.
func init() {
	// D32 and D33 need special handling — they trigger when count > 1
	// The default FileScope positive match handles this since it matches on first occurrence
	// For proper count-based detection, the engine would need enhancement
	// Current implementation: flags if CMD/ENTRYPOINT exists (partial coverage)
}
