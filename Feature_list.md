# feature_list.md

## ✅ Completed Features (v1.0.0)

### Module 1 — Secrets Scanner
- [x] Scan working directory files for common secret patterns (AWS keys, API tokens, private keys, generic high-entropy strings)
- [x] Scan git commit history (not just current files) for secrets that were committed and later removed
- [x] Configurable ignore-list / allowlist (e.g., test fixtures, `.env.example`)
- [x] Output: list of findings with file path, line number, matched rule name, git commit hash (if from history), severity
- [x] Exit code non-zero on any finding (for CI gating)

### Module 2 — SBOM / Dependency Vulnerability Tracker
- [x] Detect project type/package manager (npm, pip, etc.)
- [x] Generate SBOM in CycloneDX or SPDX format from the project's dependency manifest
- [x] Cross-reference each dependency + version against OSV.dev for known CVEs
- [x] Flag transitive (not just direct) dependency vulnerabilities
- [x] Output: list of vulnerable packages with CVE ID, severity (CVSS score/rating), affected version range, fixed version (if available)
- [x] Exit code non-zero if any finding above a configurable severity threshold

### Module 3 — Security-Focused E2E Testing
- [x] YAML/JSON DSL to define a flow: sequence of steps (`goto`, `fill`, `click`, `waitFor`, `assertText`, etc.)
- [x] Playwright-based executor that runs a defined flow against a target URL
- [x] Plugin interface: assertion plugins can run and report pass/fail + evidence
- [x] Security Assertion Plugins: `authBypassCheck`, `idorCheck`, `sessionCookieFlagsCheck`, `logoutInvalidationCheck`, `loginRateLimitCheck`

### Module 4 — Unified CLI
- [x] Single CLI entry point with subcommands: `secrets`, `sbom`, `e2e`, `code`, `api`, and `scan` (all)
- [x] Config file (`guardgate.config.yml`) for severity thresholds, ignore lists, target URLs, flow DSL paths
- [x] Unified JSON output schema across all modules
- [x] Human-readable console output (colored pass/fail summary)
- [x] Single non-zero exit code if ANY module fails its threshold

### Module 5 — CI/CD Integration
- [x] GitHub Action workflow that runs the CLI on push/PR
- [x] Uploads full JSON report as a workflow artifact
- [x] Configurable via workflow YAML inputs (severity threshold, which modules to run)

### Module 6 — Code Scanner (Semantic AST Analysis)
- [x] TypeScript AST-based code scanning with pluggable JS rules
- [x] Built-in rules for common insecure patterns
- [x] Custom rule file support via config

### Module 7 — API Fuzzer (DAST)
- [x] YAML-based API flow definition
- [x] Endpoint fuzzing with request/response validation
- [x] Body matching (`matchBody`/`notMatchBody`) for accurate detection

### Module 8 — Web Dashboard
- [x] List view of past scan runs (repo, commit, timestamp, pass/fail summary)
- [x] Detail view per run: findings broken down by module
- [x] Basic trend view: pass/fail count over time
- [x] Ingests the unified JSON report via API endpoint

### Module 9 — AI Agent Integration
- [x] `guardgate agent` command outputs schemas for AI-generated workflows/rules

---

## 🔄 Pending Features (v1.1.0+)

### v1.1.0 — SARIF Output Format 🚧 *In Progress*
- [ ] Generate SARIF v2.1.0 formatted reports
- [ ] `--format sarif` and `--format all` CLI options
- [ ] GitHub Actions SARIF upload (findings appear in Security tab)
- [ ] GitLab code-scanning UI compatibility

### v1.2.0 — Diff-Aware / Baseline Scanning
- [ ] `guardgate scan --baseline <commit>` to only fail on new findings since a reference commit
- [ ] Suppression of pre-existing findings in legacy codebases
- [ ] Baseline fingerprinting for finding deduplication

### v1.3.0 — Real Python AST Support
- [ ] Tree-sitter-python or Python `ast` module integration for `.py` files
- [ ] Python-specific rules: `os.system`/`subprocess` with `shell=True`, `pickle.loads`, `yaml.load` without `SafeLoader`, f-string SQL construction
- [ ] Replace the TypeScript-parser-for-everything approach with per-language parsing

### v1.4.0 — Live Secret Verification
- [ ] Harmless verification calls for detected secrets (AWS `sts:GetCallerIdentity`, Stripe balance endpoint, GitHub `/user`)
- [ ] Confirmed active credential vs revoked/expired/test-only classification
- [ ] `--verify-secrets` CLI flag and config option

### v1.5.0 — OpenAPI/Swagger Import for API Fuzzer
- [ ] Parse OpenAPI 3.x / Swagger 2.0 specs
- [ ] Auto-generate fuzz flows for every documented endpoint/parameter
- [ ] `guardgate scan api --openapi <spec-path>` CLI option

### v1.6.0 — Auth-Aware API Fuzzing
- [ ] Bearer token / session cookie support for API fuzzer
- [ ] Auth header injection in fuzz flows
- [ ] Pre-flight login step for acquiring tokens

### v1.7.0 — AI-Generated Remediation Diffs
- [ ] For each finding, generate a suggested patch using LLM (Groq integration)
- [ ] "Here's the vulnerable line, here's a suggested fix" in reports
- [ ] Optional `--remediate` flag to generate fix PRs

---

## Build Order (v1.1.0+)
1. SARIF Output Format (v1.1.0) — highest-ROI for CI adoption
2. Diff-Aware / Baseline Scanning (v1.2.0) — enables adoption in legacy codebases
3. Real Python AST Support (v1.3.0) — fills the .py scanning gap
4. Live Secret Verification (v1.4.0) — upgrades from regex match to confirmed credential
5. OpenAPI Import (v1.5.0) — usability multiplier for DAST
6. Auth-Aware Fuzzing (v1.6.0) — reaches authenticated endpoints
7. AI Remediation Diffs (v1.7.0) — differentiated feature vs competitors