# feature_list.md

## Module 1 — Secrets Scanner

### Must-have (MVP)
- [ ] Scan working directory files for common secret patterns (AWS keys, API tokens, private keys, generic high-entropy strings)
- [ ] Scan git commit history (not just current files) for secrets that were committed and later removed
- [ ] Configurable ignore-list / allowlist (e.g., test fixtures, `.env.example`)
- [ ] Output: list of findings with file path, line number, matched rule name, git commit hash (if from history), severity
- [ ] Exit code non-zero on any finding (for CI gating)

### Nice-to-have (post-MVP)
- [ ] Entropy-based detection tuning to reduce false positives
- [ ] Custom rule definitions via config file
- [ ] Auto-redaction in reports (never print the full secret value, only a masked preview)

---

## Module 2 — SBOM / Dependency Vulnerability Tracker

### Must-have (MVP)
- [ ] Detect project type/package manager (npm, pip, etc. — pick 1-2 for MVP, e.g. npm + pip)
- [ ] Generate SBOM in CycloneDX or SPDX format from the project's dependency manifest
- [ ] Cross-reference each dependency + version against OSV.dev (or GitHub Advisory DB) for known CVEs
- [ ] Flag transitive (not just direct) dependency vulnerabilities
- [ ] Output: list of vulnerable packages with CVE ID, severity (CVSS score/rating), affected version range, fixed version (if available)
- [ ] Exit code non-zero if any finding above a configurable severity threshold (e.g., High/Critical)

### Nice-to-have (post-MVP)
- [ ] Support additional ecosystems (Go, Java/Maven, Rust/Cargo)
- [ ] Suggested remediation (which version to bump to)
- [ ] License compliance flagging (e.g., GPL dependency in a commercial project)

---

## Module 3 — Security-Focused E2E Testing

### Layer 1 — Flow Runner (generic, security-agnostic)
- [ ] YAML/JSON DSL to define a flow: sequence of steps (`goto`, `fill`, `click`, `waitFor`, `assertText`, etc.)
- [ ] Playwright-based executor that runs a defined flow against a target URL
- [ ] Plugin interface: after/during each step, registered assertion plugins can run and report pass/fail + evidence (screenshot, request/response data)
- [ ] Flow runner has zero knowledge of "security" — it just executes steps and calls plugins

### Layer 2 — Security Assertion Plugins (MVP set)
- [ ] `authBypassCheck` — attempt to access a protected route without a valid session; flag if access is granted
- [ ] `idorCheck` — attempt to access another user's resource by modifying an ID/parameter; flag if access is granted
- [ ] `sessionCookieFlagsCheck` — verify session/auth cookies have `HttpOnly`, `Secure`, and appropriate `SameSite` attributes
- [ ] `logoutInvalidationCheck` — verify that a session token is invalidated after logout (old token can no longer be used)
- [ ] `loginRateLimitCheck` — verify repeated failed login attempts trigger rate-limiting/lockout
- [ ] Output: pass/fail per check with evidence (screenshot + request/response snippet), tagged `type: security`

### Nice-to-have (post-MVP — do not build now, but interface must support it)
- [ ] Functional assertion plugins (`textPresentCheck`, `apiResponseMatchCheck`, `visualRegressionCheck`) tagged `type: functional`
- [ ] Parallel flow execution
- [ ] Recording a flow via browser interaction instead of hand-writing the DSL

---

## Module 4 — Unified CLI

### Must-have (MVP)
- [ ] Single CLI entry point (e.g. `toolname scan`) with subcommands: `secrets`, `sbom`, `e2e`, and `all`
- [ ] Config file (e.g. `toolname.config.yml`) to set: severity thresholds, ignore lists, target URLs for E2E, flow DSL file paths
- [ ] Unified JSON output schema across all three modules (so dashboard/reporting can consume one format)
- [ ] Human-readable console output (colored pass/fail summary) in addition to JSON
- [ ] Single non-zero exit code if ANY module fails its threshold (for CI gating)

---

## Module 5 — CI/CD Integration

### Must-have (MVP)
- [ ] GitHub Action (composite or Docker-based) that installs and runs the CLI's `all` command on push/PR
- [ ] Posts a single unified summary as a PR comment or check status (pass/fail counts per module, links to full report)
- [ ] Uploads full JSON report as a workflow artifact
- [ ] Configurable via workflow YAML inputs (severity threshold, which modules to run)

### Nice-to-have (post-MVP)
- [ ] GitLab CI / Bitbucket Pipelines adapters
- [ ] Slack/Discord webhook notification on failure

---

## Module 6 — Web Dashboard

### Must-have (MVP)
- [ ] List view of past scan runs (repo, commit, timestamp, pass/fail summary)
- [ ] Detail view per run: findings broken down by module (secrets / SBOM / E2E-security), with evidence where applicable
- [ ] Basic trend view: pass/fail count over time for a repo
- [ ] Ingests the unified JSON report format from Module 4 (via API endpoint the CI Action posts to)

### Nice-to-have (post-MVP)
- [ ] Auth/login, multi-user/team support
- [ ] Filtering/search across findings
- [ ] Slack/email digest of weekly findings

---

## Build Order (recommended for agent)
1. Unified CLI skeleton + config loading + unified JSON output schema (build this first — everything else plugs into it)
2. Secrets scanner module
3. SBOM/dependency module
4. E2E flow runner (Layer 1) + 1-2 security assertion plugins to validate the plugin interface works
5. Remaining security assertion plugins
6. GitHub Action wrapper
7. Dashboard (backend API first, then frontend)

## Definition of Done for MVP
All "Must-have" items checked, demoable end-to-end on a sample vulnerable repo + sample vulnerable web app, running fully within GitHub Actions free tier, with dashboard showing at least 2 historical runs.