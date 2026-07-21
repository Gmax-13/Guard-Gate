# context.md

## Project Name
GuardGate

## One-Line Pitch
A CI/CD security suite that scans repos for leaked secrets, vulnerable dependencies, and broken authentication/authorization flows — one plugin, one unified report, run automatically on every push/PR.

## Problem Statement
Modern dev teams ship fast and use CI/CD pipelines, but security checks are usually bolted on late, spread across multiple disconnected tools (a secrets scanner here, a dependency checker there, manual pentesting for auth flows), or skipped entirely by small teams who can't afford enterprise tools like Snyk or GitGuardian. This tool consolidates three of the most common and high-impact supply-chain/appsec risks into a single lightweight CI step.

## Target User
- Primary: small-to-mid size dev/DevOps teams (5-50 engineers) without a dedicated security team
- Secondary: solo developers and student/open-source projects who want basic security hygiene for free
- Buyer persona (if productized later): engineering lead or DevOps engineer who owns the CI/CD pipeline

## Core Value Proposition
"One CI/CD step, three supply-chain risks covered: leaked secrets, vulnerable dependencies, and broken auth flows — before they reach production."

## Scope for MVP (final-year project, placement-season timeline)
In scope:
1. Secrets scanner — detects hardcoded credentials/keys in repo history and new commits
2. SBOM + dependency vulnerability tracker — generates SBOM, cross-references CVEs, flags risky packages
3. Security-focused E2E testing — Playwright-driven flows that check for broken auth/access control (NOT general functional E2E testing yet)
4. Unified CLI tool that runs all three scanners
5. GitHub Action wrapper that runs the CLI on push/PR and posts results as a PR check/comment
6. Simple web dashboard showing scan history and pass/fail trends

Out of scope for MVP (explicitly deferred, but architecture must not block these later):
- General-purpose functional E2E testing (non-security assertions)
- GitLab CI / Bitbucket / Jenkins plugins (GitHub Actions only for MVP)
- Team management, billing, multi-tenant auth on the dashboard
- Auto-remediation / auto-fix PRs
- ML-based anomaly detection

## Design Principle — Extensibility for Future E2E Testing
The E2E component MUST be built as two decoupled layers:
- **Flow Runner (Layer 1):** generic Playwright automation — navigate, fill, click, assert page state. Security-agnostic. Defined via a simple YAML/JSON flow DSL.
- **Assertion Plugins (Layer 2):** pluggable check modules that hook into flow steps. MVP ships security assertion plugins only (auth bypass, IDOR, session/cookie flags, logout invalidation, login rate-limiting). Future functional assertion plugins (e.g., "text present", "API response matches") must be able to plug into the same interface without changing Layer 1.

This separation is a hard requirement, not a nice-to-have — do not couple flow execution logic to security-specific assertions.

## Tech Constraints
- Must be buildable and runnable entirely on free tiers (GitHub Actions free minutes, free-tier hosting for dashboard, free-tier DB)
- Cross-platform CLI (Linux/Mac/Windows), but primary runtime target is Linux (GitHub Actions runners)
- No paid APIs required for MVP — use OSV.dev / GitHub Advisory Database / NVD API (free tier) for CVE data

## Suggested Tech Stack (agent may confirm/adjust, not fixed in stone)
- CLI + core engine: Node.js + TypeScript (good ecosystem overlap with Playwright and GitHub Actions tooling)
- E2E flow runner: Playwright
- SBOM generation: integrate with or mirror Syft/CycloneDX output format
- Vulnerability data: OSV.dev API (free, no key needed) as primary source
- Secrets detection: regex + entropy-based scanner (reference Gitleaks' public rule patterns for detection logic, implement independently)
- Dashboard backend: Node.js/Express or Next.js API routes
- Dashboard frontend: Next.js + a simple component library
- Database: Postgres via Supabase or Neon (free tier)
- Hosting: Vercel or Render (free tier)
- CI integration: GitHub Actions (composite action or Docker-based action)

## Success Criteria for MVP Demo
- Running `<cli> scan` on a sample vulnerable repo detects: at least 1 planted secret, at least 1 known-CVE dependency, at least 1 broken-auth scenario in a sample web app
- GitHub Action runs automatically on a PR to a demo repo and posts a single unified pass/fail comment
- Dashboard shows scan history for at least 2 runs with pass/fail trend
- Full run completes in under ~5 minutes on GitHub Actions free-tier runner

## Non-Goals / Explicit Warnings for the Agent
- Do not build this as a desktop (Electron/Windows) app — it must run headless in CI and as a CLI
- Do not hardcode assumptions that block adding GitLab CI/Jenkins support later — keep the CI wrapper as a thin adapter over the core CLI
- Do not couple the E2E flow DSL to security-only concepts (see Design Principle above)
- Keep all three scanners (secrets, SBOM, E2E-security) as independently runnable CLI subcommands, not a monolith — this matters both for architecture cleanliness and for the "modular" pitch in interviews