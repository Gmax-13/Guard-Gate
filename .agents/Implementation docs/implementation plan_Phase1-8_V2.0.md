# GuardGate — Implementation Plan (v2)

A CI/CD security suite that scans repos for leaked secrets, vulnerable dependencies, and broken authentication/authorization flows — one plugin, one unified report, run automatically on every push/PR.

---

## Resolved Decisions

| Question | Decision |
|----------|----------|
| Tech Stack | Node.js + TypeScript, Playwright, Next.js, Neon Postgres, Vercel |
| Monorepo | pnpm workspaces (`packages/cli`, `packages/github-action`, `apps/dashboard`) |
| CLI Name | `guardgate` |
| Dashboard Auth | Basic auth/login (email + password, JWT sessions) — extensible for OAuth/SSO later |
| SBOM Ecosystems | npm + pip (compulsory) + Go modules, Maven/Gradle, Cargo (best-effort MVP) |
| Database | Neon Postgres (free tier) |
| E2E Scope | Works on any codebase/target URL — sample vulnerable app is demo-only |

---

## Phase 1 — Project Scaffolding & Unified CLI Skeleton

- Root config files: package.json, pnpm-workspace.yaml, tsconfig.base.json, .gitignore, .prettierrc, eslint.config.mjs
- packages/cli/ — CLI package with commander.js, config loader (zod), unified JSON report schema, Scanner interface

## Phase 2 — Secrets Scanner Module

- packages/cli/src/scanners/secrets/ — regex + entropy-based scanner, git history scanning, allowlist

## Phase 3 — SBOM / Dependency Vulnerability Scanner

- packages/cli/src/scanners/sbom/ — 5 ecosystem parsers (npm, pip, go, maven, cargo), CycloneDX SBOM generation, OSV.dev API client

## Phase 4 — E2E Security Testing (Layer 1: Flow Runner)

- packages/cli/src/scanners/e2e/ — generic Playwright flow runner, YAML/JSON DSL, plugin interface

## Phase 5 — Security Assertion Plugins (Layer 2)

- packages/cli/src/scanners/e2e/plugins/ — authBypass, IDOR, sessionCookieFlags, logoutInvalidation, loginRateLimit

## Phase 6 — GitHub Action Wrapper

- packages/github-action/ — composite action, PR comment posting, dashboard upload

## Phase 7 — Web Dashboard (with Auth)

- apps/dashboard/ — Next.js, Drizzle ORM, Neon Postgres, JWT auth, API routes, trend charts

## Phase 8 — Sample Vulnerable App & Demo Fixtures

- examples/vulnerable-app/ — deliberately insecure Express app
- examples/flows/ — sample YAML flow definitions
- examples/guardgate.config.yml — sample config
