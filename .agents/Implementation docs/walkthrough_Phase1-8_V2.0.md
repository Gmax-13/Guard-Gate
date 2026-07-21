# GuardGate MVP Walkthrough (Phases 1-8)

All development objectives under **Phases 1 to 8** have been successfully built, optimized, and compile with production builds.

## Changes Made

### 1. Root & CLI Scaffolding (Phase 1)
* Created a `pnpm` monorepo configuration containing `@guardgate/cli`, `@guardgate/dashboard`, `@guardgate/github-action`, and sample assets.
* Built the unified CLI framework with `commander` for loading configurations (`guardgate.config.yml`), executing scanners, and outputting JSON reports.

### 2. Secrets Scanner (Phase 2)
* Built a comprehensive current-directory and git-history scanning parser.
* Integrated 22 custom rules (AWS keys, Stripe, database links, private keys) combining Regex checking and Shannon entropy calculations.

### 3. SBOM Scanner (Phase 3)
* Added ecosystem support for:
  * **npm (Node.js)**: package-lock.json / package.json
  * **pip (Python)**: requirements.txt / Pipfile.lock
  * **Go Modules**: go.sum / go.mod
  * **Maven/Gradle (Java)**: pom.xml / gradle.lockfile
  * **Cargo (Rust)**: Cargo.lock / Cargo.toml
* Integrated a zero-config batch OSV.dev client to lookup CVEs and return formatted dependency trees.
* Generates CycloneDX 1.5 JSON SBOMs dynamically.

### 4. E2E Flow Runner & Plugins (Phases 4-5)
* Created a generic Playwright runner parsing a 16-step DSL (fill, click, clearCookies, goTo, assertText).
* Designed 5 plugins using hooks to monitor:
  * **authBypassCheck**: Request routes post-cookie-clearing.
  * **idorCheck**: Replay page requests incrementing / modifying path and query parameter IDs.
  * **sessionCookieFlagsCheck**: Verifying HttpOnly, Secure, and SameSite properties.
  * **logoutInvalidationCheck**: Re-sending old token post-logout.
  * **loginRateLimitCheck**: Fuzzing endpoints with rapid POST failures checking for lockout/429.

### 5. GitHub Action (Phase 6)
* Created a composite GitHub Action `packages/github-action/action.yml` parsing scan summaries, posting rich status summaries to Pull Request comments, and uploading artifacts.

### 6. Web Dashboard (Phase 7)
* Built a Next.js App Router portal with Neon serverless Postgres Drizzle ORM client.
* Supports **Light theme by default** with an interactive **Dark theme toggle** storing preferences.
* Integrates JWT session middleware, user signup/login, paginated runs list, scan details breakdowns, and trends graphs powered by Recharts.
* Exposes API endpoint routes for auth, workspace key generation, and CI ingestion.

### 7. Demo Playground (Phase 8)
* Provided a sample Express application (`examples/vulnerable-app`) containing deliberate gaps (missing logout invalidation, non-httponly cookies, no rate limiters) and a pre-configured yaml scan setup.

---

## Validation & Verification

### Compilation Verification
Both packages compile successfully with production parameters:
```bash
# Verify CLI Compilation
pnpm --filter @guardgate/cli build
# Verify Dashboard Compilation
pnpm --filter @guardgate/dashboard build
```

### Local Testing Guide
1. Launch the vulnerable demo application:
   ```bash
   cd examples/vulnerable-app
   pnpm install
   pnpm start
   ```
2. In another terminal, execute the scanner using our demo config:
   ```bash
   pnpm --filter @guardgate/cli scan --config examples/guardgate.config.yml
   ```
