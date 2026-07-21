# GuardGate MVP Setup & Run Guide (Phases 1-8)

This guide provides step-by-step setup instructions and detailed execution guides for the GuardGate suite (CLI scanners, Web Dashboard, and GitHub Action).

---

## 1. Environment & Database Setup

Before running GuardGate, make sure you have the environment configured.

### Prerequisites
* **Node.js**: Version 18 or above.
* **pnpm**: Fast package manager (version 9 or above).
* **Playwright Browsers**: Required for the E2E flow runner.
  Install them globally by running:
  ```bash
  npx playwright install chromium --with-deps
  ```

### Database Setup (Neon Postgres)
1. Set up a free serverless Postgres instance on [Neon.tech](https://neon.tech/).
2. Create a `.env` file in the dashboard folder: `apps/dashboard/.env`.
3. Add the following environment variables:
   ```env
   DATABASE_URL="postgres://<user>:<password>@<neon-host>/neondb?sslmode=require"
   JWT_SECRET="generate-a-secure-random-key"
   ```
4. Push the schema migrations to your Neon database:
   ```bash
   pnpm --filter @guardgate/dashboard db:generate
   pnpm --filter @guardgate/dashboard db:migrate
   ```

---

## 2. Compiling the Monorepo

Compile all TypeScript resources across CLI and Dashboard packages:
```bash
# Clean install all dependencies
pnpm install

# Build all packages
pnpm build
```

---

## 3. Running the Web Dashboard

Start the Next.js dashboard server:
```bash
pnpm --filter @guardgate/dashboard dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.
* **Light Theme**: Selected by default.
* **Theme Toggle**: Located at the top right of the navigation bar to toggle between Light and Dark mode.
* **Account Setup**: Go to `/register` to create a workspace account, then `/login` to access the dashboard.
* **Get API Key**: Navigate to the **Settings** page, write a key name, click **Generate Key**, and copy the raw key starting with `gg_`.

---

## 4. Running CLI Scanners

You can run individual scanners or everything together.

### Run All Scanners (Secrets, SBOM, E2E)
```bash
node packages/cli/dist/index.js scan --config examples/guardgate.config.yml
```

### Run Secrets Scanner Only
Extracts credentials and keys from directories and git history.
```bash
node packages/cli/dist/index.js scan secrets
```
* Custom rules, entropy, and history depth can be adjusted in the config.

### Run SBOM / Dependency Scanner Only
Extracts dependency manifests and queries OSV.dev for CVE matches.
```bash
node packages/cli/dist/index.js scan sbom
```
* Generates a CycloneDX SBOM inside `.guardgate/guardgate-sbom.json`.

### Run E2E Security Scanner Only
Launches headlessly, executes defined step scripts, and runs security assertion plugins.
First, make sure the target application is running (see below), then run:
```bash
node packages/cli/dist/index.js scan e2e --config examples/guardgate.config.yml
```

---

## 5. Integrating CI/CD and Ingestion

To upload reports automatically from the CLI to your local Dashboard:
1. Copy your API Key from the dashboard's Settings tab.
2. Run the CLI with the `GUARDGATE_API_KEY` environment variable:
   ```bash
   # Windows PowerShell
   $env:GUARDGATE_API_KEY="gg_your_raw_api_key"
   node packages/cli/dist/index.js scan --config examples/guardgate.config.yml --upload http://localhost:3000
   
   # Linux/macOS Bash
   GUARDGATE_API_KEY="gg_your_raw_api_key" node packages/cli/dist/index.js scan --config examples/guardgate.config.yml --upload http://localhost:3000
   ```
3. Refresh the Dashboard Runs view to see findings populated instantly.

---

## 6. Demo Playground (Vulnerable App)

The monorepo includes a vulnerable Express app to demo GuardGate assertions.

### Starting the Demo
1. Run the app:
   ```bash
   cd examples/vulnerable-app
   pnpm start
   ```
   The app will run on [http://localhost:3001](http://localhost:3001).

2. Run the E2E scanner against it:
   ```bash
   node packages/cli/dist/index.js scan e2e --config examples/guardgate.config.yml
   ```
   The E2E scanner will run `login-flow.yml` steps, and plugins will catch the deliberate security issues:
   * Cookie Flags Check will fail: Cookie `session_token` lacks `HttpOnly` and `Secure`.
   * Auth Bypass will fail: `/admin` can be accessed without cookie headers.
   * Logout Invalidation will fail: Old cookie still gets HTTP 200 after logging out.
