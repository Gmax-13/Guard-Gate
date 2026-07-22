<div align="center">
  <img src="https://img.shields.io/badge/Security-First-blue?style=for-the-badge&logo=shield&logoColor=white" alt="Security First"/>
  <h1>🛡️ GuardGate CLI</h1>
  <p><strong>The Next-Generation Programmable Security Suite for Modern CI/CD Pipelines</strong></p>
</div>

---

**GuardGate** is an extensible, AI-ready security suite designed to run seamlessly in your CI/CD pipelines. This package contains the core CLI and scanning engine for the GuardGate suite.

![GuardGate Architecture](https://raw.githubusercontent.com/Gmax-13/Guard-Gate/main/diagram.png)

It goes beyond simple regex scanning by providing:
- **🌐 E2E Security Tests (Browser)**: Headless browser workflows powered by Playwright to catch XSS, CSRF, and Auth Bypasses.
- **⚡ API Fuzzer (DAST)**: Dynamically test your endpoints.
- **🧠 True Semantic AST Analysis (Code Scanner)**: Write real JavaScript plugins that traverse the TypeScript Compiler API.
- **📦 SBOM & Dependency Scanner**: Automatically audits against known CVEs.
- **🔑 Secrets Scanner**: Fast and reliable scanning to ensure credentials never leak.

## 🚀 Installation

```bash
npm install -g guardgate
# or
npx guardgate
```

## 🛠 Usage

Run the scanner in your project directory:

```bash
guardgate scan
```

### Specific Modules
```bash
guardgate scan code    # Run Semantic AST analysis
guardgate scan api     # Run API DAST fuzzing
guardgate scan e2e     # Run Playwright Browser tests
guardgate scan sbom    # Run Dependency vulnerability scan
guardgate scan secrets # Run Secrets scan
```

### Output Formats
```bash
guardgate scan --format json       # JSON report only
guardgate scan --format console    # Console output only
guardgate scan --format both       # Console + JSON (default)
guardgate scan --format sarif      # SARIF v2.1.0 report only
guardgate scan --format all        # Console + JSON + SARIF
```

### Diff-Aware (Baseline) Scanning
```bash
guardgate scan --baseline main     # Compare against main branch
guardgate scan --baseline HEAD~1   # Compare against previous commit
```

## 🤖 AI Agent Integration

GuardGate is built to be piloted by AI. We expose a powerful utility command that generates detailed YAML/JS instructions, empowering your AI coding assistant to automatically generate test cases and workflows:

```bash
guardgate agent
```
Provide the output to your AI to watch it generate `.guardgate/flows` and `.guardgate/rules` dynamically!

---

For more details, visit the [main repository](https://github.com/Gmax-13/Guard-Gate).
