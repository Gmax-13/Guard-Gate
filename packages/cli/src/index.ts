#!/usr/bin/env node

/**
 * GuardGate CLI
 *
 * Main entry point — registers subcommands for each scanner module.
 * Always scans the current working directory and outputs to .guardgate/.
 *
 * Usage:
 *   guardgate scan            — run all scanners in phases
 *   guardgate scan secrets    — scan for leaked secrets
 *   guardgate scan sbom       — scan dependencies for CVEs
 *   guardgate scan e2e        — run security-focused E2E tests
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { resolve, join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { loadConfig } from './config/loader.js';
import { logger, LogLevel } from './utils/logger.js';
import {
  getCurrentBranch,
  getCurrentCommitSha,
  getRemoteUrl,
  isGitRepo,
} from './utils/git.js';
import { formatReport } from './report/formatter.js';
import { writeJsonReport } from './report/json-writer.js';
import { writeSarifReport } from './report/sarif-writer.js';
import { applyBaseline } from './utils/baseline.js';
import type { Scanner, ScanContext } from './types/scanner.js';
import type { ScanReport, ModuleResult } from './types/report.js';
import { Severity, SEVERITY_WEIGHT } from './types/report.js';

const VERSION = '1.2.1';

const program = new Command();

program
  .name('guardgate')
  .description(
    chalk.bold.cyan('GuardGate') +
      ' — CI/CD security suite: secrets scanning, dependency vulnerabilities, and security E2E testing',
  )
  .version(VERSION)
  .enablePositionalOptions();

// ─── scan command group ───────────────────────────────────────────────
const scanCmd = program
  .command('scan')
  .description('Run security scans (runs all phases when no subcommand is given)')
  .enablePositionalOptions()
  .passThroughOptions();

/** Shared scan options */
function addScanOptions(cmd: Command): Command {
  return cmd
    .option('-c, --config <path>', 'Path to guardgate config file')
    .option(
      '-s, --severity <level>',
      'Minimum severity threshold to fail (info|low|medium|high|critical)',
    )
    .option('--format <format>', 'Output format (json|console|both|sarif|all)')
    .option('--baseline <ref>', 'Compare against a baseline git commit to only report new findings')
    .option('--verbose', 'Enable verbose/debug output')
    .option('--quiet', 'Suppress all output except errors');
}

// Add shared options to `scan` itself (for `guardgate scan` with no subcommand)
addScanOptions(scanCmd);

/**
 * Resolve scan options into a ScanContext + loaded config.
 */
async function resolveScanContext(
  options: Record<string, string | boolean | undefined>,
): Promise<{ context: ScanContext; config: ReturnType<typeof loadConfig> }> {
  // Set log level
  if (options.verbose) logger.setLevel(LogLevel.DEBUG);
  if (options.quiet) logger.setLevel(LogLevel.ERROR);

  // Always scan the current working directory
  const rootDir = process.cwd();
  const config = loadConfig(rootDir, options.config as string | undefined);

  // CLI options override config file
  if (options.severity) {
    config.severityThreshold = options.severity as Severity;
  }
  if (options.format) {
    config.outputFormat = options.format as 'json' | 'console' | 'both' | 'sarif' | 'all';
  }
  if (options.baseline) {
    config.baseline = options.baseline as string;
  }

  // Resolve output directory to absolute path under cwd and ensure it exists
  config.outputDir = resolve(rootDir, config.outputDir);
  mkdirSync(config.outputDir, { recursive: true });

  const context: ScanContext = {
    rootDir,
    config: config as unknown as Record<string, unknown>,
    severityThreshold: config.severityThreshold,
  };

  return { context, config };
}

/**
 * Run an array of scanners, aggregate results into a ScanReport.
 */
async function runScanners(
  scanners: Scanner[],
  context: ScanContext,
  config: ReturnType<typeof loadConfig>,
): Promise<ScanReport> {
  const startTime = Date.now();
  const moduleResults: ModuleResult[] = [];

  for (const scanner of scanners) {
    logger.section(`${scanner.displayName}`);
    const spinner = ora(`Running ${scanner.displayName}...`).start();

    try {
      const result = await scanner.scan(context);
      moduleResults.push(result);

      if (result.passed) {
        spinner.succeed(`${scanner.displayName}: ${chalk.green('PASSED')} (${result.findingCount} findings)`);
      } else {
        spinner.fail(`${scanner.displayName}: ${chalk.red('FAILED')} (${result.findingCount} findings)`);
      }
    } catch (err) {
      spinner.fail(`${scanner.displayName}: ${chalk.red('ERROR')}`);
      const message = err instanceof Error ? err.message : String(err);
      moduleResults.push({
        module: scanner.name,
        passed: false,
        findingCount: 0,
        findingsBySeverity: {
          [Severity.INFO]: 0,
          [Severity.LOW]: 0,
          [Severity.MEDIUM]: 0,
          [Severity.HIGH]: 0,
          [Severity.CRITICAL]: 0,
        },
        findings: [],
        durationMs: 0,
        error: message,
      });
    }
  }

  const totalDurationMs = Date.now() - startTime;

  // Build summary
  const totalFindings = moduleResults.reduce((sum, m) => sum + m.findingCount, 0);
  const findingsBySeverity = {
    [Severity.INFO]: 0,
    [Severity.LOW]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.HIGH]: 0,
    [Severity.CRITICAL]: 0,
  };
  for (const result of moduleResults) {
    for (const severity of Object.values(Severity)) {
      findingsBySeverity[severity] += result.findingsBySeverity[severity] ?? 0;
    }
  }

  const moduleStatus: Record<string, boolean> = {};
  for (const result of moduleResults) {
    moduleStatus[result.module] = result.passed;
  }

  const passed = moduleResults.every((m) => m.passed);

  // Get repo info
  const rootDir = context.rootDir;
  const isRepo = await isGitRepo(rootDir);

  const report: ScanReport = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    repository: {
      url: isRepo ? await getRemoteUrl(rootDir) : rootDir,
      branch: isRepo ? await getCurrentBranch(rootDir) : 'unknown',
      commitSha: isRepo ? await getCurrentCommitSha(rootDir) : 'unknown',
    },
    summary: {
      passed,
      totalFindings,
      findingsBySeverity,
      moduleStatus: moduleStatus as ScanReport['summary']['moduleStatus'],
    },
    modules: moduleResults,
    durationMs: totalDurationMs,
  };

  if (config.baseline) {
    await applyBaseline(report, config.baseline, context.rootDir, config.severityThreshold as Severity);
  }

  // Output the report
  const fmt = config.outputFormat;
  if (fmt === 'console' || fmt === 'both' || fmt === 'all') {
    formatReport(report);
  }
  if (fmt === 'json' || fmt === 'both' || fmt === 'all') {
    writeJsonReport(report, config.outputDir);
  }
  if (fmt === 'sarif' || fmt === 'all') {
    writeSarifReport(report, config.outputDir);
  }

  return report;
}

/**
 * Dynamically load scanner modules.
 * Lazy-loads only the requested scanners to keep startup fast.
 */
async function loadScannerModule(name: string): Promise<Scanner | null> {
  try {
    switch (name) {
      case 'secrets': {
        const { SecretsScanner } = await import('./scanners/secrets/index.js');
        return new SecretsScanner();
      }
      case 'sbom': {
        const { SbomScanner } = await import('./scanners/sbom/index.js');
        return new SbomScanner();
      }
      case 'code': {
        const { CodeScanner } = await import('./scanners/code/index.js');
        return new CodeScanner();
      }
      case 'api': {
        const { ApiScanner } = await import('./scanners/api/index.js');
        return new ApiScanner();
      }
      case 'e2e': {
        const { E2eScanner } = await import('./scanners/e2e/index.js');
        return new E2eScanner();
      }
      default:
        logger.error(`Unknown scanner module: ${name}`);
        return null;
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to load scanner module '${name}': ${message}`);
    return null;
  }
}

/**
 * Run all scanners sequentially in numbered phases with clear banners.
 */
async function runAllPhased(
  options: Record<string, string | boolean | undefined>,
): Promise<void> {
  const { context, config } = await resolveScanContext(options);

  const PHASES = [
    { name: 'secrets', label: 'Secrets Scanner' },
    { name: 'sbom',    label: 'SBOM / Dependency Scanner' },
    { name: 'code',    label: 'Code Scanner (Semantic Analysis)' },
    { name: 'api',     label: 'API Security Fuzzer (DAST)' },
    { name: 'e2e',     label: 'E2E Security Tests' },
  ];

  const enabledPhases = PHASES.filter((phase) => {
    const moduleConfig = (config as unknown as Record<string, { enabled?: boolean }>)[phase.name];
    if (moduleConfig && moduleConfig.enabled === false) {
      logger.info(`Skipping disabled module: ${phase.name}`);
      return false;
    }
    return true;
  });

  if (enabledPhases.length === 0) {
    logger.error('No scanner modules available');
    process.exit(1);
  }

  console.log();
  console.log(chalk.bold.cyan('╔══════════════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║') + chalk.bold.white('          GuardGate — Full Security Scan             ') + chalk.bold.cyan('║'));
  console.log(chalk.bold.cyan('╚══════════════════════════════════════════════════════╝'));
  console.log(chalk.gray(`  Running ${enabledPhases.length} phase(s) sequentially...`));
  console.log();

  const allModuleResults: ModuleResult[] = [];
  const startTime = Date.now();

  for (let i = 0; i < enabledPhases.length; i++) {
    const phase = enabledPhases[i];
    const phaseNum = i + 1;
    const total = enabledPhases.length;

    console.log(
      chalk.bold.cyan(`── Phase ${phaseNum}/${total}: `) +
      chalk.bold.white(phase.label) +
      chalk.bold.cyan(' ─────────────────────────────────────'),
    );

    const scanner = await loadScannerModule(phase.name);
    if (!scanner) {
      console.log(chalk.red(`  ✖ Failed to load ${phase.name} scanner`));
      console.log();
      continue;
    }

    const spinner = ora(`Running ${phase.label}...`).start();

    try {
      const result = await scanner.scan(context);
      allModuleResults.push(result);

      if (result.passed) {
        spinner.succeed(
          chalk.green(`Phase ${phaseNum}/${total} — ${phase.label}: PASSED`) +
          chalk.gray(` (${result.findingCount} findings, ${(result.durationMs / 1000).toFixed(2)}s)`),
        );
      } else {
        spinner.fail(
          chalk.red(`Phase ${phaseNum}/${total} — ${phase.label}: FAILED`) +
          chalk.gray(` (${result.findingCount} findings, ${(result.durationMs / 1000).toFixed(2)}s)`),
        );
      }
    } catch (err) {
      spinner.fail(chalk.red(`Phase ${phaseNum}/${total} — ${phase.label}: ERROR`));
      const message = err instanceof Error ? err.message : String(err);
      allModuleResults.push({
        module: scanner.name,
        passed: false,
        findingCount: 0,
        findingsBySeverity: {
          [Severity.INFO]: 0,
          [Severity.LOW]: 0,
          [Severity.MEDIUM]: 0,
          [Severity.HIGH]: 0,
          [Severity.CRITICAL]: 0,
        },
        findings: [],
        durationMs: 0,
        error: message,
      });
    }

    console.log();
  }

  // Build aggregated report
  const totalDurationMs = Date.now() - startTime;
  const totalFindings = allModuleResults.reduce((sum, m) => sum + m.findingCount, 0);
  const findingsBySeverity = {
    [Severity.INFO]: 0,
    [Severity.LOW]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.HIGH]: 0,
    [Severity.CRITICAL]: 0,
  };
  for (const result of allModuleResults) {
    for (const severity of Object.values(Severity)) {
      findingsBySeverity[severity] += result.findingsBySeverity[severity] ?? 0;
    }
  }

  const moduleStatus: Record<string, boolean> = {};
  for (const result of allModuleResults) {
    moduleStatus[result.module] = result.passed;
  }

  const passed = allModuleResults.every((m) => m.passed);

  const rootDir = context.rootDir;
  const isRepo = await isGitRepo(rootDir);

  const report: ScanReport = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    repository: {
      url: isRepo ? await getRemoteUrl(rootDir) : rootDir,
      branch: isRepo ? await getCurrentBranch(rootDir) : 'unknown',
      commitSha: isRepo ? await getCurrentCommitSha(rootDir) : 'unknown',
    },
    summary: {
      passed,
      totalFindings,
      findingsBySeverity,
      moduleStatus: moduleStatus as ScanReport['summary']['moduleStatus'],
    },
    modules: allModuleResults,
    durationMs: totalDurationMs,
  };

  if (config.baseline) {
    await applyBaseline(report, config.baseline, context.rootDir, config.severityThreshold as Severity);
  }

  // Output
  const fmt = config.outputFormat;
  if (fmt === 'console' || fmt === 'both' || fmt === 'all') {
    formatReport(report);
  }
  if (fmt === 'json' || fmt === 'both' || fmt === 'all') {
    writeJsonReport(report, config.outputDir);
  }
  if (fmt === 'sarif' || fmt === 'all') {
    writeSarifReport(report, config.outputDir);
  }

  process.exit(report.summary.passed ? 0 : 1);
}

// ─── scan (no subcommand) → run all phases sequentially ──────────────
scanCmd.action(async (options) => {
  await runAllPhased(options);
});

// ─── scan secrets ─────────────────────────────────────────────────────
addScanOptions(
  scanCmd
    .command('secrets')
    .description('Scan for leaked secrets and credentials'),
).action(async (options) => {
  const { context, config } = await resolveScanContext(options);
  const scanner = await loadScannerModule('secrets');
  if (!scanner) process.exit(1);

  const report = await runScanners([scanner], context, config);
  process.exit(report.summary.passed ? 0 : 1);
});

// ─── scan sbom ────────────────────────────────────────────────────────
addScanOptions(
  scanCmd
    .command('sbom')
    .description('Scan dependencies for known vulnerabilities (SBOM)'),
).action(async (options) => {
  const { context, config } = await resolveScanContext(options);
  const scanner = await loadScannerModule('sbom');
  if (!scanner) process.exit(1);

  const report = await runScanners([scanner], context, config);
  process.exit(report.summary.passed ? 0 : 1);
});

// ─── scan code ────────────────────────────────────────────────────────
addScanOptions(
  scanCmd
    .command('code')
    .description('Scan backend source code for insecure patterns (AST & Custom Rules)'),
).action(async (options) => {
  const { context, config } = await resolveScanContext(options);
  const scanner = await loadScannerModule('code');
  if (!scanner) process.exit(1);

  const report = await runScanners([scanner], context, config);
  process.exit(report.summary.passed ? 0 : 1);
});

// ─── scan api ────────────────────────────────────────────────────────
addScanOptions(
  scanCmd
    .command('api')
    .description('Fuzz backend API endpoints for vulnerabilities (DAST)'),
).action(async (options) => {
  const { context, config } = await resolveScanContext(options);
  const scanner = await loadScannerModule('api');
  if (!scanner) process.exit(1);

  const report = await runScanners([scanner], context, config);
  process.exit(report.summary.passed ? 0 : 1);
});

// ─── scan e2e ─────────────────────────────────────────────────────────
addScanOptions(
  scanCmd
    .command('e2e')
    .description('Run security-focused E2E tests'),
).action(async (options) => {
  const { context, config } = await resolveScanContext(options);
  const scanner = await loadScannerModule('e2e');
  if (!scanner) process.exit(1);

  const report = await runScanners([scanner], context, config);
  process.exit(report.summary.passed ? 0 : 1);
});

// ─── help command ───────────────────────────────────────────────────────
program
  .command('help')
  .description('Display comprehensive help information')
  .action(() => {
    const helpText = `
GuardGate Security Scanner

Usage: guardgate scan [options] [command]

Description:
  Run security scans against your repository and application.
  If no subcommand is provided, runs all enabled modules sequentially.

Global Options:
  -c, --config <path>     Path to guardgate config file
  -s, --severity <level>  Minimum severity threshold to fail
                          (info|low|medium|high|critical)
  --format <format>       Output format (json|console|both|sarif|all)
  --verbose               Enable verbose/debug output
  --quiet                 Suppress all output except errors
  -h, --help              display help for command

Modules (Subcommands):
  guardgate scan secrets  Scan for leaked secrets and credentials (history & files)
  guardgate scan sbom     Scan dependencies for known vulnerabilities (SBOM)
  guardgate scan code     Scan backend source code for insecure patterns (Semantic Analysis)
  guardgate scan api      Fuzz backend API endpoints for vulnerabilities (DAST)
  guardgate scan e2e      Run security-focused E2E browser tests

Utility Commands:
  guardgate agent         Output detailed instructions and schemas for AI agents
                          to generate customizable security workflows.
  guardgate help          Display this comprehensive help information.

Examples:
  $ guardgate scan
  $ guardgate scan code --severity high --format json
  $ guardgate scan secrets -c custom-config.yml
`;
    console.log(helpText.trim());
  });

// ─── agent command ──────────────────────────────────────────────────────
program
  .command('agent')
  .description('Output detailed instructions for AI agents to generate workflows')
  .action(() => {
    const prompt = `
# GuardGate Agent Instructions

You are an AI Agent assisting the user with setting up security workflows for GuardGate.
GuardGate supports 3 programmable modules: E2E (Browser), API (DAST), and Code Scanner (Semantic Analysis).

## Objective
Analyze the user's application using \`list_dir\` and \`view_file\` and generate appropriate YAML workflow/rule files.
Save all generated files into the \`<project-root>/.guardgate/\` directory structure.
After creating any file, register its path in the user's \`guardgate.config.yml\` under the appropriate module.

---

### 1. E2E Tests (Browser Functionality & Security)
- **Scope:** Create flows that test the ENTIRE functionality of the application (e.g. standard user journeys, checkouts, form submissions) AND embed security assertions within them.
- **File Naming:** .guardgate/flows/guardgate_e2e_[action].yml
- **Registration:** Add to \`e2e.flowFiles\` in \`guardgate.config.yml\`.
- **Schema:**
\`\`\`yaml
name: "E2E Auth Bypass"
targetUrl: "http://localhost:3000"
plugins:
  - "authBypassCheck"
  - "idorCheck"
  - "sessionCookieFlagsCheck"
  - "logoutInvalidationCheck"
  - "loginRateLimitCheck"
steps:
  - action: "goto"
    url: "/login"
  - action: "fill"
    selector: "#username"
    value: "admin"
  - action: "click"
    selector: "#submit"
  - action: "assertText"
    selector: ".welcome"
    text: "Welcome"
\`\`\`

---

### 2. API Fuzzer (DAST)
- **File Naming:** \`.guardgate/flows/guardgate_api_[target].yml\`
- **Registration:** Add to \`api.flowFiles\` in \`guardgate.config.yml\`.
- **Schema:**
\`\`\`yaml
name: "API SQL Injection Test"
endpoints:
  - method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH"
    path: "/api/login"
    headers:
      Content-Type: "application/json"
    body:
      username: "admin' OR '1'='1"
      password: "foo"
    assert:
      status: 200
      plugin: "sql-injection"
      matchBody: "syntax error|admin" # Optional: Check response body for vulnerable string
      notMatchBody: "safe" # Optional: Check response body does NOT contain string
\`\`\`

---

### 3. Programmable Code Scanner (Semantic Analysis)
- **File Naming:** \`.guardgate/rules/guardgate_code_[rule].js\`
- **Registration:** Add to \`code.ruleFiles\` in \`guardgate.config.yml\`.
- **Schema (JavaScript Plugin):**
\`\`\`javascript
module.exports = {
  id: "custom-sqli",
  severity: "high", // "high" | "critical" | "medium" | "low"
  message: "Avoid dynamic raw queries",
  check: function(node, ts, context) {
    // You can write actual semantic AST logic here
    if (ts.isCallExpression(node)) {
      // Analyze node...
      return true; // Return true if finding is detected
    }
    return false;
  }
};
\`\`\`

---

## Instructions for the Agent
1. **Analyze**: Explore the project to understand the routes, APIs, and codebase quirks.
2. **Generate**: Create the necessary YAML/JS files for the requested module (or all three).
3. **Register**: Update guardgate.config.yml to include your new files.
4. **CI/CD**: If requested, create a .github/workflows/guardgate.yml file using the guardgate action to run on push/PR.
5. **Run**: Propose to the user to run guardgate scan to verify.
`;
    console.log(prompt.trim());
  });

// ─── Parse and execute ───────────────────────────────────────────────
program.parse();
