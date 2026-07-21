#!/usr/bin/env node

/**
 * GuardGate CLI
 *
 * Main entry point — registers subcommands for each scanner module.
 * Usage:
 *   guardgate scan secrets    — scan for leaked secrets
 *   guardgate scan sbom       — scan dependencies for CVEs
 *   guardgate scan e2e        — run security-focused E2E tests
 *   guardgate scan all        — run all scanners
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
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
import type { Scanner, ScanContext } from './types/scanner.js';
import type { ScanReport, ModuleResult } from './types/report.js';
import { Severity, SEVERITY_WEIGHT } from './types/report.js';

const VERSION = '0.1.0';

const program = new Command();

program
  .name('guardgate')
  .description(
    chalk.bold.cyan('GuardGate') +
      ' — CI/CD security suite: secrets scanning, dependency vulnerabilities, and security E2E testing',
  )
  .version(VERSION);

// ─── scan command group ───────────────────────────────────────────────
const scanCmd = program
  .command('scan')
  .description('Run security scans');

/** Shared scan options */
function addScanOptions(cmd: Command): Command {
  return cmd
    .option('-c, --config <path>', 'Path to guardgate config file')
    .option('-d, --dir <path>', 'Target directory to scan', process.cwd())
    .option(
      '-s, --severity <level>',
      'Minimum severity threshold to fail (info|low|medium|high|critical)',
    )
    .option('-o, --output <dir>', 'Output directory for reports')
    .option('--format <format>', 'Output format (json|console|both)')
    .option('--verbose', 'Enable verbose/debug output')
    .option('--quiet', 'Suppress all output except errors');
}

/**
 * Resolve scan options into a ScanContext + loaded config.
 */
async function resolveScanContext(
  options: Record<string, string | boolean | undefined>,
): Promise<{ context: ScanContext; config: ReturnType<typeof loadConfig> }> {
  // Set log level
  if (options.verbose) logger.setLevel(LogLevel.DEBUG);
  if (options.quiet) logger.setLevel(LogLevel.ERROR);

  const rootDir = (options.dir as string) ?? process.cwd();
  const config = loadConfig(rootDir, options.config as string | undefined);

  // CLI options override config file
  if (options.severity) {
    config.severityThreshold = options.severity as Severity;
  }
  if (options.output) {
    config.outputDir = options.output as string;
  }
  if (options.format) {
    config.outputFormat = options.format as 'json' | 'console' | 'both';
  }

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

  // Output the report
  if (config.outputFormat === 'console' || config.outputFormat === 'both') {
    formatReport(report);
  }
  if (config.outputFormat === 'json' || config.outputFormat === 'both') {
    writeJsonReport(report, config.outputDir);
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

// ─── scan all ─────────────────────────────────────────────────────────
addScanOptions(
  scanCmd
    .command('all')
    .description('Run all security scanners'),
).action(async (options) => {
  const { context, config } = await resolveScanContext(options);

  const modules = ['secrets', 'sbom', 'e2e'];
  const scanners: Scanner[] = [];

  for (const name of modules) {
    // Skip disabled modules
    const moduleConfig = (config as unknown as Record<string, { enabled?: boolean }>)[name];
    if (moduleConfig && moduleConfig.enabled === false) {
      logger.info(`Skipping disabled module: ${name}`);
      continue;
    }

    const scanner = await loadScannerModule(name);
    if (scanner) {
      scanners.push(scanner);
    }
  }

  if (scanners.length === 0) {
    logger.error('No scanner modules available');
    process.exit(1);
  }

  const report = await runScanners(scanners, context, config);
  process.exit(report.summary.passed ? 0 : 1);
});

// ─── Parse and execute ───────────────────────────────────────────────
program.parse();
