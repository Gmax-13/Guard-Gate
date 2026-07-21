/**
 * Report Formatter
 *
 * Formats a ScanReport into human-readable colored console output.
 */

import chalk from 'chalk';
import type { ScanReport, ModuleResult, Finding } from '../types/report.js';
import { Severity } from '../types/report.js';

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  [Severity.CRITICAL]: chalk.bgRed.white.bold,
  [Severity.HIGH]: chalk.red.bold,
  [Severity.MEDIUM]: chalk.yellow,
  [Severity.LOW]: chalk.blue,
  [Severity.INFO]: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  [Severity.CRITICAL]: '🔴',
  [Severity.HIGH]: '🟠',
  [Severity.MEDIUM]: '🟡',
  [Severity.LOW]: '🔵',
  [Severity.INFO]: 'ℹ️',
};

/**
 * Format and print the full scan report to the console.
 */
export function formatReport(report: ScanReport): void {
  console.log();
  console.log(chalk.bold.cyan('╔══════════════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║') + chalk.bold.white('           GuardGate Security Scan Report           ') + chalk.bold.cyan('║'));
  console.log(chalk.bold.cyan('╚══════════════════════════════════════════════════════╝'));
  console.log();

  // Repository info
  console.log(chalk.gray(`Repository: ${report.repository.url}`));
  console.log(chalk.gray(`Branch:     ${report.repository.branch}`));
  console.log(chalk.gray(`Commit:     ${report.repository.commitSha.substring(0, 8)}`));
  console.log(chalk.gray(`Timestamp:  ${report.timestamp}`));
  console.log(chalk.gray(`Duration:   ${(report.durationMs / 1000).toFixed(2)}s`));
  console.log();

  // Module results
  for (const moduleResult of report.modules) {
    formatModuleResult(moduleResult);
  }

  // Overall summary
  console.log(chalk.bold.cyan('───────────────────────────────────────────────────────'));
  const statusIcon = report.summary.passed ? chalk.green('✔ PASSED') : chalk.red('✖ FAILED');
  console.log(chalk.bold(`Overall: ${statusIcon}`));
  console.log(
    chalk.gray(`Total findings: ${report.summary.totalFindings}`),
  );
  formatSeverityBreakdown(report.summary.findingsBySeverity);
  console.log();
}

/**
 * Format a single module's results.
 */
function formatModuleResult(result: ModuleResult): void {
  const statusIcon = result.passed ? chalk.green('✔') : chalk.red('✖');
  const moduleLabel = chalk.bold(`${statusIcon} ${result.module.toUpperCase()}`);
  const durationLabel = chalk.gray(`(${(result.durationMs / 1000).toFixed(2)}s)`);

  console.log(`${moduleLabel} ${durationLabel}`);

  if (result.error) {
    console.log(chalk.red(`  Error: ${result.error}`));
    console.log();
    return;
  }

  if (result.findingCount === 0) {
    console.log(chalk.green('  No findings'));
    console.log();
    return;
  }

  console.log(chalk.gray(`  ${result.findingCount} finding(s):`));

  // Show up to 10 findings inline, then summarize the rest
  const displayFindings = result.findings.slice(0, 10);
  for (const finding of displayFindings) {
    formatFinding(finding);
  }

  if (result.findings.length > 10) {
    console.log(chalk.gray(`  ... and ${result.findings.length - 10} more (see JSON report)`));
  }

  console.log();
}

/**
 * Format a single finding.
 */
function formatFinding(finding: Finding): void {
  const icon = SEVERITY_ICONS[finding.severity];
  const severityLabel = SEVERITY_COLORS[finding.severity](
    ` ${finding.severity.toUpperCase()} `,
  );
  const location = finding.filePath
    ? chalk.gray(`${finding.filePath}${finding.lineNumber ? `:${finding.lineNumber}` : ''}`)
    : '';

  console.log(`  ${icon} ${severityLabel} ${finding.ruleName}`);
  console.log(chalk.gray(`     ${finding.message}`));
  if (location) {
    console.log(chalk.gray(`     at ${location}`));
  }
  if (finding.commitHash) {
    console.log(chalk.gray(`     commit: ${finding.commitHash.substring(0, 8)}`));
  }
}

/**
 * Format severity breakdown counts.
 */
function formatSeverityBreakdown(counts: Record<Severity, number>): void {
  const parts: string[] = [];
  for (const severity of [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]) {
    const count = counts[severity] ?? 0;
    if (count > 0) {
      parts.push(SEVERITY_COLORS[severity](`${severity}: ${count}`));
    }
  }
  if (parts.length > 0) {
    console.log(`  ${parts.join(chalk.gray(' │ '))}`);
  }
}
