/**
 * Secrets Scanner Module
 *
 * Entry point for the secrets scanner. Implements the Scanner interface.
 * Combines file scanning + git history scanning.
 */

import type { Scanner, ScanContext } from '../../types/scanner.js';
import type { ModuleResult } from '../../types/report.js';
import { Severity, SEVERITY_WEIGHT } from '../../types/report.js';
import type { GuardGateConfig } from '../../config/schema.js';
import { scanFiles } from './file-scanner.js';
import { scanHistory } from './history-scanner.js';
import { isGitRepo } from '../../utils/git.js';
import { logger } from '../../utils/logger.js';

export class SecretsScanner implements Scanner {
  readonly name = 'secrets' as const;
  readonly displayName = 'Secrets Scanner';

  async scan(context: ScanContext): Promise<ModuleResult> {
    const startTime = Date.now();
    const config = context.config as unknown as GuardGateConfig;
    const secretsConfig = config.secrets;

    logger.info('Scanning for leaked secrets and credentials...');

    try {
      // Phase 1: Scan current files
      logger.info('Scanning current files...');
      const fileFindings = await scanFiles({
        rootDir: context.rootDir,
        allowlistPatterns: secretsConfig.allowlist,
        entropyThreshold: secretsConfig.entropyThreshold,
        customRules: secretsConfig.customRules,
      });

      // Phase 2: Scan git history (if enabled and in a git repo)
      let historyFindings: Awaited<ReturnType<typeof scanHistory>> = [];
      if (secretsConfig.scanHistory) {
        const isRepo = await isGitRepo(context.rootDir);
        if (isRepo) {
          logger.info('Scanning git history...');
          historyFindings = await scanHistory({
            rootDir: context.rootDir,
            allowlistPatterns: secretsConfig.allowlist,
            maxCommits: secretsConfig.maxCommits,
            entropyThreshold: secretsConfig.entropyThreshold,
            customRules: secretsConfig.customRules,
          });
        } else {
          logger.info('Not a git repository, skipping history scan');
        }
      }

      // Combine all findings
      const allFindings = [...fileFindings, ...historyFindings];

      // Calculate severity breakdown
      const findingsBySeverity = {
        [Severity.INFO]: 0,
        [Severity.LOW]: 0,
        [Severity.MEDIUM]: 0,
        [Severity.HIGH]: 0,
        [Severity.CRITICAL]: 0,
      };
      for (const finding of allFindings) {
        findingsBySeverity[finding.severity]++;
      }

      // Determine pass/fail based on severity threshold
      const thresholdWeight = SEVERITY_WEIGHT[context.severityThreshold as Severity] ?? SEVERITY_WEIGHT[Severity.HIGH];
      const hasFailingFindings = allFindings.some(
        (f) => SEVERITY_WEIGHT[f.severity] >= thresholdWeight,
      );

      const durationMs = Date.now() - startTime;

      return {
        module: 'secrets',
        passed: !hasFailingFindings,
        findingCount: allFindings.length,
        findingsBySeverity,
        findings: allFindings,
        durationMs,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`Secrets scanner failed: ${message}`);

      return {
        module: 'secrets',
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
        durationMs: Date.now() - startTime,
        error: message,
      };
    }
  }
}
