/**
 * SBOM Scanner Module
 *
 * Entry point for the SBOM/dependency vulnerability scanner.
 * Implements the Scanner interface.
 */

import type { Scanner, ScanContext } from '../../types/scanner.js';
import type { ModuleResult } from '../../types/report.js';
import { Severity, SEVERITY_WEIGHT } from '../../types/report.js';
import type { GuardGateConfig } from '../../config/schema.js';
import type { Dependency } from './types.js';
import { detectEcosystems } from './detector.js';
import { batchQueryOsv } from './osv-client.js';
import { matchVulnerabilities } from './vulnerability-matcher.js';
import { generateSbom, writeSbom } from './sbom-generator.js';
import { logger } from '../../utils/logger.js';

export class SbomScanner implements Scanner {
  readonly name = 'sbom' as const;
  readonly displayName = 'SBOM / Dependency Vulnerability Scanner';

  async scan(context: ScanContext): Promise<ModuleResult> {
    const startTime = Date.now();
    const config = context.config as unknown as GuardGateConfig;
    const sbomConfig = config.sbom;

    logger.info('Scanning dependencies for known vulnerabilities...');

    try {
      // Step 1: Detect ecosystems
      const parsers = detectEcosystems(context.rootDir, sbomConfig.ecosystems);

      if (parsers.length === 0) {
        logger.warn('No supported ecosystems detected, skipping SBOM scan');
        return this.emptyResult(Date.now() - startTime);
      }

      // Step 2: Parse dependencies from all detected ecosystems
      const allDependencies: Dependency[] = [];

      for (const parser of parsers) {
        logger.info(`Parsing ${parser.displayName} dependencies...`);
        const result = await parser.parse(context.rootDir);

        // Filter based on config
        let deps = result.dependencies;
        if (!sbomConfig.includeTransitive) {
          deps = deps.filter((d) => d.isDirect);
        }

        // Apply ignore list
        if (sbomConfig.ignoredPackages.length > 0) {
          deps = deps.filter((d) => {
            const nameVersion = `${d.name}@${d.version}`;
            return !sbomConfig.ignoredPackages.includes(d.name) &&
              !sbomConfig.ignoredPackages.includes(nameVersion);
          });
        }

        allDependencies.push(...deps);
        logger.info(`  Found ${deps.length} dependencies`);
      }

      if (allDependencies.length === 0) {
        logger.info('No dependencies found to check');
        return this.emptyResult(Date.now() - startTime);
      }

      // Step 3: Generate SBOM
      if (sbomConfig.generateSbom) {
        const sbom = generateSbom(allDependencies);
        writeSbom(sbom, config.outputDir);
      }

      // Step 4: Query OSV.dev for vulnerabilities
      logger.info(`Checking ${allDependencies.length} dependencies against OSV.dev...`);
      const osvResults = await batchQueryOsv(allDependencies);

      // Step 5: Match vulnerabilities to findings
      const findings = matchVulnerabilities(osvResults);

      // Calculate severity breakdown
      const findingsBySeverity = {
        [Severity.INFO]: 0,
        [Severity.LOW]: 0,
        [Severity.MEDIUM]: 0,
        [Severity.HIGH]: 0,
        [Severity.CRITICAL]: 0,
      };
      for (const finding of findings) {
        findingsBySeverity[finding.severity]++;
      }

      // Determine pass/fail
      const threshold = sbomConfig.severityThreshold ?? context.severityThreshold;
      const thresholdWeight = SEVERITY_WEIGHT[threshold as Severity] ?? SEVERITY_WEIGHT[Severity.HIGH];
      const hasFailingFindings = findings.some(
        (f) => SEVERITY_WEIGHT[f.severity] >= thresholdWeight,
      );

      const durationMs = Date.now() - startTime;
      const vulnCount = osvResults.filter((r) => r.vulnerabilities.length > 0).length;
      logger.info(`Found ${findings.length} vulnerabilities in ${vulnCount} packages`);

      return {
        module: 'sbom',
        passed: !hasFailingFindings,
        findingCount: findings.length,
        findingsBySeverity,
        findings,
        durationMs,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`SBOM scanner failed: ${message}`);

      return {
        module: 'sbom',
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

  private emptyResult(durationMs: number): ModuleResult {
    return {
      module: 'sbom',
      passed: true,
      findingCount: 0,
      findingsBySeverity: {
        [Severity.INFO]: 0,
        [Severity.LOW]: 0,
        [Severity.MEDIUM]: 0,
        [Severity.HIGH]: 0,
        [Severity.CRITICAL]: 0,
      },
      findings: [],
      durationMs,
    };
  }
}
