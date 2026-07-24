/**
 * SBOM Scanner Module
 *
 * Entry point for the SBOM/dependency vulnerability scanner.
 * Implements the Scanner interface.
 */

import type { Scanner, ScanContext } from '../../types/scanner.js';
import type { ModuleResult, Finding } from '../../types/report.js';
import { Severity, SEVERITY_WEIGHT } from '../../types/report.js';
import type { GuardGateConfig } from '../../config/schema.js';
import type { Dependency } from './types.js';
import fg from 'fast-glob';
import { dirname } from 'node:path';
import { detectEcosystems } from './detector.js';
import { batchQueryOsv } from './osv-client.js';
import { matchVulnerabilities } from './vulnerability-matcher.js';
import { generateSbom, writeSbom, generateSpdxSbom, writeSpdxSbom } from './sbom-generator.js';
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
      // Step 1: Detect ecosystems by finding all manifest files recursively
      const manifestFiles = await fg([
        '**/package.json', '**/package-lock.json', '**/yarn.lock',
        '**/requirements.txt', '**/Pipfile.lock', '**/pyproject.toml',
        '**/go.mod', '**/pom.xml', '**/Cargo.toml', '**/Cargo.lock'
      ], {
        cwd: context.rootDir,
        ignore: ['**/node_modules/**', '**/.git/**', '**/.guardgate/**', '**/dist/**', '**/build/**'],
        absolute: true,
      });

      // Get unique directories containing manifests, plus the root directory as a fallback
      const scanDirs = [...new Set([context.rootDir, ...manifestFiles.map(f => dirname(f))])];
      const allDependencies: Dependency[] = [];
      let detectedAny = false;

      for (const dir of scanDirs) {
        const parsers = detectEcosystems(dir, sbomConfig.ecosystems);
        
        if (parsers.length > 0) {
          detectedAny = true;
          for (const parser of parsers) {
            logger.info(`Parsing ${parser.displayName} dependencies in ${dir}...`);
            const result = await parser.parse(dir);

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
          }
        }
      }

      if (!detectedAny) {
        logger.warn('No supported ecosystems detected, skipping SBOM scan');
        return this.emptyResult(Date.now() - startTime);
      }
      
      logger.info(`  Found ${allDependencies.length} total dependencies`);

      if (allDependencies.length === 0) {
        logger.info('No dependencies found to check');
        return this.emptyResult(Date.now() - startTime);
      }

      // Step 3: Generate SBOM
      if (sbomConfig.generateSbom) {
        if (sbomConfig.sbomFormat === 'spdx') {
          const sbom = generateSpdxSbom(allDependencies);
          writeSpdxSbom(sbom, config.outputDir);
        } else {
          const sbom = generateSbom(allDependencies);
          writeSbom(sbom, config.outputDir);
        }
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

      const errorFinding: Finding = {
        id: `sbom-error-${Date.now()}`,
        module: 'sbom',
        ruleId: 'execution-error',
        ruleName: 'SBOM Execution Error',
        severity: Severity.HIGH,
        message: `Failed to verify dependencies: ${message}`,
      };

      return {
        module: 'sbom',
        passed: false,
        findingCount: 1,
        findingsBySeverity: {
          [Severity.INFO]: 0,
          [Severity.LOW]: 0,
          [Severity.MEDIUM]: 0,
          [Severity.HIGH]: 1,
          [Severity.CRITICAL]: 0,
        },
        findings: [errorFinding],
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
