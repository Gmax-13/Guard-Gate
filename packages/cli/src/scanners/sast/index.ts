import { relative, join } from 'node:path';
import fg from 'fast-glob';
import { logger } from '../../utils/logger.js';
import { Severity, type ModuleResult, type Finding } from '../../types/report.js';
import type { Scanner, ScanContext } from '../../types/scanner.js';
import type { SastConfig } from '../../config/schema.js';
import { parseAndScanFile } from './ast-parser.js';
import { parseSastRules, type SastCustomRule } from './rules.js';
import { resolve } from 'node:path';

export class SastScanner implements Scanner {
  readonly name = 'sast';
  readonly displayName = 'SAST (Static Analysis)';

  async scan(context: ScanContext): Promise<ModuleResult> {
    const startTime = Date.now();
    const config = context.config.sast as SastConfig;
    const rootDir = context.rootDir;

    const findings: Finding[] = [];
    const findingsBySeverity = {
      [Severity.INFO]: 0,
      [Severity.LOW]: 0,
      [Severity.MEDIUM]: 0,
      [Severity.HIGH]: 0,
      [Severity.CRITICAL]: 0,
    };

    if (config.enabled === false) {
      logger.info('SAST scanner is disabled');
      return this.buildResult(true, findings, findingsBySeverity, startTime);
    }

    try {
      // Build glob pattern based on configured extensions
      // e.g., ["**/*.js", "**/*.ts"]
      const extPatterns = config.extensions.map(ext => `**/*${ext}`);
      
      const files = await fg(extPatterns, {
        cwd: rootDir,
        ignore: config.exclude,
        absolute: true,
      });

      // Load custom rules
      const customRules: SastCustomRule[] = [];
      if (config.ruleFiles) {
        for (const ruleFile of config.ruleFiles) {
          const fullPath = resolve(rootDir, ruleFile);
          const rules = parseSastRules(fullPath);
          customRules.push(...rules);
        }
      }

      logger.debug(`Found ${files.length} files to analyze with ${customRules.length} custom rules`);

      for (const file of files) {
        try {
          const fileFindings = parseAndScanFile(file, customRules);
          for (const f of fileFindings) {
            const relPath = relative(rootDir, f.file);
            const severity = f.severity as Severity;

            findingsBySeverity[severity]++;
            findings.push({
              id: `sast-${f.type.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`,
              module: 'sast',
              ruleId: f.type.toLowerCase().replace(/\s+/g, '-'),
              ruleName: f.type,
              severity,
              message: f.message,
              filePath: relPath,
              lineNumber: f.line,
              evidence: [
                {
                  type: 'snippet',
                  label: 'Offending Code',
                  data: f.snippet,
                }
              ]
            });
          }
        } catch (err) {
          logger.debug(`Failed to parse ${file}: ${err instanceof Error ? err.message : String(err)}`);
          // Ignore parsing errors for non-compliant or unsupported files
        }
      }

      // Check if we passed the severity threshold
      let passed = true;
      const thresholdWeight = this.getSeverityWeight(config.severityThreshold as Severity);

      for (const f of findings) {
        if (this.getSeverityWeight(f.severity) >= thresholdWeight) {
          passed = false;
          break;
        }
      }

      return this.buildResult(passed, findings, findingsBySeverity, startTime);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`SAST scan failed: ${message}`);
      return {
        ...this.buildResult(false, findings, findingsBySeverity, startTime),
        error: message,
      };
    }
  }

  private buildResult(
    passed: boolean,
    findings: Finding[],
    findingsBySeverity: Record<Severity, number>,
    startTime: number,
  ): ModuleResult {
    return {
      module: this.name,
      passed,
      findingCount: findings.length,
      findingsBySeverity,
      findings,
      durationMs: Date.now() - startTime,
    };
  }

  private getSeverityWeight(severity: Severity): number {
    const weights: Record<Severity, number> = {
      [Severity.INFO]: 0,
      [Severity.LOW]: 1,
      [Severity.MEDIUM]: 2,
      [Severity.HIGH]: 3,
      [Severity.CRITICAL]: 4,
    };
    return weights[severity] ?? 0;
  }
}
