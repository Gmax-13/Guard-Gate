import { resolve } from 'node:path';
import { logger } from '../../utils/logger.js';
import { Severity, type ModuleResult, type Finding } from '../../types/report.js';
import type { Scanner, ScanContext } from '../../types/scanner.js';
import type { ApiConfig } from '../../config/schema.js';
import { parseApiFlow } from './parser.js';
import { runApiEndpoint } from './runner.js';

export class ApiScanner implements Scanner {
  readonly name = 'api';
  readonly displayName = 'API Fuzzer';

  async scan(context: ScanContext): Promise<ModuleResult> {
    const startTime = Date.now();
    const config = context.config.api as ApiConfig;
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
      logger.info('API Fuzzer is disabled');
      return this.buildResult(true, findings, findingsBySeverity, startTime);
    }

    if (!config.targetUrl) {
      logger.warn('API targetUrl is missing. Skipping scan.');
      return this.buildResult(true, findings, findingsBySeverity, startTime);
    }

    if (!config.flowFiles || config.flowFiles.length === 0) {
      logger.warn('No API flow files configured.');
      return this.buildResult(true, findings, findingsBySeverity, startTime);
    }

    try {
      for (const flowFile of config.flowFiles) {
        const fullPath = resolve(rootDir, flowFile);
        const flow = parseApiFlow(fullPath);
        if (!flow) continue;

        logger.info(`Running API flow: ${flow.name}`);
        
        for (const endpoint of flow.endpoints) {
          const endpointFindings = await runApiEndpoint(endpoint, config.targetUrl, config.timeout);
          for (const f of endpointFindings) {
            findingsBySeverity[f.severity]++;
            findings.push(f);
          }
        }
      }

      // API scanner fails if any findings exist (since they represent successful exploits/bypasses)
      const passed = findings.length === 0;

      return this.buildResult(passed, findings, findingsBySeverity, startTime);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`API scan failed: ${message}`);
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
}
