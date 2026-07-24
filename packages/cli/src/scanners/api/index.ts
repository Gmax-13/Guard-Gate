import { resolve } from 'node:path';
import { logger } from '../../utils/logger.js';
import { Severity, SEVERITY_WEIGHT, type ModuleResult, type Finding } from '../../types/report.js';
import type { Scanner, ScanContext } from '../../types/scanner.js';
import type { ApiConfig } from '../../config/schema.js';
import { parseApiFlow } from './parser.js';
import type { ApiFlow } from './parser.js';
import { runApiEndpoint } from './runner.js';
import { generateOpenApiFlows } from './openapi-parser.js';

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

    if ((!config.flowFiles || config.flowFiles.length === 0) && !config.openapiSpec) {
      logger.warn('No API flow files or OpenAPI spec configured.');
      return this.buildResult(true, findings, findingsBySeverity, startTime);
    }

    try {
      const flowsToRun: ApiFlow[] = [];

      for (const flowFile of config.flowFiles || []) {
        const fullPath = resolve(rootDir, flowFile);
        const flow = parseApiFlow(fullPath);
        if (flow) flowsToRun.push(flow);
      }

      if (config.openapiSpec) {
        const fullPath = resolve(rootDir, config.openapiSpec);
        const openApiFlow = generateOpenApiFlows(fullPath);
        if (openApiFlow) {
          logger.warn('Auth-aware fuzzing (v1.6.0) is not yet implemented. --openapi flows will run unauthenticated and may return uniform 401s on secure endpoints.');
          flowsToRun.push(openApiFlow);
        }
      }

      for (let flow of flowsToRun) {

        // Interpolate variables
        const variables = {
          ...process.env,
          ...config.variables,
          ...flow.variables,
        };
        const json = JSON.stringify(flow);
        const interpolated = json.replace(/\$\{([^}]+)\}/g, (match, varName) => {
          const value = variables[varName];
          if (value === undefined) {
            logger.warn(`Unresolved variable in API flow: ${match}`);
            return match;
          }
          return value.replace(/"/g, '\\"');
        });
        flow = JSON.parse(interpolated);
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

      // Determine pass/fail using severity threshold (consistent with other modules)
      const threshold = config.severityThreshold ?? context.severityThreshold;
      const thresholdWeight = SEVERITY_WEIGHT[threshold as Severity] ?? SEVERITY_WEIGHT[Severity.HIGH];
      const hasFailingFindings = findings.some(
        (f) => SEVERITY_WEIGHT[f.severity] >= thresholdWeight,
      );
      const passed = !hasFailingFindings;

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
