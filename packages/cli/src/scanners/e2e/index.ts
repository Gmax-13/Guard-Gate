/**
 * E2E Scanner Module
 *
 * Entry point for the security-focused E2E testing module.
 * Implements the Scanner interface.
 * Orchestrates flow file loading, plugin registration, and flow execution.
 */

import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Scanner, ScanContext } from '../../types/scanner.js';
import type { ModuleResult, Finding } from '../../types/report.js';
import { Severity, SEVERITY_WEIGHT } from '../../types/report.js';
import type { GuardGateConfig } from '../../config/schema.js';
import { parseFlowFile, interpolateVariables } from './flow-parser.js';
import { runFlow, type FlowRunnerOptions } from './flow-runner.js';
import { loadBuiltinPlugins, pluginRegistry } from './plugin-registry.js';
import { logger } from '../../utils/logger.js';

export class E2eScanner implements Scanner {
  readonly name = 'e2e' as const;
  readonly displayName = 'Security E2E Testing';

  async scan(context: ScanContext): Promise<ModuleResult> {
    const startTime = Date.now();
    const config = context.config as unknown as GuardGateConfig;
    const e2eConfig = config.e2e;

    if (!e2eConfig.targetUrl && e2eConfig.flowFiles.length === 0 && !e2eConfig.flowDir) {
      logger.warn('No target URL or flow files configured for E2E testing');
      return this.emptyResult(Date.now() - startTime);
    }

    try {
      // Load plugins
      await loadBuiltinPlugins();
      const plugins = pluginRegistry.getFiltered(e2eConfig.plugins);
      logger.info(`Loaded ${plugins.length} assertion plugins`);

      // Discover flow files
      const flowFiles = this.discoverFlowFiles(context.rootDir, e2eConfig);

      if (flowFiles.length === 0) {
        logger.warn('No flow files found for E2E testing');
        return this.emptyResult(Date.now() - startTime);
      }

      logger.info(`Found ${flowFiles.length} flow file(s)`);

      // Runner options
      const runnerOptions: FlowRunnerOptions = {
        browser: e2eConfig.browser,
        headless: e2eConfig.headless,
        stepTimeout: e2eConfig.stepTimeout,
        screenshotOnFailure: e2eConfig.screenshotOnFailure,
        outputDir: config.outputDir,
      };

      // Execute each flow
      const allFindings: Finding[] = [];

      for (const flowFile of flowFiles) {
        logger.info(`Running flow: ${flowFile}`);

        try {
          // Parse and interpolate
          let flow = parseFlowFile(flowFile);

          // Override targetUrl from config if not set in the flow
          if (e2eConfig.targetUrl && (!flow.targetUrl || flow.targetUrl.includes('${TARGET_URL}'))) {
            flow = { ...flow, targetUrl: e2eConfig.targetUrl };
          }

          flow = interpolateVariables(flow, e2eConfig.variables);

          // Resolve per-flow plugins
          const currentPlugins = flow.plugins && flow.plugins.length > 0
            ? pluginRegistry.getFiltered(flow.plugins)
            : plugins;

          // Run the flow
          const result = await runFlow(flow, currentPlugins, runnerOptions);

          // Convert assertion results to findings
          for (const assertion of result.assertionResults) {
            if (!assertion.passed) {
              allFindings.push({
                id: `e2e-${allFindings.length}`,
                module: 'e2e',
                ruleId: assertion.checkId,
                ruleName: assertion.checkName,
                severity: assertion.severity as Severity,
                message: assertion.message,
                evidence: assertion.evidence,
                metadata: {
                  flowName: result.flowName,
                  pluginName: assertion.pluginName,
                  pluginType: assertion.pluginType,
                  ...assertion.metadata,
                },
              });
            }
          }

          // Report step failure as a finding too
          if (!result.stepsCompleted && result.stepError) {
            allFindings.push({
              id: `e2e-step-error-${allFindings.length}`,
              module: 'e2e',
              ruleId: 'flow-execution-error',
              ruleName: 'Flow Execution Error',
              severity: Severity.HIGH,
              message: result.stepError,
              metadata: { flowName: result.flowName },
            });
          }
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          logger.error(`Failed to run flow ${flowFile}: ${message}`);
          allFindings.push({
            id: `e2e-flow-error-${allFindings.length}`,
            module: 'e2e',
            ruleId: 'flow-parse-error',
            ruleName: 'Flow Parse Error',
            severity: Severity.HIGH,
            message: `Failed to parse/run flow: ${message}`,
            filePath: flowFile,
          });
        }
      }

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

      // Determine pass/fail
      const thresholdWeight =
        SEVERITY_WEIGHT[context.severityThreshold as Severity] ??
        SEVERITY_WEIGHT[Severity.HIGH];
      const hasFailingFindings = allFindings.some(
        (f) => SEVERITY_WEIGHT[f.severity] >= thresholdWeight,
      );

      return {
        module: 'e2e',
        passed: !hasFailingFindings,
        findingCount: allFindings.length,
        findingsBySeverity,
        findings: allFindings,
        durationMs: Date.now() - startTime,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`E2E scanner failed: ${message}`);

      return {
        module: 'e2e',
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

  /**
   * Discover flow files from config.
   */
  private discoverFlowFiles(rootDir: string, e2eConfig: GuardGateConfig['e2e']): string[] {
    const files: string[] = [];

    // Explicit flow files from config
    for (const file of e2eConfig.flowFiles) {
      const fullPath = resolve(rootDir, file);
      if (existsSync(fullPath)) {
        files.push(fullPath);
      } else {
        logger.warn(`Flow file not found: ${fullPath}`);
      }
    }

    // Flow directory
    if (e2eConfig.flowDir) {
      const dirPath = resolve(rootDir, e2eConfig.flowDir);
      if (existsSync(dirPath)) {
        const dirFiles = readdirSync(dirPath)
          .filter((f) => f.endsWith('.yml') || f.endsWith('.yaml') || f.endsWith('.json'))
          .map((f) => join(dirPath, f));
        files.push(...dirFiles);
      } else {
        logger.warn(`Flow directory not found: ${dirPath}`);
      }
    }

    return files;
  }

  private emptyResult(durationMs: number): ModuleResult {
    return {
      module: 'e2e',
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
