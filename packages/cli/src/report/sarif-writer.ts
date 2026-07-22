/**
 * SARIF Report Writer
 *
 * Converts a GuardGate ScanReport into SARIF v2.1.0 format for integration
 * with GitHub Code Scanning, GitLab SAST, Azure DevOps, and VS Code SARIF Viewer.
 *
 * SARIF Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname, resolve, isAbsolute } from 'node:path';
import type { ScanReport, ModuleResult, Finding } from '../types/report.js';
import { Severity } from '../types/report.js';
import { logger } from '../utils/logger.js';

// ─── SARIF Type Definitions ──────────────────────────────────────────────

/** SARIF v2.1.0 severity level */
type SarifLevel = 'error' | 'warning' | 'note' | 'none';

/** SARIF reporting descriptor (rule definition) */
interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  helpUri?: string;
  properties?: Record<string, unknown>;
}

/** SARIF physical location */
interface SarifPhysicalLocation {
  artifactLocation: {
    uri: string;
    uriBaseId?: string;
  };
  region?: {
    startLine: number;
    startColumn?: number;
  };
}

/** SARIF result (individual finding) */
interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations?: Array<{ physicalLocation: SarifPhysicalLocation }>;
  partialFingerprints?: Record<string, string>;
  fingerprints?: Record<string, string>;
  baselineState?: 'new' | 'unchanged' | 'updated' | 'absent';
  properties?: Record<string, unknown>;
}

/** SARIF version control details */
interface SarifVersionControlDetails {
  repositoryUri: string;
  branch?: string;
  revisionId?: string;
}

/** SARIF run (one per scanner module) */
interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      semanticVersion: string;
      informationUri: string;
      rules: SarifReportingDescriptor[];
    };
  };
  results: SarifResult[];
  versionControlProvenance?: SarifVersionControlDetails[];
  invocations?: Array<{
    executionSuccessful: boolean;
    toolExecutionNotifications?: Array<{
      level: SarifLevel;
      message: { text: string };
    }>;
  }>;
}

/** Top-level SARIF log */
interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

// ─── Mapping Helpers ─────────────────────────────────────────────────────

/** Map GuardGate severity to SARIF level */
function severityToSarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case Severity.CRITICAL:
      return 'error';
    case Severity.HIGH:
      return 'error';
    case Severity.MEDIUM:
      return 'warning';
    case Severity.LOW:
      return 'note';
    case Severity.INFO:
      return 'note';
    default:
      return 'warning';
  }
}

/**
 * Convert a file path to a SARIF-compatible URI.
 * SARIF expects forward-slash URIs relative to the repo root.
 */
function toSarifUri(filePath: string): string {
  // Normalize to forward slashes
  let normalized = filePath.replace(/\\/g, '/');

  // Strip leading ./ if present
  if (normalized.startsWith('./')) {
    normalized = normalized.substring(2);
  }

  // If it's an absolute path, just use the filename/relative portion
  // SARIF consumers typically expect relative paths with %srcroot%
  if (isAbsolute(filePath)) {
    // Best-effort: use path as-is with forward slashes
    return normalized;
  }

  return normalized;
}

/**
 * Build a human-readable display name for a scanner module.
 */
function moduleDisplayName(moduleName: string): string {
  const names: Record<string, string> = {
    secrets: 'Secrets Scanner',
    sbom: 'SBOM / Dependency Scanner',
    code: 'Code Scanner',
    api: 'API Fuzzer',
    e2e: 'E2E Security Tests',
  };
  return names[moduleName] ?? moduleName;
}

// ─── SARIF Conversion ────────────────────────────────────────────────────

/**
 * Convert a single ModuleResult into a SARIF run.
 */
function moduleResultToSarifRun(
  moduleResult: ModuleResult,
  report: ScanReport,
): SarifRun {
  // Collect unique rules from findings
  const ruleMap = new Map<string, SarifReportingDescriptor>();
  const ruleIndexMap = new Map<string, number>();

  for (const finding of moduleResult.findings) {
    if (!ruleMap.has(finding.ruleId)) {
      const index = ruleMap.size;
      ruleIndexMap.set(finding.ruleId, index);
      ruleMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleName,
        shortDescription: { text: finding.ruleName },
        defaultConfiguration: {
          level: severityToSarifLevel(finding.severity),
        },
        properties: {
          'guardgate/severity': finding.severity,
          'guardgate/module': finding.module,
        },
      });
    }
  }

  // Convert findings to SARIF results
  const results: SarifResult[] = moduleResult.findings.map((finding) => {
    const result: SarifResult = {
      ruleId: finding.ruleId,
      ruleIndex: ruleIndexMap.get(finding.ruleId) ?? 0,
      level: severityToSarifLevel(finding.severity),
      message: { text: finding.message },
    };

    // Add physical location if file path is available
    if (finding.filePath) {
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: {
              uri: toSarifUri(finding.filePath),
              uriBaseId: '%SRCROOT%',
            },
            ...(finding.lineNumber
              ? { region: { startLine: finding.lineNumber } }
              : {}),
          },
        },
      ];
    }

    // Add partial fingerprints for deduplication
    const partialFingerprints: Record<string, string> = {};
    if (finding.commitHash) {
      partialFingerprints['commitHash'] = finding.commitHash;
    }
    partialFingerprints['findingId'] = finding.id;
    result.partialFingerprints = partialFingerprints;

    // Add baseline stable fingerprint
    if (finding.fingerprint) {
      result.fingerprints = {
        guardgate: finding.fingerprint,
      };
    }

    // Set baseline state
    if (finding.baselineStatus === 'new') {
      result.baselineState = 'new';
    } else if (finding.baselineStatus === 'baseline') {
      result.baselineState = 'unchanged';
    }

    // Add metadata as properties
    if (finding.metadata && Object.keys(finding.metadata).length > 0) {
      result.properties = {
        'guardgate/metadata': finding.metadata,
      };
    }

    return result;
  });

  // Build version control provenance
  const versionControl: SarifVersionControlDetails[] = [];
  if (report.repository.url && report.repository.url !== 'unknown') {
    versionControl.push({
      repositoryUri: report.repository.url,
      branch:
        report.repository.branch !== 'unknown'
          ? report.repository.branch
          : undefined,
      revisionId:
        report.repository.commitSha !== 'unknown'
          ? report.repository.commitSha
          : undefined,
    });
  }

  const run: SarifRun = {
    tool: {
      driver: {
        name: `GuardGate/${moduleResult.module}`,
        version: report.version,
        semanticVersion: report.version,
        informationUri: 'https://github.com/Gmax-13/Guard-Gate',
        rules: Array.from(ruleMap.values()),
      },
    },
    results,
    invocations: [
      {
        executionSuccessful: !moduleResult.error,
        ...(moduleResult.error
          ? {
              toolExecutionNotifications: [
                {
                  level: 'error' as SarifLevel,
                  message: { text: moduleResult.error },
                },
              ],
            }
          : {}),
      },
    ],
  };

  if (versionControl.length > 0) {
    run.versionControlProvenance = versionControl;
  }

  return run;
}

/**
 * Convert a full ScanReport to a SARIF v2.1.0 log.
 */
export function reportToSarif(report: ScanReport): SarifLog {
  const runs: SarifRun[] = report.modules.map((moduleResult) =>
    moduleResultToSarifRun(moduleResult, report),
  );

  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs,
  };
}

/**
 * Write a scan report as a SARIF file to disk.
 *
 * @param report - The scan report to convert and write
 * @param outputDir - The directory to write the SARIF file to
 * @returns The full path to the written file
 */
export function writeSarifReport(
  report: ScanReport,
  outputDir: string,
): string {
  const sarifLog = reportToSarif(report);
  const filename = `guardgate-report-${Date.now()}.sarif`;
  const filePath = join(outputDir, filename);

  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify(sarifLog, null, 2), 'utf-8');
    logger.info(`SARIF report written to ${filePath}`);
    return filePath;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to write SARIF report: ${message}`);
    throw err;
  }
}

/**
 * Print a SARIF report to stdout (for piping).
 */
export function printSarifReport(report: ScanReport): void {
  const sarifLog = reportToSarif(report);
  console.log(JSON.stringify(sarifLog, null, 2));
}
