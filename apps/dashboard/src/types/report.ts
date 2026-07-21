/**
 * Unified JSON Report Schema (Local Dashboard Copy)
 */

export enum Severity {
  INFO = 'info',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export type ModuleName = 'secrets' | 'sbom' | 'e2e';

export interface Evidence {
  type: string;
  label: string;
  data: string;
}

export interface Finding {
  id: string;
  module: ModuleName;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  message: string;
  filePath?: string;
  lineNumber?: number;
  commitHash?: string;
  evidence?: Evidence[];
  metadata?: Record<string, unknown>;
}

export interface ModuleResult {
  module: ModuleName;
  passed: boolean;
  findingCount: number;
  findingsBySeverity: Record<Severity, number>;
  findings: Finding[];
  durationMs: number;
  error?: string;
}

export interface ScanSummary {
  passed: boolean;
  totalFindings: number;
  findingsBySeverity: Record<Severity, number>;
  moduleStatus: Record<ModuleName, boolean>;
}

export interface ScanReport {
  version: string;
  timestamp: string;
  repository: {
    url: string;
    branch: string;
    commitSha: string;
  };
  summary: ScanSummary;
  modules: ModuleResult[];
  durationMs: number;
}
