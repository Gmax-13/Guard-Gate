/**
 * Unified JSON Report Schema
 *
 * This is the central contract for GuardGate. All scanner modules produce
 * `ModuleResult` objects that are aggregated into a `ScanReport`.
 * The dashboard, CI action, and CLI formatters all consume this schema.
 */

/** Severity levels for findings, ordered from lowest to highest impact. */
export enum Severity {
  INFO = 'info',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

/** Numeric severity weights for threshold comparisons. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  [Severity.INFO]: 0,
  [Severity.LOW]: 1,
  [Severity.MEDIUM]: 2,
  [Severity.HIGH]: 3,
  [Severity.CRITICAL]: 4,
};

/** The scanner module that produced the finding. */
export type ModuleName = 'secrets' | 'sbom' | 'e2e' | 'api' | 'code';

/** Evidence attached to a finding (screenshots, request/response snippets, etc.) */
export interface Evidence {
  /** Type of evidence (e.g., 'screenshot', 'request', 'response', 'snippet') */
  type: string;
  /** Human-readable label */
  label: string;
  /** The evidence data — could be a file path (screenshot), text snippet, or serialized object */
  data: string;
}

/** A single security finding from any scanner module. */
export interface Finding {
  /** Unique identifier for this finding within the run */
  id: string;
  /** Which module produced this finding */
  module: ModuleName;
  /** Rule or check that triggered this finding (e.g., 'aws-access-key', 'CVE-2021-44228', 'authBypassCheck') */
  ruleId: string;
  /** Human-readable rule/check name */
  ruleName: string;
  /** Severity of the finding */
  severity: Severity;
  /** Human-readable description of what was found */
  message: string;
  /** File path where the finding was detected (if applicable) */
  filePath?: string;
  /** Line number in the file (if applicable) */
  lineNumber?: number;
  /** Git commit hash (for secrets found in history) */
  commitHash?: string;
  /** Evidence supporting the finding */
  evidence?: Evidence[];
  /** Module-specific metadata (e.g., CVE details, cookie attributes, etc.) */
  metadata?: Record<string, unknown>;
  /** Stable fingerprint for deduplication across runs (SHA-256 hash) */
  fingerprint?: string;
  /** Baseline status: 'new' = introduced since baseline, 'baseline' = pre-existing */
  baselineStatus?: 'new' | 'baseline';
  /** AI-generated unified diff patch to fix the vulnerability */
  remediationPatch?: string;
  /** AI-generated explanation of the fix */
  remediationExplanation?: string;
}

/** Result from a single scanner module. */
export interface ModuleResult {
  /** Which module produced this result */
  module: ModuleName;
  /** Whether the module passed its threshold (no findings above threshold severity) */
  passed: boolean;
  /** Total number of findings */
  findingCount: number;
  /** Breakdown of findings by severity */
  findingsBySeverity: Record<Severity, number>;
  /** All findings from this module */
  findings: Finding[];
  /** Module execution duration in milliseconds */
  durationMs: number;
  /** Optional error if the module failed to run */
  error?: string;
}

/** Summary of the entire scan run. */
export interface ScanSummary {
  /** Overall pass/fail — true only if ALL modules passed */
  passed: boolean;
  /** Total findings across all modules */
  totalFindings: number;
  /** Breakdown by severity across all modules */
  findingsBySeverity: Record<Severity, number>;
  /** Per-module pass/fail status */
  moduleStatus: Record<ModuleName, boolean>;
}

/** The complete scan report — the top-level output of a GuardGate scan. */
export interface ScanReport {
  /** Report format version */
  version: string;
  /** Timestamp of the scan (ISO 8601) */
  timestamp: string;
  /** Repository information */
  repository: {
    /** Repository root path or remote URL */
    url: string;
    /** Current branch */
    branch: string;
    /** Current commit SHA */
    commitSha: string;
  };
  /** High-level summary */
  summary: ScanSummary;
  /** Results from each scanner module that was run */
  modules: ModuleResult[];
  /** Total scan duration in milliseconds */
  durationMs: number;
  /** Baseline comparison metadata (present only when --baseline is used) */
  baseline?: {
    /** The git ref used as the baseline */
    ref: string;
    /** Number of findings introduced since the baseline */
    newFindings: number;
    /** Number of pre-existing findings suppressed from pass/fail */
    baselineFindings: number;
  };
}
