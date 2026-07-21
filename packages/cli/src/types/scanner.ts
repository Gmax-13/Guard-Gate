/**
 * Scanner Interface
 *
 * Every scanner module (secrets, sbom, e2e) must implement this interface.
 * This is the plug-in point for the CLI — scanners are independently runnable
 * and produce a uniform ModuleResult.
 */

import type { ModuleResult, ModuleName } from './report.js';

/** Configuration context passed to each scanner at runtime. */
export interface ScanContext {
  /** Absolute path to the repository/project root being scanned */
  rootDir: string;
  /** The resolved GuardGate configuration */
  config: Record<string, unknown>;
  /** Severity threshold — findings at or above this severity cause a fail */
  severityThreshold: string;
}

/** The interface that all scanner modules must implement. */
export interface Scanner {
  /** Unique name identifying this scanner module */
  readonly name: ModuleName;

  /** Human-readable display name */
  readonly displayName: string;

  /**
   * Run the scan and return results.
   * Must not throw — errors should be captured in ModuleResult.error.
   */
  scan(context: ScanContext): Promise<ModuleResult>;
}
