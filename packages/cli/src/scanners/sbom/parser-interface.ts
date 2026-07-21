/**
 * Ecosystem Parser Interface
 *
 * All ecosystem parsers (npm, pip, go, maven, cargo) implement this interface.
 */

import type { ParseResult } from './types.js';

export interface EcosystemParser {
  /** Ecosystem identifier (e.g., 'npm', 'pypi', 'go', 'maven', 'cargo') */
  readonly ecosystem: string;

  /** Human-readable display name */
  readonly displayName: string;

  /**
   * Check if this ecosystem is present in the given directory.
   * Returns the path to the detected manifest/lock file, or null if not found.
   */
  detect(rootDir: string): string | null;

  /**
   * Parse the dependency manifest/lock file and return all dependencies.
   */
  parse(rootDir: string): Promise<ParseResult>;
}
