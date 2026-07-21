/**
 * SBOM Scanner Types
 *
 * Shared types for the SBOM/dependency vulnerability scanner.
 */

/** A single dependency in the project's dependency tree. */
export interface Dependency {
  /** Package name */
  name: string;
  /** Installed version */
  version: string;
  /** Ecosystem/package manager (e.g., 'npm', 'pypi', 'go', 'maven', 'cargo') */
  ecosystem: string;
  /** Whether this is a direct dependency (vs transitive) */
  isDirect: boolean;
  /** Parent package (for transitive deps) */
  parent?: string;
}

/** A known vulnerability matched to a dependency. */
export interface VulnerabilityMatch {
  /** The affected dependency */
  dependency: Dependency;
  /** CVE identifier (e.g., 'CVE-2021-44228') */
  cveId: string;
  /** OSV identifier */
  osvId: string;
  /** Human-readable summary */
  summary: string;
  /** Detailed description */
  details?: string;
  /** CVSS score (0-10) */
  cvssScore?: number;
  /** Severity rating derived from CVSS */
  severity: string;
  /** The version range that is affected */
  affectedRange: string;
  /** The version that fixes the vulnerability (if known) */
  fixedVersion?: string;
  /** References/URLs for more info */
  references: string[];
}

/** Result from an ecosystem parser. */
export interface ParseResult {
  /** The ecosystem that was parsed */
  ecosystem: string;
  /** All dependencies found */
  dependencies: Dependency[];
  /** File that was parsed */
  sourceFile: string;
}

/** CycloneDX SBOM component (simplified). */
export interface SbomComponent {
  type: 'library';
  name: string;
  version: string;
  purl: string;
  scope?: 'required' | 'optional' | 'excluded';
}

/** CycloneDX SBOM document (simplified). */
export interface SbomDocument {
  bomFormat: 'CycloneDX';
  specVersion: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ name: string; version: string }>;
  };
  components: SbomComponent[];
}
