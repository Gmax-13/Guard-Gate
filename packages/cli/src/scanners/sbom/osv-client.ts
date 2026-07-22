/**
 * OSV.dev API Client
 *
 * Queries the OSV.dev vulnerability database for known CVEs.
 * Free, no API key required. Supports batch queries.
 * https://osv.dev/docs/
 */

import { logger } from '../../utils/logger.js';
import type { Dependency } from './types.js';

const OSV_API_BASE = 'https://api.osv.dev/v1';

/** OSV ecosystem name mapping */
const ECOSYSTEM_MAP: Record<string, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  go: 'Go',
  maven: 'Maven',
  cargo: 'crates.io',
};

/** Raw vulnerability from OSV API */
interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package?: {
      ecosystem: string;
      name: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
  references?: Array<{
    type: string;
    url: string;
  }>;
}

/** Vulnerability result for a single dependency */
export interface OsvResult {
  dependency: Dependency;
  vulnerabilities: OsvVulnerability[];
}

/**
 * Query OSV.dev for vulnerabilities affecting a single package.
 */
export async function queryOsv(dep: Dependency): Promise<OsvVulnerability[]> {
  const ecosystem = ECOSYSTEM_MAP[dep.ecosystem] ?? dep.ecosystem;

  try {
    const response = await fetch(`${OSV_API_BASE}/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: {
          name: dep.name,
          ecosystem,
        },
        version: dep.version,
      }),
    });

    if (!response.ok) {
      throw new Error(`OSV query failed for ${dep.name}@${dep.version}: HTTP ${response.status}`);
    }

    const data = (await response.json()) as { vulns?: OsvVulnerability[] };
    return data.vulns ?? [];
  } catch (err) {
    throw new Error(`OSV query error for ${dep.name}@${dep.version}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Batch query OSV.dev for vulnerabilities.
 * Uses the batch endpoint for efficiency.
 */
export async function batchQueryOsv(deps: Dependency[]): Promise<OsvResult[]> {
  const results: OsvResult[] = [];

  // OSV batch API accepts up to 1000 queries
  const BATCH_SIZE = 1000;

  for (let i = 0; i < deps.length; i += BATCH_SIZE) {
    const batch = deps.slice(i, i + BATCH_SIZE);
    const queries = batch.map((dep) => ({
      package: {
        name: dep.name,
        ecosystem: ECOSYSTEM_MAP[dep.ecosystem] ?? dep.ecosystem,
      },
      version: dep.version,
    }));

    try {
      const response = await fetch(`${OSV_API_BASE}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
      });

      if (!response.ok) {
        throw new Error(`OSV batch query failed: HTTP ${response.status}`);
      }

      const data = (await response.json()) as {
        results: Array<{ vulns?: OsvVulnerability[] }>;
      };

      for (let j = 0; j < batch.length; j++) {
        results.push({
          dependency: batch[j],
          vulnerabilities: data.results[j]?.vulns ?? [],
        });
      }
    } catch (err) {
      logger.warn(`OSV batch query error: ${err instanceof Error ? err.message : String(err)}. Falling back to individual queries...`);
      // Fall back to individual queries
      for (const dep of batch) {
        const vulns = await queryOsv(dep);
        results.push({ dependency: dep, vulnerabilities: vulns });
      }
    }
  }

  return results;
}

/**
 * Extract a CVE ID from OSV aliases.
 */
export function extractCveId(vuln: OsvVulnerability): string {
  const cve = vuln.aliases?.find((a) => a.startsWith('CVE-'));
  return cve ?? vuln.id;
}

/**
 * Extract CVSS score from OSV severity data.
 */
export function extractCvssScore(vuln: OsvVulnerability): number | undefined {
  if (!vuln.severity) return undefined;

  for (const sev of vuln.severity) {
    if (sev.type === 'CVSS_V3') {
      // CVSS vector string — extract the score
      const scoreMatch = sev.score.match(/^CVSS:3\.\d+\/.*$/);
      if (scoreMatch) {
        // Parse the CVSS score from the vector — simplified
        // In practice, you'd use a CVSS calculator
        return undefined; // Will use severity rating instead
      }
      // If it's a plain number
      const num = parseFloat(sev.score);
      if (!isNaN(num)) return num;
    }
  }

  return undefined;
}

/**
 * Derive severity rating from CVSS score.
 */
export function deriveSeverity(cvssScore?: number): string {
  if (cvssScore === undefined) return 'medium';
  if (cvssScore >= 9.0) return 'critical';
  if (cvssScore >= 7.0) return 'high';
  if (cvssScore >= 4.0) return 'medium';
  if (cvssScore >= 0.1) return 'low';
  return 'info';
}
