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
      // Try parsing CVSS v3 vector string first
      if (sev.score.startsWith('CVSS:')) {
        const score = parseCvssV3Vector(sev.score);
        if (score !== undefined) return score;
      }
      // If it's a plain number
      const num = parseFloat(sev.score);
      if (!isNaN(num)) return num;
    }
  }

  return undefined;
}

/**
 * Parse a CVSS v3.x vector string and compute the base score.
 * Implements the CVSS v3.1 specification base score equations.
 * https://www.first.org/cvss/v3.1/specification-document
 */
function parseCvssV3Vector(vector: string): number | undefined {
  // Extract metric values from vector string
  const metrics = new Map<string, string>();
  const parts = vector.split('/');
  for (const part of parts) {
    const [key, value] = part.split(':');
    if (key && value) {
      metrics.set(key, value);
    }
  }

  // Metric value lookups (per CVSS v3.1 spec)
  const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC: Record<string, number> = { L: 0.77, H: 0.44 };
  const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
  const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.50 };
  const UI: Record<string, number> = { N: 0.85, R: 0.62 };
  const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

  const av = AV[metrics.get('AV') ?? ''];
  const ac = AC[metrics.get('AC') ?? ''];
  const ui = UI[metrics.get('UI') ?? ''];
  const s = metrics.get('S');
  const c = CIA[metrics.get('C') ?? ''];
  const i = CIA[metrics.get('I') ?? ''];
  const a = CIA[metrics.get('A') ?? ''];

  if (av === undefined || ac === undefined || ui === undefined ||
      s === undefined || c === undefined || i === undefined || a === undefined) {
    return undefined;
  }

  const scopeChanged = s === 'C';
  const prLookup = scopeChanged ? PR_CHANGED : PR_UNCHANGED;
  const pr = prLookup[metrics.get('PR') ?? ''];
  if (pr === undefined) return undefined;

  // ISS = 1 - [(1 - C) × (1 - I) × (1 - A)]
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);

  // Impact
  let impact: number;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }

  if (impact <= 0) return 0;

  // Exploitability = 8.22 × AV × AC × PR × UI
  const exploitability = 8.22 * av * ac * pr * ui;

  // Base Score
  let baseScore: number;
  if (scopeChanged) {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    baseScore = Math.min(impact + exploitability, 10);
  }

  // Round up to one decimal place (per spec: "round up")
  return Math.ceil(baseScore * 10) / 10;
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

