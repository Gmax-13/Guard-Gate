/**
 * SBOM Generator
 *
 * Generates a CycloneDX 1.5 SBOM document from parsed dependencies.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import type { Dependency, SbomDocument, SbomComponent } from './types.js';
import { logger } from '../../utils/logger.js';

/** Map ecosystem names to PURL types */
const PURL_TYPES: Record<string, string> = {
  npm: 'npm',
  pypi: 'pypi',
  go: 'golang',
  maven: 'maven',
  cargo: 'cargo',
};

/**
 * Generate a Package URL (PURL) for a dependency.
 */
function generatePurl(dep: Dependency): string {
  const type = PURL_TYPES[dep.ecosystem] ?? dep.ecosystem;

  if (dep.ecosystem === 'maven') {
    // Maven uses group:artifact format
    const parts = dep.name.split(':');
    if (parts.length === 2) {
      return `pkg:${type}/${parts[0]}/${parts[1]}@${dep.version}`;
    }
  }

  return `pkg:${type}/${dep.name}@${dep.version}`;
}

/**
 * Generate a CycloneDX 1.5 SBOM document.
 */
export function generateSbom(dependencies: Dependency[]): SbomDocument {
  const components: SbomComponent[] = dependencies.map((dep) => ({
    type: 'library',
    name: dep.name,
    version: dep.version,
    purl: generatePurl(dep),
    scope: dep.isDirect ? 'required' : undefined,
  }));

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          name: 'guardgate',
          version: '0.1.0',
        },
      ],
    },
    components,
  };
}

/**
 * Write an SBOM document to disk.
 */
export function writeSbom(sbom: SbomDocument, outputDir: string): string {
  const filePath = join(outputDir, 'guardgate-sbom.json');

  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify(sbom, null, 2), 'utf-8');
    logger.info(`SBOM written to ${filePath}`);
    return filePath;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to write SBOM: ${message}`);
    throw err;
  }
}
