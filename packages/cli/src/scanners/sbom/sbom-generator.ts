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
          version: '1.2.3',
        },
      ],
    },
    components,
  };
}

/**
 * Write a CycloneDX SBOM document to disk.
 */
export function writeSbom(sbom: SbomDocument, outputDir: string): string {
  const filePath = join(outputDir, 'guardgate-sbom.json');

  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify(sbom, null, 2), 'utf-8');
    logger.info(`CycloneDX SBOM written to ${filePath}`);
    return filePath;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to write CycloneDX SBOM: ${message}`);
    throw err;
  }
}

/**
 * Generate an SPDX 2.3 SBOM document.
 */
export function generateSpdxSbom(dependencies: Dependency[]): any {
  const packages = dependencies.map((dep, index) => {
    const spdxId = `SPDXRef-Package-${index + 1}`;
    return {
      name: dep.name,
      SPDXID: spdxId,
      versionInfo: dep.version,
      downloadLocation: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: generatePurl(dep)
        }
      ]
    };
  });

  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "GuardGate-SBOM",
    documentNamespace: `http://spdx.org/spdxdocs/guardgate-sbom-${Date.now()}`,
    creationInfo: {
      creators: ["Tool: GuardGate-1.2.3"],
      created: new Date().toISOString()
    },
    packages,
    relationships: packages.map(pkg => ({
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: pkg.SPDXID
    }))
  };
}

/**
 * Write an SPDX 2.3 SBOM document to disk.
 */
export function writeSpdxSbom(sbom: any, outputDir: string): string {
  const filePath = join(outputDir, 'guardgate-sbom.spdx.json');

  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify(sbom, null, 2), 'utf-8');
    logger.info(`SPDX SBOM written to ${filePath}`);
    return filePath;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to write SPDX SBOM: ${message}`);
    throw err;
  }
}
