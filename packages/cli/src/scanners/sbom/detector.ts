/**
 * Ecosystem Detector
 *
 * Auto-detects which package ecosystems are present in a project.
 */

import type { EcosystemParser } from './parser-interface.js';
import { NpmParser } from './parsers/npm.js';
import { PipParser } from './parsers/pip.js';
import { GoParser } from './parsers/go.js';
import { MavenParser } from './parsers/maven.js';
import { CargoParser } from './parsers/cargo.js';
import { logger } from '../../utils/logger.js';

/** All available ecosystem parsers. */
const ALL_PARSERS: EcosystemParser[] = [
  new NpmParser(),
  new PipParser(),
  new GoParser(),
  new MavenParser(),
  new CargoParser(),
];

/**
 * Detect which ecosystems are present in the given directory.
 *
 * @param rootDir - Project root directory
 * @param filterEcosystems - Optional list of ecosystem names to limit to
 * @returns Array of parsers whose ecosystem was detected
 */
export function detectEcosystems(
  rootDir: string,
  filterEcosystems: string[] = [],
): EcosystemParser[] {
  const detected: EcosystemParser[] = [];

  for (const parser of ALL_PARSERS) {
    // If a filter is set, only check those ecosystems
    if (filterEcosystems.length > 0 && !filterEcosystems.includes(parser.ecosystem)) {
      continue;
    }

    const manifestPath = parser.detect(rootDir);
    if (manifestPath) {
      logger.info(`Detected ${parser.displayName} (${manifestPath})`);
      detected.push(parser);
    }
  }

  return detected;
}
