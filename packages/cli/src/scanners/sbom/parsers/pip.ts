/**
 * pip Ecosystem Parser
 *
 * Parses requirements.txt and Pipfile.lock for Python dependencies.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { EcosystemParser } from '../parser-interface.js';
import type { ParseResult, Dependency } from '../types.js';
import { logger } from '../../../utils/logger.js';

export class PipParser implements EcosystemParser {
  readonly ecosystem = 'pypi';
  readonly displayName = 'pip (Python)';

  detect(rootDir: string): string | null {
    const pipfileLock = join(rootDir, 'Pipfile.lock');
    if (existsSync(pipfileLock)) return pipfileLock;

    const requirements = join(rootDir, 'requirements.txt');
    if (existsSync(requirements)) return requirements;

    const poetryLock = join(rootDir, 'poetry.lock');
    if (existsSync(poetryLock)) return poetryLock;

    return null;
  }

  async parse(rootDir: string): Promise<ParseResult> {
    // Try Pipfile.lock first (has transitive deps)
    const pipfileLock = join(rootDir, 'Pipfile.lock');
    if (existsSync(pipfileLock)) {
      return this.parsePipfileLock(pipfileLock);
    }

    // Fall back to requirements.txt
    const requirements = join(rootDir, 'requirements.txt');
    if (existsSync(requirements)) {
      return this.parseRequirementsTxt(requirements);
    }

    return { ecosystem: 'pypi', dependencies: [], sourceFile: '' };
  }

  private parsePipfileLock(lockPath: string): ParseResult {
    try {
      const content = JSON.parse(readFileSync(lockPath, 'utf-8'));
      const dependencies: Dependency[] = [];

      // Parse 'default' (production) dependencies
      if (content.default) {
        for (const [name, info] of Object.entries(content.default)) {
          const pkg = info as Record<string, unknown>;
          const version = ((pkg.version as string) ?? '').replace(/^==/, '');
          if (name && version) {
            dependencies.push({
              name,
              version,
              ecosystem: 'pypi',
              isDirect: true, // Pipfile.lock doesn't clearly distinguish, treat all as direct
            });
          }
        }
      }

      // Parse 'develop' dependencies
      if (content.develop) {
        for (const [name, info] of Object.entries(content.develop)) {
          const pkg = info as Record<string, unknown>;
          const version = ((pkg.version as string) ?? '').replace(/^==/, '');
          if (name && version) {
            dependencies.push({
              name,
              version,
              ecosystem: 'pypi',
              isDirect: true,
            });
          }
        }
      }

      logger.debug(`pip: found ${dependencies.length} dependencies from Pipfile.lock`);
      return { ecosystem: 'pypi', dependencies, sourceFile: lockPath };
    } catch (err) {
      logger.warn(`Failed to parse Pipfile.lock: ${err}`);
      return { ecosystem: 'pypi', dependencies: [], sourceFile: lockPath };
    }
  }

  private parseRequirementsTxt(reqPath: string): ParseResult {
    try {
      const content = readFileSync(reqPath, 'utf-8');
      const dependencies: Dependency[] = [];

      for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();

        // Skip comments, empty lines, and option lines
        if (!line || line.startsWith('#') || line.startsWith('-')) continue;

        // Parse: package==version, package>=version, package~=version, etc.
        const match = line.match(/^([A-Za-z0-9_.-]+)\s*(?:[=~!<>]=*\s*([A-Za-z0-9_.*-]+))?/);
        if (match) {
          const name = match[1].toLowerCase();
          const version = match[2] ?? 'unknown';
          dependencies.push({
            name,
            version,
            ecosystem: 'pypi',
            isDirect: true,
          });
        }
      }

      logger.debug(`pip: found ${dependencies.length} dependencies from requirements.txt`);
      return { ecosystem: 'pypi', dependencies, sourceFile: reqPath };
    } catch (err) {
      logger.warn(`Failed to parse requirements.txt: ${err}`);
      return { ecosystem: 'pypi', dependencies: [], sourceFile: reqPath };
    }
  }
}
