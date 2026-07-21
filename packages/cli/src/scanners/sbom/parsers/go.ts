/**
 * Go Ecosystem Parser
 *
 * Parses go.sum and go.mod for Go module dependencies.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { EcosystemParser } from '../parser-interface.js';
import type { ParseResult, Dependency } from '../types.js';
import { logger } from '../../../utils/logger.js';

export class GoParser implements EcosystemParser {
  readonly ecosystem = 'go';
  readonly displayName = 'Go Modules';

  detect(rootDir: string): string | null {
    const goSum = join(rootDir, 'go.sum');
    if (existsSync(goSum)) return goSum;

    const goMod = join(rootDir, 'go.mod');
    if (existsSync(goMod)) return goMod;

    return null;
  }

  async parse(rootDir: string): Promise<ParseResult> {
    const directDeps = this.parseGoMod(rootDir);

    // Try go.sum first (has all transitive deps)
    const goSum = join(rootDir, 'go.sum');
    if (existsSync(goSum)) {
      return this.parseGoSum(goSum, directDeps);
    }

    // Fall back to go.mod
    const goMod = join(rootDir, 'go.mod');
    if (existsSync(goMod)) {
      const dependencies = Array.from(directDeps.values());
      return { ecosystem: 'go', dependencies, sourceFile: goMod };
    }

    return { ecosystem: 'go', dependencies: [], sourceFile: '' };
  }

  private parseGoMod(rootDir: string): Map<string, Dependency> {
    const deps = new Map<string, Dependency>();
    const goMod = join(rootDir, 'go.mod');

    if (!existsSync(goMod)) return deps;

    try {
      const content = readFileSync(goMod, 'utf-8');
      let inRequireBlock = false;

      for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();

        if (line === 'require (') {
          inRequireBlock = true;
          continue;
        }
        if (line === ')') {
          inRequireBlock = false;
          continue;
        }

        // Single-line require: require github.com/pkg/errors v0.9.1
        const singleMatch = line.match(/^require\s+(\S+)\s+(\S+)/);
        if (singleMatch) {
          deps.set(singleMatch[1], {
            name: singleMatch[1],
            version: singleMatch[2],
            ecosystem: 'go',
            isDirect: true,
          });
          continue;
        }

        // Block require line
        if (inRequireBlock) {
          const blockMatch = line.match(/^(\S+)\s+(\S+)/);
          if (blockMatch && !blockMatch[1].startsWith('//')) {
            deps.set(blockMatch[1], {
              name: blockMatch[1],
              version: blockMatch[2],
              ecosystem: 'go',
              isDirect: !line.includes('// indirect'),
            });
          }
        }
      }
    } catch (err) {
      logger.warn(`Failed to parse go.mod: ${err}`);
    }

    return deps;
  }

  private parseGoSum(sumPath: string, directDeps: Map<string, Dependency>): ParseResult {
    try {
      const content = readFileSync(sumPath, 'utf-8');
      const seen = new Set<string>();
      const dependencies: Dependency[] = [];

      for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();
        if (!line) continue;

        // Format: module version hash
        // e.g., github.com/pkg/errors v0.9.1 h1:abc123=
        const match = line.match(/^(\S+)\s+(v\S+?)(?:\/go\.mod)?\s+/);
        if (match) {
          const name = match[1];
          const version = match[2];
          const key = `${name}@${version}`;

          if (!seen.has(key)) {
            seen.add(key);
            dependencies.push({
              name,
              version,
              ecosystem: 'go',
              isDirect: directDeps.has(name),
            });
          }
        }
      }

      logger.debug(`go: found ${dependencies.length} dependencies from go.sum`);
      return { ecosystem: 'go', dependencies, sourceFile: sumPath };
    } catch (err) {
      logger.warn(`Failed to parse go.sum: ${err}`);
      return { ecosystem: 'go', dependencies: [], sourceFile: sumPath };
    }
  }
}
