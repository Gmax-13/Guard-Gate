/**
 * Cargo Ecosystem Parser
 *
 * Parses Cargo.lock for Rust crate dependencies.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { EcosystemParser } from '../parser-interface.js';
import type { ParseResult, Dependency } from '../types.js';
import { logger } from '../../../utils/logger.js';

export class CargoParser implements EcosystemParser {
  readonly ecosystem = 'cargo';
  readonly displayName = 'Cargo (Rust)';

  detect(rootDir: string): string | null {
    const cargoLock = join(rootDir, 'Cargo.lock');
    if (existsSync(cargoLock)) return cargoLock;

    const cargoToml = join(rootDir, 'Cargo.toml');
    if (existsSync(cargoToml)) return cargoToml;

    return null;
  }

  async parse(rootDir: string): Promise<ParseResult> {
    // Read Cargo.toml for direct deps
    const directDeps = this.parseCargoToml(rootDir);

    // Try Cargo.lock (full transitive tree)
    const cargoLock = join(rootDir, 'Cargo.lock');
    if (existsSync(cargoLock)) {
      return this.parseCargoLock(cargoLock, directDeps);
    }

    // Fall back to Cargo.toml only
    const dependencies = Array.from(directDeps.values());
    const cargoToml = join(rootDir, 'Cargo.toml');
    return { ecosystem: 'cargo', dependencies, sourceFile: cargoToml };
  }

  private parseCargoToml(rootDir: string): Map<string, Dependency> {
    const deps = new Map<string, Dependency>();
    const cargoToml = join(rootDir, 'Cargo.toml');

    if (!existsSync(cargoToml)) return deps;

    try {
      const content = readFileSync(cargoToml, 'utf-8');
      let inDependencies = false;

      for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();

        // Detect section headers
        if (line === '[dependencies]' || line === '[dev-dependencies]' || line === '[build-dependencies]') {
          inDependencies = true;
          continue;
        }
        if (line.startsWith('[') && !line.includes('dependencies')) {
          inDependencies = false;
          continue;
        }

        if (inDependencies && line && !line.startsWith('#')) {
          // name = "version" or name = { version = "..." }
          const simpleMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
          if (simpleMatch) {
            deps.set(simpleMatch[1], {
              name: simpleMatch[1],
              version: simpleMatch[2],
              ecosystem: 'cargo',
              isDirect: true,
            });
            continue;
          }

          const tableMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/);
          if (tableMatch) {
            deps.set(tableMatch[1], {
              name: tableMatch[1],
              version: tableMatch[2],
              ecosystem: 'cargo',
              isDirect: true,
            });
          }
        }
      }
    } catch (err) {
      logger.warn(`Failed to parse Cargo.toml: ${err}`);
    }

    return deps;
  }

  private parseCargoLock(lockPath: string, directDeps: Map<string, Dependency>): ParseResult {
    try {
      const content = readFileSync(lockPath, 'utf-8');
      const dependencies: Dependency[] = [];
      let currentName = '';
      let currentVersion = '';

      for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();

        if (line === '[[package]]') {
          // Save the previous package if we have one
          if (currentName && currentVersion) {
            dependencies.push({
              name: currentName,
              version: currentVersion,
              ecosystem: 'cargo',
              isDirect: directDeps.has(currentName),
            });
          }
          currentName = '';
          currentVersion = '';
          continue;
        }

        const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/);
        if (nameMatch) {
          currentName = nameMatch[1];
          continue;
        }

        const versionMatch = line.match(/^version\s*=\s*"([^"]+)"/);
        if (versionMatch) {
          currentVersion = versionMatch[1];
        }
      }

      // Don't forget the last package
      if (currentName && currentVersion) {
        dependencies.push({
          name: currentName,
          version: currentVersion,
          ecosystem: 'cargo',
          isDirect: directDeps.has(currentName),
        });
      }

      logger.debug(`cargo: found ${dependencies.length} dependencies from Cargo.lock`);
      return { ecosystem: 'cargo', dependencies, sourceFile: lockPath };
    } catch (err) {
      logger.warn(`Failed to parse Cargo.lock: ${err}`);
      return { ecosystem: 'cargo', dependencies: [], sourceFile: lockPath };
    }
  }
}
