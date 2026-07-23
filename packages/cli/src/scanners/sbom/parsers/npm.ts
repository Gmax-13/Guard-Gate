/**
 * npm Ecosystem Parser
 *
 * Parses package-lock.json (v2/v3) or yarn.lock for npm dependencies.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { EcosystemParser } from '../parser-interface.js';
import type { ParseResult, Dependency } from '../types.js';
import { logger } from '../../../utils/logger.js';

export class NpmParser implements EcosystemParser {
  readonly ecosystem = 'npm';
  readonly displayName = 'npm (Node.js)';

  detect(rootDir: string): string | null {
    const lockPath = join(rootDir, 'package-lock.json');
    if (existsSync(lockPath)) return lockPath;

    const yarnLock = join(rootDir, 'yarn.lock');
    if (existsSync(yarnLock)) return yarnLock;

    // Fall back to package.json if no lock file
    const pkgPath = join(rootDir, 'package.json');
    if (existsSync(pkgPath)) return pkgPath;

    return null;
  }

  async parse(rootDir: string): Promise<ParseResult> {
    const dependencies: Dependency[] = [];

    // Try package-lock.json first (most reliable for transitive deps)
    const lockPath = join(rootDir, 'package-lock.json');
    if (existsSync(lockPath)) {
      return this.parseLockfile(lockPath, rootDir);
    }

    // Fall back to package.json (direct deps only)
    const pkgPath = join(rootDir, 'package.json');
    if (existsSync(pkgPath)) {
      return this.parsePackageJson(pkgPath);
    }

    return { ecosystem: 'npm', dependencies: [], sourceFile: '' };
  }

  private parseLockfile(lockPath: string, rootDir: string): ParseResult {
    try {
      const content = JSON.parse(readFileSync(lockPath, 'utf-8'));
      const dependencies: Dependency[] = [];

      // Read direct deps from package.json for isDirect flagging
      const directDeps = new Set<string>();
      const pkgPath = join(rootDir, 'package.json');
      if (existsSync(pkgPath)) {
        try {
          const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
          for (const name of Object.keys(pkg.dependencies ?? {})) {
            directDeps.add(name);
          }
          for (const name of Object.keys(pkg.devDependencies ?? {})) {
            directDeps.add(name);
          }
        } catch {
          // Ignore parse errors
        }
      }

      // package-lock.json v2/v3 uses 'packages' field
      if (content.packages) {
        for (const [key, info] of Object.entries(content.packages)) {
          if (key === '') continue; // Root package
          const pkg = info as Record<string, unknown>;
          const name = key.replace(/^node_modules\//, '').replace(/.*node_modules\//, '');
          const version = (pkg.version as string) ?? '';

          if (name && version) {
            dependencies.push({
              name,
              version,
              ecosystem: 'npm',
              isDirect: directDeps.has(name),
            });
          }
        }
      }
      // package-lock.json v1 uses 'dependencies' field
      else if (content.dependencies) {
        this.parseLockV1Deps(content.dependencies, dependencies, directDeps);
      }

      logger.debug(`npm: found ${dependencies.length} dependencies`);
      return { ecosystem: 'npm', dependencies, sourceFile: lockPath };
    } catch (err) {
      logger.warn(`Failed to parse npm lock file: ${err}`);
      return { ecosystem: 'npm', dependencies: [], sourceFile: lockPath };
    }
  }

  private parseLockV1Deps(
    deps: Record<string, unknown>,
    result: Dependency[],
    directDeps: Set<string>,
    parent?: string,
  ): void {
    for (const [name, info] of Object.entries(deps)) {
      const pkg = info as Record<string, unknown>;
      const version = (pkg.version as string) ?? '';

      if (name && version) {
        result.push({
          name,
          version,
          ecosystem: 'npm',
          isDirect: directDeps.has(name),
          parent,
        });

        // Recurse into nested dependencies
        if (pkg.dependencies) {
          this.parseLockV1Deps(
            pkg.dependencies as Record<string, unknown>,
            result,
            directDeps,
            name,
          );
        }
      }
    }
  }

  private parsePackageJson(pkgPath: string): ParseResult {
    try {
      const content = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      const dependencies: Dependency[] = [];

      for (const [name, versionRange] of Object.entries(content.dependencies ?? {})) {
        dependencies.push({
          name,
          version: cleanVersion(versionRange as string),
          ecosystem: 'npm',
          isDirect: true,
        });
      }

      for (const [name, versionRange] of Object.entries(content.devDependencies ?? {})) {
        dependencies.push({
          name,
          version: cleanVersion(versionRange as string),
          ecosystem: 'npm',
          isDirect: true,
        });
      }

      logger.debug(`npm: found ${dependencies.length} direct dependencies from package.json`);
      return { ecosystem: 'npm', dependencies, sourceFile: pkgPath };
    } catch (err) {
      logger.warn(`Failed to parse package.json: ${err}`);
      return { ecosystem: 'npm', dependencies: [], sourceFile: pkgPath };
    }
  }
}

/**
 * Extract a clean version string from a semver range.
 * Handles compound ranges like ">=4.16.0 <5.0.0" by taking the first concrete version.
 */
function cleanVersion(version: string): string {
  const match = version.match(/(\d+\.\d+\.\d+(?:-[\w.]+)?)/);
  return match ? match[1] : version.replace(/^[\^~>=<\s]+/, '').trim();
}
