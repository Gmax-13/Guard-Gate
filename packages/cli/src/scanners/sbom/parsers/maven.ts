/**
 * Maven/Gradle Ecosystem Parser
 *
 * Parses pom.xml for Maven and build.gradle/gradle.lockfile for Gradle.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { EcosystemParser } from '../parser-interface.js';
import type { ParseResult, Dependency } from '../types.js';
import { logger } from '../../../utils/logger.js';

export class MavenParser implements EcosystemParser {
  readonly ecosystem = 'maven';
  readonly displayName = 'Maven/Gradle (Java)';

  detect(rootDir: string): string | null {
    const gradleLock = join(rootDir, 'gradle.lockfile');
    if (existsSync(gradleLock)) return gradleLock;

    const pomXml = join(rootDir, 'pom.xml');
    if (existsSync(pomXml)) return pomXml;

    const buildGradle = join(rootDir, 'build.gradle');
    if (existsSync(buildGradle)) return buildGradle;

    const buildGradleKts = join(rootDir, 'build.gradle.kts');
    if (existsSync(buildGradleKts)) return buildGradleKts;

    return null;
  }

  async parse(rootDir: string): Promise<ParseResult> {
    // Try gradle.lockfile first (most reliable)
    const gradleLock = join(rootDir, 'gradle.lockfile');
    if (existsSync(gradleLock)) {
      return this.parseGradleLockfile(gradleLock);
    }

    // Try pom.xml
    const pomXml = join(rootDir, 'pom.xml');
    if (existsSync(pomXml)) {
      return this.parsePomXml(pomXml);
    }

    // Try build.gradle (limited — no version resolution)
    const buildGradle = join(rootDir, 'build.gradle');
    if (existsSync(buildGradle)) {
      return this.parseBuildGradle(buildGradle);
    }

    const buildGradleKts = join(rootDir, 'build.gradle.kts');
    if (existsSync(buildGradleKts)) {
      return this.parseBuildGradle(buildGradleKts);
    }

    return { ecosystem: 'maven', dependencies: [], sourceFile: '' };
  }

  private parseGradleLockfile(lockPath: string): ParseResult {
    try {
      const content = readFileSync(lockPath, 'utf-8');
      const dependencies: Dependency[] = [];

      for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;

        // Format: group:artifact:version=variant
        const match = line.match(/^([^:]+):([^:]+):([^=]+)/);
        if (match) {
          dependencies.push({
            name: `${match[1]}:${match[2]}`,
            version: match[3],
            ecosystem: 'maven',
            isDirect: true,
          });
        }
      }

      logger.debug(`maven: found ${dependencies.length} dependencies from gradle.lockfile`);
      return { ecosystem: 'maven', dependencies, sourceFile: lockPath };
    } catch (err) {
      logger.warn(`Failed to parse gradle.lockfile: ${err}`);
      return { ecosystem: 'maven', dependencies: [], sourceFile: lockPath };
    }
  }

  private parsePomXml(pomPath: string): ParseResult {
    try {
      const content = readFileSync(pomPath, 'utf-8');
      const dependencies: Dependency[] = [];

      // Simple regex-based XML parsing for dependencies
      // (avoids adding an XML parser dependency)
      const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
      let match: RegExpExecArray | null;

      while ((match = depRegex.exec(content)) !== null) {
        const groupId = match[1].trim();
        const artifactId = match[2].trim();
        const version = match[3]?.trim() ?? 'unknown';

        // Skip property references like ${project.version}
        if (version.startsWith('${')) continue;

        dependencies.push({
          name: `${groupId}:${artifactId}`,
          version,
          ecosystem: 'maven',
          isDirect: true,
        });
      }

      logger.debug(`maven: found ${dependencies.length} dependencies from pom.xml`);
      return { ecosystem: 'maven', dependencies, sourceFile: pomPath };
    } catch (err) {
      logger.warn(`Failed to parse pom.xml: ${err}`);
      return { ecosystem: 'maven', dependencies: [], sourceFile: pomPath };
    }
  }

  private parseBuildGradle(gradlePath: string): ParseResult {
    try {
      const content = readFileSync(gradlePath, 'utf-8');
      const dependencies: Dependency[] = [];

      // Match common Gradle dependency declarations
      // implementation 'group:artifact:version'
      // implementation("group:artifact:version")
      const depRegex = /(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[('"]([^:'"]+):([^:'"]+):([^)'"]+)[)'"]/g;
      let match: RegExpExecArray | null;

      while ((match = depRegex.exec(content)) !== null) {
        dependencies.push({
          name: `${match[1].trim()}:${match[2].trim()}`,
          version: match[3].trim(),
          ecosystem: 'maven',
          isDirect: true,
        });
      }

      logger.debug(`maven: found ${dependencies.length} dependencies from build.gradle`);
      return { ecosystem: 'maven', dependencies, sourceFile: gradlePath };
    } catch (err) {
      logger.warn(`Failed to parse build.gradle: ${err}`);
      return { ecosystem: 'maven', dependencies: [], sourceFile: gradlePath };
    }
  }
}
