/**
 * Allowlist / Ignore List
 *
 * Handles file path exclusion logic for the secrets scanner.
 * Respects .gitignore patterns + custom allowlist from config.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { type Ignore } from 'ignore';

const require = createRequire(import.meta.url);
const ignore = require('ignore') as () => Ignore;

/** File extensions that are almost always binary / non-secret */
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.exe', '.dll', '.so', '.dylib', '.o', '.a',
  '.class', '.jar', '.war', '.pyc', '.pyo',
  '.lock', // lock files are generally safe
]);

/** Files to always skip by exact basename (lockfiles, generated manifests) */
const ALWAYS_SKIP_FILES = new Set([
  'pnpm-lock.yaml',
  'package-lock.json',
  'yarn.lock',
  'bun.lockb',
  'Gemfile.lock',
  'Cargo.lock',
  'composer.lock',
  'poetry.lock',
  'Pipfile.lock',
  'go.sum',
  'flake.lock',
  'packages.lock.json',
  'gradle.lockfile',
  '.terraform.lock.hcl',
]);

/** Directories to always skip */
const ALWAYS_SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'vendor',
  '__pycache__',
  '.guardgate',
  'dist',
  'build',
  '.next',
  'coverage',
]);

/**
 * Create an ignore filter combining .gitignore + custom allowlist patterns.
 */
export function createAllowlistFilter(
  rootDir: string,
  customPatterns: string[] = [],
): Ignore {
  const ig = ignore();

  // Load .gitignore if it exists
  const gitignorePath = join(rootDir, '.gitignore');
  if (existsSync(gitignorePath)) {
    try {
      const content = readFileSync(gitignorePath, 'utf-8');
      ig.add(content);
    } catch {
      // Ignore read errors
    }
  }

  // Load .guardgateignore if it exists
  const guardgateignorePath = join(rootDir, '.guardgateignore');
  if (existsSync(guardgateignorePath)) {
    try {
      const content = readFileSync(guardgateignorePath, 'utf-8');
      ig.add(content);
    } catch {
      // Ignore read errors
    }
  }

  // Add custom allowlist patterns from config
  if (customPatterns.length > 0) {
    ig.add(customPatterns);
  }

  return ig;
}

/**
 * Check if a file path should be skipped based on extension.
 */
export function isBinaryFile(filePath: string): boolean {
  const ext = filePath.toLowerCase().slice(filePath.lastIndexOf('.'));
  return BINARY_EXTENSIONS.has(ext);
}

/**
 * Check if a directory should always be skipped.
 */
export function isSkippedDirectory(dirName: string): boolean {
  return ALWAYS_SKIP_DIRS.has(dirName);
}

/**
 * Check if a file should always be skipped by its basename
 * (lockfiles, generated manifests with integrity hashes, etc.).
 */
export function isSkippedFile(filePath: string): boolean {
  const name = filePath.split(/[/\\]/).pop() ?? '';
  return ALWAYS_SKIP_FILES.has(name);
}

/**
 * Check if a file path matches common test/fixture patterns
 * that are unlikely to contain real secrets.
 */
export function isTestFixture(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    lower.includes('.test.') ||
    lower.includes('.spec.') ||
    lower.includes('__tests__') ||
    lower.includes('__mocks__') ||
    lower.includes('/test/') ||
    lower.includes('/tests/') ||
    lower.includes('/fixtures/') ||
    lower.includes('/testdata/') ||
    lower.endsWith('.env.example') ||
    lower.endsWith('.env.sample') ||
    lower.endsWith('.env.template')
  );
}
