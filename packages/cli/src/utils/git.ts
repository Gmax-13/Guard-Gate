/**
 * Git Utilities
 *
 * Helpers for interacting with the git repository using simple-git.
 */

import { createRequire } from 'node:module';
import { type SimpleGit } from 'simple-git';

const require = createRequire(import.meta.url);
const simpleGit = require('simple-git') as (basePath?: string) => SimpleGit;

import { logger } from './logger.js';

/**
 * Create a simple-git instance for the given directory.
 */
export function createGit(rootDir: string): SimpleGit {
  return simpleGit(rootDir);
}

/**
 * Get the repository root directory.
 */
export async function getRepoRoot(dir: string): Promise<string | null> {
  try {
    const git = createGit(dir);
    return await git.revparse(['--show-toplevel']);
  } catch {
    return null;
  }
}

/**
 * Get the current branch name.
 */
export async function getCurrentBranch(dir: string): Promise<string> {
  try {
    const git = createGit(dir);
    const branch = await git.revparse(['--abbrev-ref', 'HEAD']);
    return branch.trim();
  } catch {
    return 'unknown';
  }
}

/**
 * Get the current commit SHA.
 */
export async function getCurrentCommitSha(dir: string): Promise<string> {
  try {
    const git = createGit(dir);
    const sha = await git.revparse(['HEAD']);
    return sha.trim();
  } catch {
    return 'unknown';
  }
}

/**
 * Get the remote origin URL.
 */
export async function getRemoteUrl(dir: string): Promise<string> {
  try {
    const git = createGit(dir);
    const remotes = await git.getRemotes(true);
    const origin = remotes.find((r) => r.name === 'origin');
    return origin?.refs?.fetch ?? dir;
  } catch {
    return dir;
  }
}

/**
 * Check if a directory is inside a git repository.
 */
export async function isGitRepo(dir: string): Promise<boolean> {
  try {
    const git = createGit(dir);
    return await git.checkIsRepo();
  } catch {
    return false;
  }
}

/**
 * Get the list of commits (SHA + message) for scanning history.
 * Returns most recent first, limited by maxCommits.
 */
export async function getCommitHistory(
  dir: string,
  maxCommits: number = 100,
): Promise<Array<{ hash: string; message: string }>> {
  try {
    const git = createGit(dir);
    const log = await git.log({
      maxCount: maxCommits > 0 ? maxCommits : undefined,
    });
    return log.all.map((entry) => ({
      hash: entry.hash,
      message: entry.message,
    }));
  } catch (err) {
    logger.warn(`Failed to get commit history: ${err}`);
    return [];
  }
}

/**
 * Get the diff content for a specific commit.
 */
export async function getCommitDiff(dir: string, commitHash: string): Promise<string> {
  try {
    const git = createGit(dir);
    return await git.diff([`${commitHash}^`, commitHash]);
  } catch {
    // First commit won't have a parent
    try {
      const git = createGit(dir);
      return await git.raw([
        'show',
        '--format=',
        commitHash,
      ]);
    } catch {
      return '';
    }
  }
}
