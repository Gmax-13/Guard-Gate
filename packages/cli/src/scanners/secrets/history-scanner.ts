/**
 * History Scanner
 *
 * Scans git commit history for secrets that were committed and later removed.
 * Iterates through commit diffs and applies the same detection rules.
 */

import type { Finding } from '../../types/report.js';
import { Severity } from '../../types/report.js';
import type { SecretRule } from './rules.js';
import { BUILT_IN_RULES } from './rules.js';
import { findHighEntropyStrings } from './entropy.js';
import { getCommitHistory, getCommitDiff, createGit } from '../../utils/git.js';
import { isSkippedFile, createAllowlistFilter } from './allowlist.js';
import { logger } from '../../utils/logger.js';

interface HistoryScanOptions {
  rootDir: string;
  allowlistPatterns: string[];
  maxCommits: number;
  entropyThreshold: number;
  customRules: Array<{ id: string; name: string; regex: string; severity: string }>;
}

/**
 * Parse a unified diff to extract added lines and their file paths.
 */
function parseDiffAddedLines(
  diff: string,
): Array<{ filePath: string; lineNumber: number; content: string }> {
  const results: Array<{ filePath: string; lineNumber: number; content: string }> = [];
  const lines = diff.split('\n');
  let currentFile = '';
  let lineNumber = 0;

  for (const line of lines) {
    // Detect file header
    if (line.startsWith('+++ b/')) {
      currentFile = line.slice(6);
      lineNumber = 0;
      continue;
    }

    // Detect hunk header (e.g., @@ -0,0 +1,5 @@)
    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
    if (hunkMatch) {
      lineNumber = parseInt(hunkMatch[1], 10) - 1;
      continue;
    }

    // Track line numbers
    if (line.startsWith('+') && !line.startsWith('+++')) {
      lineNumber++;
      results.push({
        filePath: currentFile,
        lineNumber,
        content: line.substring(1), // Remove the leading '+'
      });
    } else if (!line.startsWith('-')) {
      lineNumber++;
    }
  }

  return results;
}

/**
 * Scan git history for secrets in past commits.
 */
export async function scanHistory(options: HistoryScanOptions): Promise<Finding[]> {
  const { rootDir, allowlistPatterns, maxCommits, entropyThreshold, customRules } = options;
  const findings: Finding[] = [];

  // Compile all rules
  const allRules: SecretRule[] = [...BUILT_IN_RULES];
  for (const custom of customRules) {
    try {
      allRules.push({
        id: custom.id,
        name: custom.name,
        description: `Custom rule: ${custom.name}`,
        regex: new RegExp(custom.regex, 'g'),
        severity: custom.severity as Severity,
      });
    } catch (err) {
      logger.warn(`Invalid custom rule regex for '${custom.id}': ${err}`);
    }
  }

  // Build the ignore filter (includes .gitignore, .guardgateignore, and custom config patterns)
  const ig = createAllowlistFilter(rootDir, allowlistPatterns);

  // Get commit history
  const commits = await getCommitHistory(rootDir, maxCommits);
  logger.debug(`Scanning ${commits.length} commits in history`);

  for (const commit of commits) {
    try {
      const diff = await getCommitDiff(rootDir, commit.hash);
      if (!diff) continue;

      // Parse the diff for added lines
      const addedLines = parseDiffAddedLines(diff);

      for (const { filePath, lineNumber, content } of addedLines) {
        // Skip lockfiles and generated manifests
        if (isSkippedFile(filePath)) continue;

        // Skip files ignored by .guardgateignore / .gitignore
        if (ig.ignores(filePath)) continue;

        // Skip binary-looking content
        if (content.includes('\0')) continue;

        // Regex rule matching
        for (const rule of allRules) {
          rule.regex.lastIndex = 0;
          let match: RegExpExecArray | null;

          while ((match = rule.regex.exec(content)) !== null) {
            const secretValue = match[1] ?? match[0];
            const masked = maskSecret(secretValue);

            // Deduplicate — don't report the same secret from the same file
            const isDuplicate = findings.some(
              (f) =>
                f.ruleId === rule.id &&
                f.filePath === filePath &&
                f.message.includes(masked),
            );

            if (!isDuplicate) {
              findings.push({
                id: `secrets-history-${findings.length}`,
                module: 'secrets',
                ruleId: rule.id,
                ruleName: rule.name,
                severity: rule.severity,
                message: `${rule.description} (found in git history): ${masked}`,
                filePath,
                lineNumber,
                commitHash: commit.hash,
                evidence: [
                  {
                    type: 'snippet',
                    label: 'Commit diff line (redacted)',
                    data: maskLine(content, secretValue),
                  },
                ],
                metadata: {
                  commitMessage: commit.message,
                },
              });
            }
          }
        }

        // Entropy-based detection
        if (entropyThreshold > 0) {
          const entropyMatches = findHighEntropyStrings(content, entropyThreshold);
          for (const { token, entropy } of entropyMatches) {
            const masked = maskSecret(token);
            const isDuplicate = findings.some(
              (f) =>
                f.filePath === filePath &&
                f.commitHash === commit.hash &&
                f.message.includes(masked),
            );

            if (!isDuplicate) {
              findings.push({
                id: `secrets-history-entropy-${findings.length}`,
                module: 'secrets',
                ruleId: 'high-entropy-string-history',
                ruleName: 'High-Entropy String (History)',
                severity: Severity.MEDIUM,
                message: `Possible secret in git history (entropy: ${entropy.toFixed(2)}): ${masked}`,
                filePath,
                lineNumber,
                commitHash: commit.hash,
                metadata: {
                  entropy,
                  commitMessage: commit.message,
                },
              });
            }
          }
        }
      }
    } catch (err) {
      logger.debug(`Failed to scan commit ${commit.hash}: ${err}`);
    }
  }

  logger.debug(`Found ${findings.length} secrets in history`);
  return findings;
}

/** Mask a secret value for safe display. */
function maskSecret(secret: string): string {
  if (secret.length <= 8) return '*'.repeat(secret.length);
  return `${secret.substring(0, 4)}${'*'.repeat(Math.min(secret.length - 6, 20))}${secret.substring(secret.length - 2)}`;
}

/** Mask the secret within a line. */
function maskLine(line: string, secret: string): string {
  const masked = maskSecret(secret);
  return line.replace(secret, masked).trim();
}
