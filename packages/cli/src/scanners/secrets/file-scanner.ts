/**
 * File Scanner
 *
 * Scans current working directory files for secrets using regex rules
 * and entropy analysis. Respects .gitignore + custom allowlist.
 */

import { readFileSync } from 'node:fs';
import { relative, basename, extname } from 'node:path';
import fg from 'fast-glob';
import type { Finding } from '../../types/report.js';
import { Severity } from '../../types/report.js';
import type { SecretRule } from './rules.js';
import { BUILT_IN_RULES } from './rules.js';
import { verifySecret } from './verifier.js';
import { findHighEntropyStrings } from './entropy.js';
import {
  createAllowlistFilter,
  isBinaryFile,
  isSkippedDirectory,
  isSkippedFile,
  isTestFixture,
} from './allowlist.js';
import { logger } from '../../utils/logger.js';

/** Maximum file size to scan (1MB) */
const MAX_FILE_SIZE = 1_048_576;

interface FileScanOptions {
  rootDir: string;
  allowlistPatterns: string[];
  entropyThreshold: number;
  customRules: Array<{ id: string; name: string; regex: string; severity: string }>;
  verifySecrets?: boolean;
}

/**
 * Scan all files in the working directory for secrets.
 */
export async function scanFiles(options: FileScanOptions): Promise<Finding[]> {
  const { rootDir, allowlistPatterns, entropyThreshold, customRules, verifySecrets } = options;
  const findings: Finding[] = [];

  // Build the ignore filter
  const ig = createAllowlistFilter(rootDir, allowlistPatterns);

  // Compile custom rules
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

  // Discover files
  const files = await fg('**/*', {
    cwd: rootDir,
    dot: true,
    absolute: true,
    onlyFiles: true,
    ignore: ['**/node_modules/**', '**/.git/**'],
    suppressErrors: true,
    stats: true,
  });

  logger.debug(`Found ${files.length} files to scan`);

  let scannedCount = 0;
  for (const file of files) {
    const filePath = typeof file === 'string' ? file : file.path;
    const relativePath = relative(rootDir, filePath);

    // Skip binary files
    if (isBinaryFile(relativePath)) continue;

    // Skip lockfiles and other generated files
    if (isSkippedFile(relativePath)) continue;

    // Skip test fixtures, examples, and sample files
    if (isTestFixture(relativePath)) continue;

    // Skip directories in the always-skip list
    const dirParts = relativePath.split(/[/\\]/);
    if (dirParts.some((part) => isSkippedDirectory(part))) continue;

    // Skip if ignored by allowlist
    if (ig.ignores(relativePath)) continue;

    // Read and scan
    try {
      const stats = typeof file !== 'string' && file.stats ? file.stats : undefined;
      if (stats && stats.size > MAX_FILE_SIZE) {
        logger.debug(`Skipping large file: ${relativePath} (${stats.size} bytes)`);
        continue;
      }

      const content = readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      scannedCount++;

      // Scan each line
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx];
        const lineNumber = lineIdx + 1;

        // Regex rule matching
        for (const rule of allRules) {
          // Reset regex lastIndex for global patterns
          rule.regex.lastIndex = 0;
          let match: RegExpExecArray | null;

          while ((match = rule.regex.exec(line)) !== null) {
            const secretValue = match[1] ?? match[0];
            const masked = maskSecret(secretValue);

            findings.push({
              id: `secrets-file-${findings.length}`,
              module: 'secrets',
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              message: `${rule.description}: ${masked}`,
              filePath: relativePath,
              lineNumber,
              metadata: { rawSecret: secretValue },
              evidence: [
                {
                  type: 'snippet',
                  label: 'Matched line (redacted)',
                  data: maskLine(line, secretValue),
                },
              ],
            });
          }
        }

        // Entropy-based detection
        if (entropyThreshold > 0) {
          const entropyMatches = findHighEntropyStrings(line, entropyThreshold);
          for (const { token, entropy } of entropyMatches) {
            // Skip if already matched by a regex rule
            const alreadyMatched = findings.some(
              (f) =>
                f.filePath === relativePath &&
                f.lineNumber === lineNumber &&
                f.message.includes(maskSecret(token)),
            );

            if (!alreadyMatched) {
              findings.push({
                id: `secrets-entropy-${findings.length}`,
                module: 'secrets',
                ruleId: 'high-entropy-string',
                ruleName: 'High-Entropy String',
                severity: Severity.MEDIUM,
                message: `Possible secret detected (entropy: ${entropy.toFixed(2)}): ${maskSecret(token)}`,
                filePath: relativePath,
                lineNumber,
                metadata: { entropy },
              });
            }
          }
        }
      }
    } catch (err) {
      // Skip files that can't be read (binary, permission issues, etc.)
      logger.debug(`Skipping unreadable file: ${relativePath}`);
    }
  }

  if (verifySecrets) {
    logger.debug(`Verifying ${findings.length} secrets via APIs...`);
    for (const finding of findings) {
      if (finding.metadata?.rawSecret) {
        const rawSecret = finding.metadata.rawSecret as string;
        const status = await verifySecret(finding.ruleId, rawSecret, findings.filter(f => f.filePath === finding.filePath));
        
        if (status === 'ACTIVE') {
          finding.severity = Severity.CRITICAL;
          finding.message = `[ACTIVE] ${finding.message}`;
        } else if (status === 'REVOKED') {
          finding.severity = Severity.INFO;
          finding.message = `[REVOKED/INVALID] ${finding.message}`;
        }
      }
    }
  }

  // Clean up rawSecret so it isn't leaked in reports
  for (const finding of findings) {
    if (finding.metadata) {
      delete finding.metadata.rawSecret;
      if (Object.keys(finding.metadata).length === 0) {
        delete finding.metadata;
      }
    }
  }

  logger.debug(`Scanned ${scannedCount} files`);
  return findings;
}

/**
 * Mask a secret value for safe display (show first 4 and last 2 chars).
 */
function maskSecret(secret: string): string {
  if (secret.length <= 8) return '*'.repeat(secret.length);
  return `${secret.substring(0, 4)}${'*'.repeat(Math.min(secret.length - 6, 20))}${secret.substring(secret.length - 2)}`;
}

/**
 * Mask the secret within a line of text.
 */
function maskLine(line: string, secret: string): string {
  const masked = maskSecret(secret);
  return line.replace(secret, masked).trim();
}
