/**
 * Baseline Engine
 *
 * Implements diff-aware / baseline scanning. Given a baseline git ref,
 * classifies each finding as "new" (introduced since baseline) or "baseline"
 * (pre-existing). Only new findings count toward pass/fail.
 *
 * Algorithm:
 * 1. `git diff --name-only <baseline>..HEAD` → set of changed files
 * 2. `git diff --unified=0 <baseline>..HEAD` → per-file added line ranges
 * 3. For each finding:
 *    - No filePath + fingerprint in stored baseline → "baseline"
 *    - No filePath + fingerprint NOT in stored baseline → "new"
 *    - File unchanged → "baseline"
 *    - File changed, line in added range → "new"
 *    - File changed, line NOT in added range → "baseline"
 * 4. Recalculate pass/fail using only "new" findings
 * 5. Persist current fingerprints to .guardgate/baseline.json
 */

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createGit } from './git.js';
import { logger } from './logger.js';
import type { Finding, ScanReport, ModuleResult } from '../types/report.js';
import { Severity, SEVERITY_WEIGHT } from '../types/report.js';

// ─── Fingerprinting ─────────────────────────────────────────────────────

/**
 * Generate a stable fingerprint for a finding.
 *
 * The fingerprint is a SHA-256 hash of:
 *   ruleId + normalized_filePath + trimmed_lineContent
 *
 * This is stable across line-number shifts (e.g., adding lines above),
 * but intentionally breaks on file renames (renamed files should be re-reviewed).
 *
 * For findings without a file path (SBOM, E2E, API), uses ruleId + message.
 */
export function generateFingerprint(finding: Finding, rootDir?: string): string {
  const parts: string[] = [finding.ruleId];

  if (finding.filePath) {
    // Normalize path separators and casing
    const normalizedPath = finding.filePath.replace(/\\/g, '/').toLowerCase();
    parts.push(normalizedPath);

    // Try to get the actual line content for a more stable fingerprint
    if (rootDir && finding.lineNumber) {
      try {
        const fullPath = join(rootDir, finding.filePath);
        const content = readFileSync(fullPath, 'utf-8');
        const lines = content.split('\n');
        const lineContent = lines[finding.lineNumber - 1];
        if (lineContent !== undefined) {
          parts.push(lineContent.trim());
        }
      } catch {
        // File might not exist (e.g., history-only finding) — fall back to message
        parts.push(finding.message);
      }
    } else {
      parts.push(finding.message);
    }
  } else {
    // No file path — use message as the distinguishing content
    parts.push(finding.message);
  }

  const raw = parts.join('::');
  return createHash('sha256').update(raw).digest('hex').substring(0, 16);
}

/**
 * Add fingerprints to all findings in a report.
 */
export function addFingerprints(report: ScanReport, rootDir: string): void {
  for (const moduleResult of report.modules) {
    for (const finding of moduleResult.findings) {
      if (!finding.fingerprint) {
        finding.fingerprint = generateFingerprint(finding, rootDir);
      }
    }
  }
}

// ─── Baseline Fingerprint Persistence ────────────────────────────────────

const BASELINE_FINGERPRINTS_FILE = 'baseline.json';

interface BaselineSnapshot {
  /** ISO timestamp of when this snapshot was saved */
  savedAt: string;
  /** The baseline ref used */
  baselineRef: string;
  /** Set of fingerprints from the last scan */
  fingerprints: string[];
}

/**
 * Load stored baseline fingerprints from .guardgate/baseline.json.
 * Returns a Set of fingerprint strings, or null if no snapshot exists.
 */
function loadBaselineFingerprints(outputDir: string): Set<string> | null {
  const filePath = join(outputDir, BASELINE_FINGERPRINTS_FILE);
  try {
    if (!existsSync(filePath)) return null;
    const raw = readFileSync(filePath, 'utf-8');
    const snapshot = JSON.parse(raw) as BaselineSnapshot;
    if (!Array.isArray(snapshot.fingerprints)) return null;
    logger.debug(`Loaded ${snapshot.fingerprints.length} baseline fingerprints from ${filePath}`);
    return new Set(snapshot.fingerprints);
  } catch (err) {
    logger.debug(`Could not load baseline fingerprints: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

/**
 * Save current fingerprints to .guardgate/baseline.json for future baseline comparisons.
 */
function saveBaselineFingerprints(
  report: ScanReport,
  baselineRef: string,
  outputDir: string,
): void {
  const fingerprints: string[] = [];
  for (const moduleResult of report.modules) {
    for (const finding of moduleResult.findings) {
      if (finding.fingerprint) {
        fingerprints.push(finding.fingerprint);
      }
    }
  }

  const snapshot: BaselineSnapshot = {
    savedAt: new Date().toISOString(),
    baselineRef,
    fingerprints,
  };

  try {
    if (!existsSync(outputDir)) {
      mkdirSync(outputDir, { recursive: true });
    }
    const filePath = join(outputDir, BASELINE_FINGERPRINTS_FILE);
    writeFileSync(filePath, JSON.stringify(snapshot, null, 2), 'utf-8');
    logger.debug(`Saved ${fingerprints.length} fingerprints to ${filePath}`);
  } catch (err) {
    logger.warn(`Could not save baseline fingerprints: ${err instanceof Error ? err.message : String(err)}`);
  }
}

// ─── Git Diff Helpers ────────────────────────────────────────────────────

/** A range of line numbers (inclusive on both ends). */
interface LineRange {
  start: number;
  end: number;
}

/**
 * Get the list of files changed between a baseline ref and HEAD.
 * Returns relative paths (forward-slash normalized).
 */
export async function getChangedFiles(
  rootDir: string,
  baselineRef: string,
): Promise<Set<string>> {
  try {
    const git = createGit(rootDir);
    const diffOutput = await git.diff(['--name-only', `${baselineRef}...HEAD`]);
    const files = diffOutput
      .split('\n')
      .map((f) => f.trim())
      .filter((f) => f.length > 0)
      .map((f) => f.replace(/\\/g, '/').toLowerCase());
    return new Set(files);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const cleanMsg = message.split('\n').find(l => l.trim().length > 0) ?? 'Unknown error';
    logger.warn(`Failed to get changed files from baseline '${baselineRef}': ${cleanMsg.trim()}`);
    // If diff fails, treat everything as new (safe fallback)
    return new Set(['*']);
  }
}

/**
 * Parse the unified diff output to extract per-file added line ranges.
 * Uses `git diff --unified=0` to get precise hunk headers without context lines.
 *
 * Returns a Map of normalized file path → array of added line ranges.
 */
export async function getChangedLineRanges(
  rootDir: string,
  baselineRef: string,
): Promise<Map<string, LineRange[]>> {
  const rangeMap = new Map<string, LineRange[]>();

  try {
    const git = createGit(rootDir);
    const diffOutput = await git.diff(['--unified=0', `${baselineRef}...HEAD`]);

    let currentFile: string | null = null;
    const lines = diffOutput.split('\n');

    for (const line of lines) {
      // Match diff file header: +++ b/path/to/file
      const fileMatch = line.match(/^\+\+\+ b\/(.+)$/);
      if (fileMatch) {
        currentFile = fileMatch[1].replace(/\\/g, '/').toLowerCase();
        if (!rangeMap.has(currentFile)) {
          rangeMap.set(currentFile, []);
        }
        continue;
      }

      // Match hunk header: @@ -oldStart[,oldCount] +newStart[,newCount] @@
      const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
      if (hunkMatch && currentFile) {
        const start = parseInt(hunkMatch[1], 10);
        const count = hunkMatch[2] !== undefined ? parseInt(hunkMatch[2], 10) : 1;

        if (count > 0) {
          const end = start + count - 1;
          rangeMap.get(currentFile)!.push({ start, end });
        }
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const cleanMsg = message.split('\n').find(l => l.trim().length > 0) ?? 'Unknown error';
    logger.warn(`Failed to parse diff line ranges from baseline '${baselineRef}': ${cleanMsg.trim()}`);
  }

  return rangeMap;
}

/**
 * Check if a line number falls within any of the given ranges.
 */
function isLineInRanges(lineNumber: number, ranges: LineRange[]): boolean {
  return ranges.some((r) => lineNumber >= r.start && lineNumber <= r.end);
}

// ─── Finding Classification ─────────────────────────────────────────────

/**
 * Classify all findings as "new" or "baseline".
 *
 * Rules:
 * - No filePath + fingerprint in baselineFingerprints → "baseline" (pre-existing)
 * - No filePath + fingerprint NOT in baselineFingerprints → "new"
 * - No filePath + no baselineFingerprints available → "new" (safe fallback)
 * - File not in changedFiles set → "baseline"
 * - File changed, finding on an added/modified line → "new"
 * - File changed, finding on an unchanged line → "baseline"
 * - If changedFiles contains '*' (diff failed) → all treated as "new" (safe fallback)
 */
export function classifyFindings(
  findings: Finding[],
  changedFiles: Set<string>,
  changedLineRanges: Map<string, LineRange[]>,
  baselineFingerprints?: Set<string> | null,
): void {
  const allNew = changedFiles.has('*');

  for (const finding of findings) {
    // No file path — use fingerprint-based comparison against stored baseline
    if (!finding.filePath) {
      if (baselineFingerprints && finding.fingerprint && baselineFingerprints.has(finding.fingerprint)) {
        finding.baselineStatus = 'baseline';
      } else {
        finding.baselineStatus = 'new';
      }
      continue;
    }

    // If diff failed, treat everything as new
    if (allNew) {
      finding.baselineStatus = 'new';
      continue;
    }

    const normalizedPath = finding.filePath.replace(/\\/g, '/').toLowerCase();

    // File wasn't changed → pre-existing finding
    if (!changedFiles.has(normalizedPath)) {
      finding.baselineStatus = 'baseline';
      continue;
    }

    // File was changed — check if finding is on an added/modified line
    const ranges = changedLineRanges.get(normalizedPath);
    if (!ranges || ranges.length === 0) {
      // File changed but we don't have line-level info
      // (could be a rename, mode change, etc.) → treat as new to be safe
      finding.baselineStatus = 'new';
      continue;
    }

    if (finding.lineNumber && isLineInRanges(finding.lineNumber, ranges)) {
      finding.baselineStatus = 'new';
    } else {
      finding.baselineStatus = 'baseline';
    }
  }
}

// ─── Report-Level Baseline Application ──────────────────────────────────

/**
 * Apply baseline filtering to a complete scan report.
 *
 * This is the main entry point. Called after all scanners have run.
 * It:
 * 1. Adds fingerprints to all findings
 * 2. Loads stored baseline fingerprints (for SBOM/API/E2E comparison)
 * 3. Gets changed files/lines from git
 * 4. Classifies each finding as new or baseline
 * 5. Recalculates pass/fail using only new findings
 * 6. Saves current fingerprints for future baseline comparisons
 * 7. Adds baseline metadata to the report
 */
export async function applyBaseline(
  report: ScanReport,
  baselineRef: string,
  rootDir: string,
  severityThreshold: Severity,
  outputDir?: string,
): Promise<void> {
  logger.info(`Applying baseline: comparing against '${baselineRef}'`);

  // Step 1: Add fingerprints
  addFingerprints(report, rootDir);

  // Step 2: Load stored baseline fingerprints for non-file findings
  const resolvedOutputDir = outputDir ?? join(rootDir, '.guardgate');
  const baselineFingerprints = loadBaselineFingerprints(resolvedOutputDir);
  if (baselineFingerprints) {
    logger.info(`  Loaded ${baselineFingerprints.size} stored baseline fingerprint(s) for SBOM/API/E2E comparison`);
  } else {
    logger.info(`  No stored baseline fingerprints found — non-file findings (SBOM/API/E2E) will be treated as new`);
  }

  // Step 3: Get changed files and line ranges
  const changedFiles = await getChangedFiles(rootDir, baselineRef);
  const changedLineRanges = await getChangedLineRanges(rootDir, baselineRef);

  logger.info(`  ${changedFiles.size === 1 && changedFiles.has('*') ? 'all' : changedFiles.size} file(s) changed since baseline`);

  // Step 4: Classify findings across all modules
  let totalNew = 0;
  let totalBaseline = 0;

  for (const moduleResult of report.modules) {
    classifyFindings(moduleResult.findings, changedFiles, changedLineRanges, baselineFingerprints);

    // Count new vs baseline
    const newFindings = moduleResult.findings.filter((f) => f.baselineStatus === 'new');
    const baselineFindings = moduleResult.findings.filter((f) => f.baselineStatus === 'baseline');

    totalNew += newFindings.length;
    totalBaseline += baselineFindings.length;

    // Step 5: Recalculate module pass/fail using only new findings
    const thresholdWeight = SEVERITY_WEIGHT[severityThreshold] ?? SEVERITY_WEIGHT[Severity.HIGH];
    const hasFailingNewFindings = newFindings.some(
      (f) => SEVERITY_WEIGHT[f.severity] >= thresholdWeight,
    );

    moduleResult.passed = !hasFailingNewFindings && !moduleResult.error;

    // Recalculate finding counts to reflect new findings only for severity breakdown
    // (keep findingCount as total for reporting, but pass/fail based on new only)
  }

  // Step 6: Recalculate overall pass/fail
  report.summary.passed = report.modules.every((m) => m.passed);

  // Step 7: Save current fingerprints for future comparisons
  saveBaselineFingerprints(report, baselineRef, resolvedOutputDir);

  // Step 8: Add baseline metadata
  report.baseline = {
    ref: baselineRef,
    newFindings: totalNew,
    baselineFindings: totalBaseline,
  };

  logger.info(`  Baseline result: ${totalNew} new finding(s), ${totalBaseline} pre-existing (suppressed)`);
}

