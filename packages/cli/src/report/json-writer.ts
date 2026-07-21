/**
 * JSON Report Writer
 *
 * Writes a ScanReport to a JSON file on disk.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import type { ScanReport } from '../types/report.js';
import { logger } from '../utils/logger.js';

/**
 * Write a scan report to a JSON file.
 *
 * @param report - The scan report to write
 * @param outputDir - The directory to write the report to
 * @returns The full path to the written file
 */
export function writeJsonReport(report: ScanReport, outputDir: string): string {
  const filename = `guardgate-report-${Date.now()}.json`;
  const filePath = join(outputDir, filename);

  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf-8');
    logger.info(`JSON report written to ${filePath}`);
    return filePath;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to write JSON report: ${message}`);
    throw err;
  }
}

/**
 * Write a scan report to stdout as JSON (for piping).
 */
export function printJsonReport(report: ScanReport): void {
  console.log(JSON.stringify(report, null, 2));
}
