import { execSync } from 'node:child_process';
import { writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { logger } from './logger.js';
import type { ScanReport } from '../types/report.js';

export function applyRemediations(report: ScanReport, rootDir: string, shouldApply: boolean = false): void {
  logger.section(shouldApply ? 'Applying AI Remediations' : 'Generating AI Remediations (Dry Run)');
  
  let appliedCount = 0;
  const createdBranches: string[] = [];

  for (const module of report.modules) {
    for (const finding of module.findings) {
      if (!finding.remediationPatch) continue;

      const branchName = `fix/guardgate-${finding.ruleId.substring(0, 20).replace(/[^a-zA-Z0-9-]/g, '-')}-${randomUUID().substring(0, 8)}`;
      
      const patchDir = join(rootDir, '.guardgate', 'remediations');
      try {
        execSync(`mkdir -p "${patchDir}"`, { stdio: 'ignore' });
      } catch {} // ignore if exists

      const patchPath = join(patchDir, `${finding.id}.patch`);

      try {
        writeFileSync(patchPath, finding.remediationPatch, 'utf-8');

        if (!shouldApply) {
          appliedCount++;
          logger.info(`✅ Generated patch file for ${finding.id} at .guardgate/remediations/${finding.id}.patch`);
          continue;
        }

        // Check if inside work tree
        try {
          execSync('git rev-parse --is-inside-work-tree', { cwd: rootDir, stdio: 'ignore' });
        } catch {
          throw new Error('Not inside a git working tree');
        }

        // Verify git is clean before branching
        try {
          execSync('git diff --quiet', { cwd: rootDir, stdio: 'ignore' });
          execSync('git diff --cached --quiet', { cwd: rootDir, stdio: 'ignore' });
        } catch {
          throw new Error('Working tree is not clean. Please commit or stash changes before applying remediations.');
        }

        execSync(`git checkout -b ${branchName}`, { cwd: rootDir, stdio: 'ignore' });
        execSync(`git apply "${patchPath}"`, { cwd: rootDir, stdio: 'ignore' });
        
        // Do NOT auto-commit. Just leave the branch with modified files.
        // The user can review the changes and commit them.
        execSync('git checkout -', { cwd: rootDir, stdio: 'ignore' });

        createdBranches.push(branchName);
        appliedCount++;
        logger.info(`✅ Created branch '${branchName}' and applied patch for finding ${finding.id}`);

      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.warn(`Failed to apply remediation for ${finding.id}. ${msg}`);
        // Attempt to clean up and return to previous branch
        try {
          execSync('git checkout -', { cwd: rootDir, stdio: 'ignore' });
          execSync(`git branch -D ${branchName}`, { cwd: rootDir, stdio: 'ignore' });
        } catch {}
      }
    }
  }

  if (appliedCount > 0) {
    if (shouldApply) {
      logger.info(`\nSuccessfully created ${createdBranches.length} fix branches!`);
      logger.info('Patches have been applied but NOT committed. You can review them using:');
      createdBranches.forEach(b => logger.info(`  git checkout ${b} && git diff`));
    } else {
      logger.info(`\nSuccessfully generated ${appliedCount} patch files!`);
      logger.info('Run again with --apply-remediations to automatically apply them in new git branches.');
    }
  } else {
    logger.info('No remediations were applied or generated.');
  }
}
