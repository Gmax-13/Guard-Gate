import { execSync } from 'node:child_process';
import { writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { logger } from './logger.js';
import type { ScanReport } from '../types/report.js';

export function applyRemediations(report: ScanReport, rootDir: string): void {
  logger.section('Applying AI Remediations');
  
  let appliedCount = 0;
  const createdBranches: string[] = [];

  for (const module of report.modules) {
    for (const finding of module.findings) {
      if (!finding.remediationPatch) continue;

      const branchName = `fix/guardgate-${finding.ruleId.substring(0, 20).replace(/[^a-zA-Z0-9-]/g, '-')}-${randomUUID().substring(0, 8)}`;
      const patchPath = join(tmpdir(), `guardgate-${randomUUID()}.patch`);

      try {
        writeFileSync(patchPath, finding.remediationPatch, 'utf-8');

        // Verify git is clean before branching (optional, but good practice. We'll skip strict check for now)
        execSync(`git checkout -b ${branchName}`, { cwd: rootDir, stdio: 'ignore' });
        
        // Apply the patch
        execSync(`git apply ${patchPath}`, { cwd: rootDir, stdio: 'ignore' });
        
        // Commit the change
        const commitMsg = `Fix: ${finding.ruleName}\n\n${finding.remediationExplanation || 'AI-generated security fix by GuardGate'}`;
        execSync('git add -u', { cwd: rootDir, stdio: 'ignore' });
        // Create a temporary commit message file to avoid quoting issues
        const msgPath = join(tmpdir(), `guardgate-msg-${randomUUID()}.txt`);
        writeFileSync(msgPath, commitMsg, 'utf-8');
        execSync(`git commit -F ${msgPath}`, { cwd: rootDir, stdio: 'ignore' });
        unlinkSync(msgPath);

        // Switch back to original branch
        execSync('git checkout -', { cwd: rootDir, stdio: 'ignore' });

        createdBranches.push(branchName);
        appliedCount++;
        logger.info(`✅ Created branch '${branchName}' for finding ${finding.id}`);

      } catch (err) {
        logger.warn(`Failed to apply remediation for ${finding.id}. Patch may conflict or git is not configured.`);
        // Attempt to clean up and return to previous branch
        try {
          execSync('git checkout -', { cwd: rootDir, stdio: 'ignore' });
          execSync(`git branch -D ${branchName}`, { cwd: rootDir, stdio: 'ignore' });
        } catch {}
      } finally {
        try {
          unlinkSync(patchPath);
        } catch {}
      }
    }
  }

  if (appliedCount > 0) {
    logger.info(`\nSuccessfully created ${appliedCount} fix branches!`);
    logger.info('You can review and push them using:');
    createdBranches.forEach(b => logger.info(`  git checkout ${b} && git push origin ${b}`));
  } else {
    logger.info('No remediations were applied.');
  }
}
