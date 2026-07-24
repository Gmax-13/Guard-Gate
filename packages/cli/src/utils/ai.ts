import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { logger } from './logger.js';
import type { ScanReport, Finding } from '../types/report.js';

interface AiConfig {
  remediation: boolean;
  provider: 'groq';
  model: string;
}

export async function generateRemediations(report: ScanReport, config: AiConfig, rootDir: string): Promise<void> {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    logger.warn('GROQ_API_KEY environment variable is not set. Skipping AI remediation generation.');
    return;
  }

  logger.section('AI Remediation Generation');
  let remediatedCount = 0;

  for (const module of report.modules) {
    for (const finding of module.findings) {
      if (finding.baselineStatus === 'baseline') {
        continue; // Don't remediate pre-existing issues unless requested
      }
      if (!finding.filePath) {
        continue; // Need a file to patch
      }

      try {
        const fullPath = resolve(rootDir, finding.filePath);
        const fileContent = readFileSync(fullPath, 'utf-8');

        logger.info(`Generating remediation for ${finding.id} in ${finding.filePath}...`);

        const systemPrompt = `You are an expert security engineer. You will be provided with a file's content and a security vulnerability finding related to this file. 
Your task is to provide a Git Unified Diff (.patch format) that fixes the vulnerability.

RULES:
1. ONLY return the Unified Diff enclosed in \`\`\`diff ... \`\`\` and a brief explanation enclosed in \`\`\`text ... \`\`\`.
2. Do not include any other markdown or conversational text outside these blocks.
3. The diff must be applicable directly to the file using \`git apply\`. Ensure the file paths in the diff header match the provided file path. Use a / b prefixes (e.g. \`--- a/${finding.filePath}\n+++ b/${finding.filePath}\`).
4. Ensure the fix is secure and addresses the specific rule mentioned.`;

        const userPrompt = `FILE PATH: ${finding.filePath}
LINE NUMBER: ${finding.lineNumber ?? 'Unknown'}
VULNERABILITY RULE: ${finding.ruleId} (${finding.ruleName})
MESSAGE: ${finding.message}

FILE CONTENT:
\`\`\`
${fileContent}
\`\`\`

Generate the unified diff and explanation.`;

        const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: config.model,
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userPrompt }
            ],
            temperature: 0.1,
            max_tokens: 2048,
          })
        });

        if (!res.ok) {
          const errBody = await res.text();
          logger.warn(`Groq API error (${res.status}): ${errBody}`);
          continue;
        }

        const data = await res.json() as any;
        const content = data.choices[0]?.message?.content || '';

        const diffMatch = content.match(/```diff\n([\s\S]*?)```/);
        const textMatch = content.match(/```text\n([\s\S]*?)```/);

        if (diffMatch && diffMatch[1]) {
          finding.remediationPatch = diffMatch[1].trim() + '\n';
          finding.remediationExplanation = textMatch ? textMatch[1].trim() : 'AI-generated fix.';
          remediatedCount++;
          logger.info(`✅ Remediation generated for ${finding.id}`);
        } else {
          logger.warn(`Failed to parse diff from Groq response for ${finding.id}`);
        }

      } catch (err) {
        logger.warn(`Failed to generate remediation for ${finding.id}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  if (remediatedCount > 0) {
    logger.info(`Successfully generated ${remediatedCount} remediation patch(es).`);
  } else {
    logger.info('No remediations were generated.');
  }
}
